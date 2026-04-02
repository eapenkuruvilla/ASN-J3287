#!/usr/bin/env python3
"""
create_mbr.py - Build SaeJ3287Data from an input BSM (Ieee1609Dot2Data).

Usage:
    python3 create_mbr.py \\
        --bsm <file.coer> \\
        [--sign-api-key <token>]          # ISS virtual-device signing (recommended)
        [--certs-dir <path>]              # local ECQV signing (RSU or pseudonym bundle)
        [--recipient-cert <ma.cert>]      # certRecipInfo encryption to MA cert
        [--encrypt-api-key <token>        # rekRecipInfo encryption via ISS API
         --encrypt-recipient-id <id>]
        [--out-dir coer/]

The script reads the BSM, hard-codes a LongAcc-ValueTooLarge observation
(tgtId=5, obsId=4), sets generationTime to the current TAI time, and
constructs a SaeJ3287Mbr (EtsiTs103759Mbr) that embeds the BSM as
IEEE 1609.2 V2xPduStream evidence.

Produces:
    {out_dir}/out_plaintext.coer   -- SaeJ3287Data { plaintext: SaeJ3287Mbr }
    {out_dir}/out_signed.coer      -- SaeJ3287Data { signed: Ieee1609Dot2Data }
                                      (requires --sign-api-key or --certs-dir)
    {out_dir}/out_ste.coer         -- SaeJ3287Data { sTE: Ieee1609Dot2Data }
                                      (requires signing + --recipient-cert /
                                       --recipient-pub / --encrypt-api-key)
"""

import argparse
import datetime
import glob
import hashlib
import os
import struct
import sys

try:
    import requests as _requests
except ImportError:
    _requests = None

from asn1c_lib import decode_oer, encode_jer
from encode_mbr import build_mbr_from_bsm, build_signed_1609, build_encrypted_1609, tai64_now

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ── Helpers ───────────────────────────────────────────────────────────────────

def geolocate_ip() -> tuple:
    """Return (lat, lon, elev) based on current public IP via ip-api.com.

    Latitude/longitude are scaled to 1e-7 degree units (IEEE 1609.2 / SAE J2735).
    Elevation is returned as 0 (ip-api.com does not provide elevation).
    Falls back to (0, 0, 0) if the request fails or requests is unavailable.
    """
    if _requests is None:
        print("  (requests not installed; using lat=0 lon=0 elev=0)", file=sys.stderr)
        return 0, 0, 0
    try:
        resp = _requests.get("http://ip-api.com/json/", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise ValueError(data.get("message", "ip-api returned non-success"))
        lat  = round(data["lat"] * 10_000_000)
        lon  = round(data["lon"] * 10_000_000)
        print(f"  (IP geolocation: lat={lat}, lon={lon})", file=sys.stderr)
        return lat, lon, 0
    except Exception as exc:
        print(f"  (IP geolocation failed: {exc}; using lat=0 lon=0 elev=0)",
              file=sys.stderr)
        return 0, 0, 0


def _expansion_scalar_aes_dm(seed_key: bytes, i: int, j: int, order_n: int) -> int:
    """AES-ECB butterfly key expansion KDF (SCMS pseudonym cert profile).

    Computes f_k(i, j) mod N for butterfly key expansion:
        kU = (sk_base + f_k(i, j)) mod N

    Algorithm matches DataSigner.expansion_scalar_aes_dm() in faulty-bsm-generator.
    """
    if len(seed_key) not in (16, 24, 32):
        raise ValueError("seed_key must be 16/24/32 bytes for AES")

    x_int = ((i & 0xFFFFFFFF) << 64) | ((j & 0xFFFFFFFF) << 32)
    x = x_int.to_bytes(16, "big")

    blocks = []
    for t in (1, 2, 3):
        xt = (int.from_bytes(x, "big") + t) & ((1 << 128) - 1)
        xt_bytes = xt.to_bytes(16, "big")
        cipher = Cipher(algorithms.AES(seed_key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(xt_bytes) + enc.finalize()
        blocks.append(bytes(a ^ b for a, b in zip(ct, xt_bytes)))

    return int.from_bytes(b"".join(blocks), "big") % order_n


def _find_issuer_cert_coer(bundle_dir: str, issuer_hid8: bytes) -> bytes:
    """Scan trustedcerts/ and certchain/ for the cert whose SHA-256[-8:] matches issuer_hid8."""
    import pathlib
    for subdir in ("trustedcerts", "certchain"):
        root = pathlib.Path(bundle_dir) / subdir
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            b = p.read_bytes()
            if hashlib.sha256(b).digest()[-8:] == issuer_hid8:
                return b
    raise RuntimeError(f"Issuer cert not found for HashedId8={issuer_hid8.hex()}")


def load_signing_key(path: str, bundle_dir: str = None):
    """Load the actual P-256 signing key for an ISS SCMS application certificate.

    ISS SCMS issues implicit (ECQV) application certificates per IEEE 1609.2.

    For RSU bundles (rsu-N/downloadFiles/<hash>.s):
      bundle_dir defaults to the rsu-N/ directory (one level above downloadFiles/).

    For pseudonym bundles (download/{i}/{i}_{j}.s):
      bundle_dir must be passed explicitly (the root of the pseudonym bundle).
      Butterfly expansion is applied when sgn_expnsn.key is present at bundle_dir.

    ECQV key reconstruction (IEEE 1609.2 §5.3.2 / SCMS profile):
      tbs_coer  = COER(cert.toBeSigned)
      e         = SHA-256( SHA-256(tbs_coer) || SHA-256(issuer_cert_coer) )  mod n
      kU        = (sk_base + f_k(i, j))  mod n      [butterfly; else kU = sk_base]
      dU        = (r + e * kU)  mod n

    path is expected to be the .s file.
    Falls back to PEM if path does not point to a 32-byte raw scalar.
    """
    # P-256 curve order
    _N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    with open(path, 'rb') as f:
        data = f.read()

    if len(data) == 32:
        r = int.from_bytes(data, 'big')

        # Locate bundle_dir (contains dwnl_sgn.priv, certchain/, trustedcerts/)
        if bundle_dir is None:
            # RSU layout: dwnl_sgn.priv lives one level above downloadFiles/
            bundle_dir = os.path.dirname(os.path.dirname(path))
        seed_path = os.path.join(bundle_dir, 'dwnl_sgn.priv')
        with open(seed_path, 'rb') as f:
            sk_base = int.from_bytes(f.read(), 'big')

        # Load corresponding cert
        cert_path = path[:-2] + '.cert'
        with open(cert_path, 'rb') as f:
            cert_bytes = f.read()

        # Butterfly expansion when sgn_expnsn.key is present (pseudonym bundle)
        exp_path = os.path.join(bundle_dir, 'sgn_expnsn.key')
        if os.path.exists(exp_path):
            with open(exp_path, 'rb') as f:
                sgn_expnsn = f.read()
            # i and j are hex values encoded in the filename: {i}_{j}.cert
            basename = os.path.splitext(os.path.basename(cert_path))[0]
            parts = basename.split('_')
            i_val = int(parts[0], 16)
            j_val = int(parts[1], 16)
            f_ij = _expansion_scalar_aes_dm(sgn_expnsn, i_val, j_val, _N)
            kU = (sk_base + f_ij) % _N
        else:
            kU = sk_base

        # Correct e: SHA-256( SHA-256(COER(TBS)) || SHA-256(issuer_cert) ) mod n
        cert_dict = decode_oer("Certificate", cert_bytes)
        tbs_coer = encode_jer("ToBeSignedCertificate", cert_dict["toBeSigned"])
        issuer_info = cert_dict.get("issuer", {})
        issuer_hid8_hex = (issuer_info.get("sha256AndDigest")
                           or issuer_info.get("sha384AndDigest"))
        if issuer_hid8_hex:
            try:
                issuer_cert_coer = _find_issuer_cert_coer(
                    bundle_dir, bytes.fromhex(issuer_hid8_hex))
                e = int.from_bytes(
                    hashlib.sha256(
                        hashlib.sha256(tbs_coer).digest() +
                        hashlib.sha256(issuer_cert_coer).digest()
                    ).digest(), 'big'
                ) % _N
            except RuntimeError as exc:
                print(f"  WARNING: {exc}; falling back to SHA256(cert) for e",
                      file=sys.stderr)
                e = int.from_bytes(hashlib.sha256(cert_bytes).digest(), 'big') % _N
        else:
            e = int.from_bytes(hashlib.sha256(cert_bytes).digest(), 'big') % _N

        scalar = (r + (e * kU) % _N) % _N
        return ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())

    return serialization.load_pem_private_key(data, password=None,
                                               backend=default_backend())


def parse_cert_validity(cert_bytes: bytes):
    """Parse (start, expire) as UTC datetimes from an IEEE 1609.2 cert.

    Scans for a ValidityPeriod: Time32 (4 bytes) followed by a Duration
    CHOICE tag (0x80–0x86) and Uint16 value.  Collects all plausible matches
    (start in 2015–2040 range, duration >= 1 hour) and returns the one with
    the latest start — avoiding false positives from incidental byte patterns
    elsewhere in the cert with very short durations.
    """
    EPOCH = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)
    DURATION_SECS = {0: 1e-6, 1: 1e-3, 2: 1, 3: 60, 4: 3600, 5: 216000, 6: 365.25 * 86400}
    lo = datetime.datetime(2015, 1, 1, tzinfo=datetime.timezone.utc)
    hi = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
    candidates = []
    for i in range(len(cert_bytes) - 6):
        tag = cert_bytes[i + 4]
        if 0x80 <= tag <= 0x86:
            t = struct.unpack_from('>I', cert_bytes, i)[0]
            start = EPOCH + datetime.timedelta(seconds=t)
            if lo <= start <= hi:
                alt = tag & 0x07
                val = struct.unpack_from('>H', cert_bytes, i + 5)[0]
                secs = val * DURATION_SECS[alt]
                if secs >= 3600:  # ignore durations shorter than 1 hour (false positives)
                    try:
                        expire = start + datetime.timedelta(seconds=secs)
                    except OverflowError:
                        continue
                    candidates.append((start, expire))
    if not candidates:
        raise ValueError("Could not parse validity period from certificate")
    return max(candidates, key=lambda x: x[0])  # latest start


def select_rsu_cert(certs_dir: str):
    """Scan rsu-*/downloadFiles/*.cert under certs_dir and return (cert_path, key_path)
    for the currently valid certificate with the earliest expiry.
    Exits with an error if no valid certificate is found.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    candidates = []
    for cert_path in sorted(glob.glob(
            os.path.join(certs_dir, 'rsu-*/downloadFiles/*.cert'))):
        key_path = cert_path[:-5] + '.s'
        if not os.path.exists(key_path):
            continue
        try:
            with open(cert_path, 'rb') as fh:
                start, expire = parse_cert_validity(fh.read())
        except ValueError:
            continue
        if start <= now < expire:
            candidates.append((expire, cert_path, key_path))
    if not candidates:
        print(f"ERROR: no valid RSU certificate found under {certs_dir} "
              f"(current UTC time: {now.strftime('%Y-%m-%d %H:%M:%S')})",
              file=sys.stderr)
        # Print all certs found with their validity windows to aid diagnosis
        for cert_path in sorted(glob.glob(
                os.path.join(certs_dir, 'rsu-*/downloadFiles/*.cert'))):
            try:
                with open(cert_path, 'rb') as fh:
                    start, expire = parse_cert_validity(fh.read())
                status = "not yet valid" if now < start else "expired"
                print(f"  {cert_path}: {start.strftime('%Y-%m-%d %H:%M')} – "
                      f"{expire.strftime('%Y-%m-%d %H:%M')} UTC  [{status}]",
                      file=sys.stderr)
            except ValueError:
                print(f"  {cert_path}: could not parse validity period",
                      file=sys.stderr)
        sys.exit(1)
    candidates.sort()
    _, cert_path, key_path = candidates[0]
    return cert_path, key_path


def select_pseudonym_cert(certs_dir: str):
    """Scan download/{i}/{i}_{j}.cert under certs_dir and return (cert_path, key_path)
    for the currently valid certificate with the earliest expiry.
    Exits with an error if no valid certificate is found.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    candidates = []
    for cert_path in sorted(glob.glob(
            os.path.join(certs_dir, 'download', '*', '*.cert'))):
        key_path = cert_path[:-5] + '.s'
        if not os.path.exists(key_path):
            continue
        try:
            with open(cert_path, 'rb') as fh:
                start, expire = parse_cert_validity(fh.read())
        except ValueError:
            continue
        if start <= now < expire:
            candidates.append((expire, cert_path, key_path))
    if not candidates:
        print(f"ERROR: no valid pseudonym certificate found under {certs_dir}/download/ "
              f"(current UTC time: {now.strftime('%Y-%m-%d %H:%M:%S')})",
              file=sys.stderr)
        for cert_path in sorted(glob.glob(
                os.path.join(certs_dir, 'download', '*', '*.cert'))):
            try:
                with open(cert_path, 'rb') as fh:
                    start, expire = parse_cert_validity(fh.read())
                status = "not yet valid" if now < start else "expired"
                print(f"  {cert_path}: {start.strftime('%Y-%m-%d %H:%M')} – "
                      f"{expire.strftime('%Y-%m-%d %H:%M')} UTC  [{status}]",
                      file=sys.stderr)
            except ValueError:
                print(f"  {cert_path}: could not parse validity period",
                      file=sys.stderr)
        sys.exit(1)
    candidates.sort()
    _, cert_path, key_path = candidates[0]
    return cert_path, key_path


def load_recipient_pub(hex_str: str) -> bytes:
    data = bytes.fromhex(hex_str.replace(':', '').replace(' ', ''))
    if len(data) == 64:
        data = b'\x04' + data
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("Expected 65-byte uncompressed P-256 key (04 || x || y)")
    return data


def write_file(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)
    print(f"  {path}  ({len(data)} bytes)", file=sys.stderr)


def build_signed_1609_via_api(mbr_bytes: bytes, api_key: str, psid: int,
                               api_url: str) -> bytes:
    """Sign mbr_bytes via the ISS virtual device sign API.

    Returns raw OER bytes of Ieee1609Dot2Data { signedData } — same type
    returned by build_signed_1609() so callers are interchangeable.
    """
    import base64
    if _requests is None:
        raise RuntimeError("'requests' not installed; run: pip install requests")

    url     = api_url.rstrip("/") + "/api/v3/virtual-device/sign"
    payload = {"psid": psid, "tbsOer": base64.b64encode(mbr_bytes).decode()}
    headers = {"Content-Type": "application/json", "x-virtual-api-key": api_key}

    print(f"  POST {url}", file=sys.stderr)
    resp = _requests.post(url, json=payload, headers=headers, timeout=30)
    try:
        body = resp.json()
    except Exception:
        raise RuntimeError(f"ISS sign API non-JSON response (HTTP {resp.status_code}):\n{resp.text}")
    if resp.status_code != 200:
        raise RuntimeError(f"ISS sign API HTTP {resp.status_code}: {body}")
    if "signedPayload" not in body:
        raise RuntimeError(f"ISS sign API missing 'signedPayload': {body}")

    signed_oer = base64.b64decode(body["signedPayload"])
    print(f"  ISS signed payload: {len(signed_oer)} bytes", file=sys.stderr)
    return signed_oer


def build_encrypted_1609_via_api(signed_1609_bytes: bytes, api_key: str,
                                  recipient_device_id: str, api_url: str) -> bytes:
    """Encrypt signed_1609_bytes via the ISS virtual device encrypt API.

    Uses recipient.device_id so the output uses rekRecipInfo — decryptable
    by POST /virtual-device/decrypt with the same device's api-key.

    The signed payload is wrapped as Ieee1609Dot2Data { unsecuredData } before
    posting, per the API requirement that `message` is a C-OER Ieee1609Dot2Data.
    The API returns Ieee1609Dot2Data { encryptedData } OER bytes.
    """
    import base64

    if _requests is None:
        raise RuntimeError("'requests' not installed; run: pip install requests")

    # Wrap signed bytes as unsecuredData so the API receives a valid Ieee1609Dot2Data
    wrapped = encode_jer("Ieee1609Dot2Data", {
        "protocolVersion": 3,
        "content": {"unsecuredData": signed_1609_bytes.hex().upper()},
    })

    url     = api_url.rstrip("/") + "/api/v3/virtual-device/encrypt"
    payload = {
        "message":   base64.b64encode(wrapped).decode(),
        "recipient": {"device_id": recipient_device_id},
    }
    headers = {"Content-Type": "application/json", "x-virtual-api-key": api_key}

    print(f"  POST {url}", file=sys.stderr)
    resp = _requests.post(url, json=payload, headers=headers, timeout=30)
    try:
        body = resp.json()
    except Exception:
        raise RuntimeError(f"ISS encrypt API non-JSON response (HTTP {resp.status_code}):\n{resp.text}")
    if resp.status_code != 200:
        raise RuntimeError(f"ISS encrypt API HTTP {resp.status_code}: {body}")
    if "encryptedData" not in body:
        raise RuntimeError(f"ISS encrypt API missing 'encryptedData': {body}")

    enc_oer = base64.b64decode(body["encryptedData"])
    print(f"  ISS encrypted payload: {len(enc_oer)} bytes (rekRecipInfo)", file=sys.stderr)
    return enc_oer


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Build SaeJ3287Data COER variants (plaintext / signed / sTE)"
    )
    p.add_argument("--certs-dir",
                   help="SCMS bundle directory. For RSU bundles (rsu-*/downloadFiles/ layout) "
                        "the currently valid cert is selected automatically. For pseudonym bundles "
                        "(download/{i}/{i}_{j}.cert layout with sgn_expnsn.key) butterfly expansion "
                        "is applied automatically. Detection is based on the presence of download/.")
    p.add_argument("--sign-api-key",
                   help="ISS virtual-device x-virtual-api-key token; "
                        "when supplied the ISS sign API is used instead of local ECQV signing")
    p.add_argument("--sign-api-url", default="https://api.dm.preprod.v2x.isscms.com",
                   help="ISS DMS base URL for signing and API-based encryption "
                        "(default: https://api.dm.preprod.v2x.isscms.com)")
    p.add_argument("--recipient-cert",
                   help="Recipient MA certificate file (raw COER/DER); "
                        "derives the public key, recipientId (HashedId8), and KDF2 P1 — "
                        "use this instead of --recipient-pub for standard-compliant encryption")
    p.add_argument("--recipient-pub",
                   help="Recipient P-256 public key, hex-encoded uncompressed "
                        "(64 or 65 bytes); use --recipient-cert instead when the cert is available")
    p.add_argument("--encrypt-api-key",
                   help="ISS virtual-device x-virtual-api-key token for API-based encryption; "
                        "encrypts to the virtual device's own key (rekRecipInfo) — "
                        "decryptable via decrypt_mbr.py with the same token")
    p.add_argument("--encrypt-recipient-id",
                   help="Device ID to encrypt to (required with --encrypt-api-key)")
    p.add_argument("--bsm", required=True,
                   help="Input BSM / SaeJ3287Mbr COER file")
    p.add_argument("--out-dir", default="coer",
                   help="Output directory (default: coer/)")
    p.add_argument("--psid", type=int, default=38,
                   help="PSID for headerInfo (default: 38 = MBR)")
    p.add_argument("--lat",  type=int, default=None,
                   help="observationLocation latitude in 1e-7 deg units "
                        "(default: derived from IP geolocation)")
    p.add_argument("--lon",  type=int, default=None,
                   help="observationLocation longitude in 1e-7 deg units "
                        "(default: derived from IP geolocation)")
    p.add_argument("--elev", type=int, default=0,
                   help="observationLocation elevation (default: 0)")
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    if args.certs_dir and args.sign_api_key:
        print("ERROR: --certs-dir and --sign-api-key are mutually exclusive.",
              file=sys.stderr)
        sys.exit(1)

    if args.certs_dir:
        if os.path.isdir(os.path.join(args.certs_dir, 'download')):
            # Pseudonym bundle: download/{i}/{i}_{j}.cert + sgn_expnsn.key
            print(f"  Detected pseudonym bundle: {args.certs_dir}", file=sys.stderr)
            cert_path, key_path = select_pseudonym_cert(args.certs_dir)
            signing_key = load_signing_key(key_path, bundle_dir=args.certs_dir)
        else:
            # RSU bundle: rsu-*/downloadFiles/*.cert
            cert_path, key_path = select_rsu_cert(args.certs_dir)
            signing_key = load_signing_key(key_path)
        with open(cert_path, 'rb') as fh:
            cert_bytes_selected = fh.read()
        print(f"  Selected cert: {cert_path} "
              f"(SHA-256: {hashlib.sha256(cert_bytes_selected).hexdigest()[:16]}...)",
              file=sys.stderr)
    else:
        signing_key = None
        cert_bytes_selected = None
    if args.recipient_cert and args.recipient_pub:
        print("ERROR: --recipient-cert and --recipient-pub are mutually exclusive.",
              file=sys.stderr)
        sys.exit(1)
    if args.encrypt_api_key and (args.recipient_cert or args.recipient_pub):
        print("ERROR: --encrypt-api-key is mutually exclusive with "
              "--recipient-cert and --recipient-pub.",
              file=sys.stderr)
        sys.exit(1)

    recipient_cert_bytes = None
    recipient_pub = None
    if args.recipient_cert:
        with open(args.recipient_cert, 'rb') as fh:
            recipient_cert_bytes = fh.read()
        # Extract the ECIES encryption public key from the cert.
        # MA certs carry it in toBeSigned.encryptionKey.publicKey.eciesNistP256
        # (a BasePublicEncryptionKey CHOICE, index 0).
        cert_dict = decode_oer("Certificate", recipient_cert_bytes)
        try:
            ek = cert_dict["toBeSigned"]["encryptionKey"]["publicKey"]["eciesNistP256"]
            if "compressed-y-0" in ek:
                raw = bytes.fromhex("02" + ek["compressed-y-0"])
            elif "compressed-y-1" in ek:
                raw = bytes.fromhex("03" + ek["compressed-y-1"])
            elif "uncompressedP256" in ek:
                raw = bytes.fromhex("04" + ek["uncompressedP256"]["x"] + ek["uncompressedP256"]["y"])
            else:
                raise ValueError(f"Unsupported eciesNistP256 format: {list(ek.keys())}")
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
            recipient_pub = pub_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        except Exception as exc:
            print(f"ERROR: could not extract encryption key from {args.recipient_cert}: {exc}",
                  file=sys.stderr)
            sys.exit(1)
        print(f"  Recipient cert: {args.recipient_cert} "
              f"(id: {hashlib.sha256(recipient_cert_bytes).digest()[-8:].hex().upper()})",
              file=sys.stderr)
    elif args.recipient_pub:
        recipient_pub = load_recipient_pub(args.recipient_pub)
        print("  WARNING: --recipient-pub used without --recipient-cert; "
              "recipientId and KDF2 P1 will be zero/empty (non-compliant).",
              file=sys.stderr)
    with open(args.bsm, 'rb') as f:
        bsm_bytes = f.read()

    if args.lat is None or args.lon is None:
        geo_lat, geo_lon, _ = geolocate_ip()
        lat  = args.lat  if args.lat  is not None else geo_lat
        lon  = args.lon  if args.lon  is not None else geo_lon
    else:
        lat, lon = args.lat, args.lon

    print("Building MBR from BSM...", file=sys.stderr)
    gen_time  = tai64_now()
    mbr_bytes = build_mbr_from_bsm(bsm_bytes, lat=lat, lon=lon, elev=args.elev,
                                    gen_time=gen_time)
    print("Writing:", file=sys.stderr)

    # Plaintext: SaeJ3287Data { version=1, content { plaintext: SaeJ3287Mbr } }
    write_file(
        os.path.join(args.out_dir, "out_plaintext.coer"),
        encode_jer("SaeJ3287Data", {
            "version": 1,
            "content": {"plaintext": decode_oer("SaeJ3287Mbr", mbr_bytes)},
        }),
    )

    if signing_key is None and not args.sign_api_key:
        print("  (skipping signed and sTE variants: no --certs-dir or --sign-api-key provided)",
              file=sys.stderr)
        return

    # ── Signed variant ───────────────────────────────────────────────────────
    if args.sign_api_key:
        signed_1609 = build_signed_1609_via_api(
            mbr_bytes, args.sign_api_key, args.psid, args.sign_api_url)
    else:
        cert_bytes = cert_bytes_selected
        signed_1609 = build_signed_1609(mbr_bytes, signing_key, cert_bytes, args.psid,
                                         gen_time=gen_time)

    # Signed: SaeJ3287Data { version=1, content { signed: Ieee1609Dot2Data { signedData } } }
    write_file(
        os.path.join(args.out_dir, "out_signed.coer"),
        encode_jer("SaeJ3287Data", {
            "version": 1,
            "content": {"signed": decode_oer("Ieee1609Dot2Data", signed_1609)},
        }),
    )

    if recipient_pub is None and not args.encrypt_api_key:
        print("  (skipping sTE variant: no --recipient-cert/--recipient-pub "
              "or --encrypt-api-key provided)", file=sys.stderr)
        return

    # sTE: SaeJ3287Data { version=1, content { sTE: Ieee1609Dot2Data { encryptedData } } }
    if args.encrypt_api_key:
        if not args.encrypt_recipient_id:
            print("ERROR: --encrypt-recipient-id is required with --encrypt-api-key.",
                  file=sys.stderr)
            sys.exit(1)
        # API path: rekRecipInfo — encrypted to virtual device's own key
        ste_1609 = build_encrypted_1609_via_api(
            signed_1609, args.encrypt_api_key, args.encrypt_recipient_id, args.sign_api_url)
    else:
        # Local path: certRecipInfo — encrypted to MA certificate
        ste_1609 = build_encrypted_1609(signed_1609, recipient_pub, recipient_cert_bytes)
    write_file(
        os.path.join(args.out_dir, "out_ste.coer"),
        encode_jer("SaeJ3287Data", {
            "version": 1,
            "content": {"sTE": decode_oer("Ieee1609Dot2Data", ste_1609)},
        }),
    )


if __name__ == "__main__":
    main()
