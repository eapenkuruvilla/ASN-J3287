#!/usr/bin/env python3
"""
create_mbr.py - Build SaeJ3287Data from an input BSM (Ieee1609Dot2Data).

Usage:
    python create_mbr.py \\
        --bsm  data/Ieee1609Dot2Data_bad_accel.coer \\
        [--certs-dir certs/e0c324c643aca860] \\
        [--recipient-pub <hex_uncompressed_pubkey>] \\
        [--out-dir coer/]

The script reads the BSM, hard-codes a LongAcc-ValueTooLarge observation
(tgtId=5, obsId=4), sets generationTime to the current TAI time, and
constructs a SaeJ3287Mbr (EtsiTs103759Mbr) that embeds the BSM as
IEEE 1609.2 V2xPduStream evidence.

Produces:
    {out_dir}/out_plaintext.coer   -- SaeJ3287MbrSec.plaintext
    {out_dir}/out_signed.coer      -- SaeJ3287MbrSec.signed (if --certs-dir)
    {out_dir}/out_ste.coer         -- SaeJ3287MbrSec.sTE    (if --certs-dir + --recipient-pub)

Certs:
    --certs-dir     Path to the SCMS organisation cert store (e.g. certs/e0c324c643aca860).
                    The script scans rsu-*/downloadFiles/*.cert under this directory,
                    selects the currently valid certificate with the earliest expiry,
                    and uses the corresponding .s key file for signing.
    --recipient-pub Recipient P-256 public key, hex-encoded, uncompressed
                    (65 bytes: 04 || x || y, or 64 bytes without the 04 prefix)
                    (optional)
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


def load_signing_key(path: str):
    """Load the actual P-256 signing key for an ISS SCMS application certificate.

    ISS SCMS issues implicit (ECQV) application certificates per IEEE 1609.2.
    Per the ISS SCMS DMS Master Guide (Guidance Notes / File Structure):
      - downloadFiles/<hash>.s     : private key reconstruction value  r  (32 bytes)
      - downloadFiles/<hash>.cert  : the implicit certificate (same base name)
      - rsu-N/dwnl_sgn.priv        : seed signing key  k_seed  (32 bytes)

    ECQV key reconstruction (IEEE 1609.2 §5.3.2):
      e      = SHA-256( COER(cert.toBeSigned) )   as a big-endian integer
      d      = (e * k_seed + r) mod n             (P-256 curve order)

    path is expected to be the .s file inside downloadFiles/.
    Falls back to PEM if path does not point to a 32-byte raw scalar.
    """
    from asn1c_lib import decode_oer, encode_jer

    # P-256 curve order
    _N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    with open(path, 'rb') as f:
        data = f.read()

    if len(data) == 32:
        r = int.from_bytes(data, 'big')

        # dwnl_sgn.priv lives one level above downloadFiles/
        seed_path = os.path.join(os.path.dirname(os.path.dirname(path)), 'dwnl_sgn.priv')
        with open(seed_path, 'rb') as f:
            k_seed = int.from_bytes(f.read(), 'big')

        # e = SHA-256( COER(cert) ) — hash of the full raw cert bytes
        cert_path = path[:-2] + '.cert'
        with open(cert_path, 'rb') as f:
            cert_bytes = f.read()
        e = int.from_bytes(hashlib.sha256(cert_bytes).digest(), 'big')

        scalar = (e * k_seed + r) % _N
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


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Build SaeJ3287Data COER variants (plaintext / signed / sTE)"
    )
    p.add_argument("--certs-dir",
                   help="SCMS organisation cert store directory (e.g. certs/e0c324c643aca860); "
                        "the currently valid rsu-*/downloadFiles/ cert is selected automatically")
    p.add_argument("--sign-api-key",
                   help="ISS virtual-device x-virtual-api-key token; "
                        "when supplied the ISS sign API is used instead of local ECQV signing")
    p.add_argument("--sign-api-url", default="https://api.dm.preprod.v2x.isscms.com",
                   help="ISS DMS base URL for signing (default: https://api.dm.preprod.v2x.isscms.com)")
    p.add_argument("--recipient-pub",
                   help="Recipient P-256 public key, hex-encoded uncompressed "
                        "(64 or 65 bytes); omit to skip sTE variant")
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
    recipient_pub = load_recipient_pub(args.recipient_pub) if args.recipient_pub else None
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

    if recipient_pub is None:
        print("  (skipping sTE variant: no --recipient-pub provided)", file=sys.stderr)
        return

    # sTE: SaeJ3287Data { version=1, content { sTE: Ieee1609Dot2Data { encryptedData } } }
    ste_1609 = build_encrypted_1609(signed_1609, recipient_pub)
    write_file(
        os.path.join(args.out_dir, "out_ste.coer"),
        encode_jer("SaeJ3287Data", {
            "version": 1,
            "content": {"sTE": decode_oer("Ieee1609Dot2Data", ste_1609)},
        }),
    )


if __name__ == "__main__":
    main()
