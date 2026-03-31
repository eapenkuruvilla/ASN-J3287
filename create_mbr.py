#!/usr/bin/env python3
"""
create_mbr.py - Build SaeJ3287Data from an input BSM (Ieee1609Dot2Data).

Usage:
    python create_mbr.py \\
        --bsm  data/Ieee1609Dot2Data_bad_accel.coer \\
        [--certs-dir certs/e0c324c643aca860] \\
        [--recipient-pub <hex_uncompressed_pubkey>] \\
        [--out-dir coer/]

The script reads the BSM, extracts generationTime and generationLocation from
its headerInfo, hard-codes a LongAcc-ValueTooLarge observation (tgtId=5,
obsId=4), and constructs a SaeJ3287Mbr (EtsiTs103759Mbr) that embeds the BSM
as IEEE 1609.2 V2xPduStream evidence.

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
import hmac as _hmac
import os
import secrets
import struct
import sys

try:
    import requests as _requests
except ImportError:
    _requests = None

from decode_mbr import decode_oer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
try:
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
except ImportError:
    from cryptography.hazmat.primitives.hashes import Prehashed

# ── OER primitive encoders ────────────────────────────────────────────────────

def enc_uint8(v: int) -> bytes:   return struct.pack('B', v)
def enc_uint16(v: int) -> bytes:  return struct.pack('>H', v)
def enc_uint32(v: int) -> bytes:  return struct.pack('>I', v)
def enc_uint64(v: int) -> bytes:  return struct.pack('>Q', v)

def enc_length(n: int) -> bytes:
    """OER/COER length determinant."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82]) + struct.pack('>H', n)
    else:
        return bytes([0x84]) + struct.pack('>I', n)

def enc_octet_string_var(data: bytes) -> bytes:
    """Variable-length OCTET STRING: length + data."""
    return enc_length(len(data)) + data

def enc_integer_var(v: int) -> bytes:
    """OER unconstrained non-negative INTEGER: length + two's-complement big-endian.
    A leading zero byte is added when the high bit of the value would be set,
    to prevent misinterpretation as a negative two's-complement value.
    """
    if v == 0:
        return b'\x01\x00'
    n = (v.bit_length() + 7) // 8
    raw = v.to_bytes(n, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return enc_length(len(raw)) + raw

def enc_quantity(count: int) -> bytes:
    """SEQUENCE OF / SET OF quantity field (oer_put_quantity)."""
    return enc_integer_var(count)

def enc_open_type(data: bytes) -> bytes:
    """Open type (ANY): length + value."""
    return enc_length(len(data)) + data

def enc_choice(index: int, value: bytes) -> bytes:
    """OER CHOICE: context tag (0x80|index) + value.
    No length wrapper — applies to both extensible and non-extensible CHOICEs
    when encoding root alternatives (before '...'). Extension additions would
    need a length wrapper, but none are used here.
    """
    if index >= 63:
        raise ValueError(f"CHOICE index {index} out of range for root alternatives (0–62)")
    return bytes([0x80 | index]) + value

def enc_enum(value: int) -> bytes:
    """OER ENUMERATED root value (0–127): 1 byte."""
    return bytes([value])


# ── IEEE 1609.2 base-type encoders ───────────────────────────────────────────

def enc_psid(psid: int) -> bytes:
    """Psid = INTEGER (0..MAX): variable-length unsigned."""
    return enc_integer_var(psid)

def enc_hashedid8(h: bytes) -> bytes:
    assert len(h) == 8
    return h

def enc_hashedid3(h: bytes) -> bytes:
    assert len(h) == 3
    return h

def enc_ecc_p256_compressed(pubkey) -> bytes:
    """EccP256CurvePoint: compressed-y-0 (index 2) or compressed-y-1 (index 3)."""
    raw = pubkey.public_bytes(serialization.Encoding.X962,
                              serialization.PublicFormat.CompressedPoint)
    # raw[0] = 0x02 (y even) or 0x03 (y odd)
    choice_index = 2 if raw[0] == 0x02 else 3
    return enc_choice(choice_index, raw[1:])   # 32-byte x

def enc_ecc_p256_xonly(x_bytes: bytes) -> bytes:
    """EccP256CurvePoint: x-only (index 0)."""
    return enc_choice(0, x_bytes)

def enc_ecdsa_p256_signature(r: int, s: int) -> bytes:
    """EcdsaP256Signature { rSig EccP256CurvePoint, sSig OCTET STRING(32) }."""
    r_sig = enc_ecc_p256_xonly(r.to_bytes(32, 'big'))
    s_sig = s.to_bytes(32, 'big')
    return r_sig + s_sig

def enc_signature_p256(r: int, s: int) -> bytes:
    """Signature CHOICE index 0 = ecdsaNistP256Signature. Signature is extensible."""
    return enc_choice(0, enc_ecdsa_p256_signature(r, s))

def enc_hash_algorithm_sha256() -> bytes:
    """HashAlgorithm::sha256 = 0."""
    return enc_enum(0)

def enc_duration_hours(h: int) -> bytes:
    """Duration CHOICE index 4 = hours (Uint16)."""
    return enc_choice(4, enc_uint16(h))

def enc_validity_period(start: int, hours: int) -> bytes:
    """ValidityPeriod { start Time32, duration Duration }."""
    return enc_uint32(start) + enc_duration_hours(hours)

def enc_psid_ssp(psid: int) -> bytes:
    """PsidSsp { psid Psid, ssp OPTIONAL }.
    Preamble: bit7=0 (no ssp).
    """
    return b'\x00' + enc_psid(psid)

def enc_seq_of_psid_ssp(psids: list) -> bytes:
    """SequenceOfPsidSsp = SEQUENCE OF PsidSsp."""
    items = b''.join(enc_psid_ssp(p) for p in psids)
    return enc_quantity(len(psids)) + items

def enc_identified_region_country(cc: int) -> bytes:
    """IdentifiedRegion CHOICE index 0 = countryOnly (Uint16)."""
    return enc_choice(0, enc_uint16(cc))

def enc_geographic_region_identified(country_code: int) -> bytes:
    """GeographicRegion CHOICE index 3 = identifiedRegion (SEQUENCE OF)."""
    item = enc_identified_region_country(country_code)
    seq = enc_quantity(1) + item
    return enc_choice(3, seq)

def enc_certificate_id_name(name: str) -> bytes:
    """CertificateId CHOICE index 1 = name (Hostname = UTF8String)."""
    b = name.encode('utf-8')
    return enc_choice(1, enc_octet_string_var(b))

def enc_public_verification_key_p256(pubkey) -> bytes:
    """PublicVerificationKey CHOICE index 0 = ecdsaNistP256."""
    return enc_choice(0, enc_ecc_p256_compressed(pubkey))

def enc_verification_key_indicator(pubkey) -> bytes:
    """VerificationKeyIndicator CHOICE index 0 = verificationKey."""
    return enc_choice(0, enc_public_verification_key_p256(pubkey))

def enc_issuer_self() -> bytes:
    """IssuerIdentifier CHOICE index 1 = self (HashAlgorithm=sha256)."""
    return enc_choice(1, enc_hash_algorithm_sha256())


# ── Certificate building ──────────────────────────────────────────────────────

def enc_to_be_signed_cert(pubkey, start: int, hours: int,
                           psids: list, name: str,
                           country_code: int = 840) -> bytes:
    """ToBeSignedCertificate OER encoding.

    Pre-extension optional fields preamble (8 bits):
      bit7: extension    = 0
      bit6: region       = 1  (present)
      bit5: assurance    = 0
      bit4: appPerms     = 1  (present)
      bit3: certIssuePerms = 0
      bit2: certReqPerms = 0
      bit1: canRollover  = 0
      bit0: encKey       = 0
    → 0b01010000 = 0x50
    """
    preamble = 0x50
    body = (
        enc_certificate_id_name(name)             # id
        + enc_hashedid3(bytes(3))                  # cracaId (3 zeros)
        + enc_uint16(0)                            # crlSeries
        + enc_validity_period(start, hours)        # validityPeriod
        + enc_geographic_region_identified(country_code)  # region (OPTIONAL)
        + enc_seq_of_psid_ssp(psids)               # appPermissions (OPTIONAL)
        + enc_verification_key_indicator(pubkey)   # verifyKeyIndicator
    )
    return bytes([preamble]) + body


def _sign_digest(signing_key, digest32: bytes) -> tuple:
    """ECDSA P-256 sign a pre-computed 32-byte digest. Returns (r, s)."""
    try:
        # cryptography >= 40: Prehashed requires the hash algorithm
        prehashed = Prehashed(hashes.SHA256())
    except TypeError:
        # older cryptography: Prehashed() takes no arguments
        prehashed = Prehashed()
    sig_der = signing_key.sign(digest32, ec.ECDSA(prehashed))
    return decode_dss_signature(sig_der)


def _1609_cert_signing_hash(issuer_cert_hash32: bytes, tbs_bytes: bytes) -> bytes:
    """IEEE 1609.2 certificate signing hash (§5.3.1.2.2).
    = SHA-256( SHA-256(tbs_bytes) || issuer_cert_hash )
    Data hash comes first; signer identifier hash comes second.
    """
    tbs_hash = hashlib.sha256(tbs_bytes).digest()
    return hashlib.sha256(tbs_hash + issuer_cert_hash32).digest()


def build_certificate(signing_key, start: int, hours: int,
                      psids: list, name: str = "test") -> bytes:
    """Build and sign a self-issued explicit Certificate.

    CertificateBase preamble: bit7=1 (signature present).

    Self-issued → signer identifier input = empty string → SHA-256(b"").
    """
    pubkey = signing_key.public_key()
    tbs_cert = enc_to_be_signed_cert(pubkey, start, hours, psids, name)

    # version=3, type=explicit(0), issuer=self, toBeSigned
    cert_tbs = enc_uint8(3) + enc_enum(0) + enc_issuer_self() + tbs_cert

    # Per IEEE 1609.2 §5.3.1.2.2: Data input = COER(ToBeSignedCertificate) = tbs_cert.
    # Signer identifier input for self-signed = empty string → SHA-256(b"").
    issuer_hash = hashlib.sha256(b"").digest()
    digest = _1609_cert_signing_hash(issuer_hash, tbs_cert)
    r, s = _sign_digest(signing_key, digest)
    signature = enc_signature_p256(r, s)

    # CertificateBase: preamble(signature present) | tbs | signature
    return b'\x80' + cert_tbs + signature


# ── 1609.2 data signing ───────────────────────────────────────────────────────

def enc_ieee1609dot2data_unsecured(mbr_bytes: bytes) -> bytes:
    """Ieee1609Dot2Data { protocolVersion=3, content.unsecuredData=mbr_bytes }."""
    content = enc_choice(0, enc_octet_string_var(mbr_bytes))  # unsecuredData
    return enc_uint8(3) + content


def enc_signed_data_payload(inner_1609_bytes: bytes) -> bytes:
    """SignedDataPayload { data Ieee1609Dot2Data OPTIONAL, ... }.

    Preamble (extension + data + extDataHash):
      bit7: extension = 0
      bit6: data      = 1
      bit5: extData   = 0
    → 0x40
    """
    return b'\x40' + inner_1609_bytes


def enc_header_info(psid: int) -> bytes:
    """HeaderInfo { psid, optionals all absent }.

    Preamble (extension + 6 optionals):
      all zero → 0x00
    """
    return b'\x00' + enc_psid(psid)


def enc_to_be_signed_data(mbr_bytes: bytes, psid: int) -> bytes:
    """ToBeSignedData { payload, headerInfo }."""
    inner = enc_ieee1609dot2data_unsecured(mbr_bytes)
    payload = enc_signed_data_payload(inner)
    header = enc_header_info(psid)
    return payload + header


def _1609_data_signing_hash(cert_bytes: bytes, tbs_bytes: bytes) -> bytes:
    """IEEE 1609.2 data signing hash (§5.3.1.2.2).
    = SHA-256( SHA-256(tbsData) || SHA-256(cert) )
    Data hash comes first; signer identifier hash comes second.
    """
    tbs_hash = hashlib.sha256(tbs_bytes).digest()
    cert_hash = hashlib.sha256(cert_bytes).digest()
    return hashlib.sha256(tbs_hash + cert_hash).digest()


def enc_signer_certificate(cert_bytes: bytes) -> bytes:
    """SignerIdentifier CHOICE index 1 = certificate (SequenceOfCertificate)."""
    seq_of_cert = enc_quantity(1) + cert_bytes
    return enc_choice(1, seq_of_cert)


def enc_signed_data(tbs_bytes: bytes, signer_bytes: bytes, r: int, s: int) -> bytes:
    """SignedData { hashId, tbsData, signer, signature }."""
    return (
        enc_hash_algorithm_sha256()
        + tbs_bytes
        + signer_bytes
        + enc_signature_p256(r, s)
    )


def build_signed_1609(mbr_bytes: bytes, signing_key,
                      cert_bytes: bytes, psid: int = 38) -> bytes:
    """Build Ieee1609Dot2Data { signedData { ... } } over mbr_bytes."""
    tbs_bytes = enc_to_be_signed_data(mbr_bytes, psid)
    digest = _1609_data_signing_hash(cert_bytes, tbs_bytes)
    r, s = _sign_digest(signing_key, digest)
    signer = enc_signer_certificate(cert_bytes)
    signed = enc_signed_data(tbs_bytes, signer, r, s)
    # Ieee1609Dot2Data { protocolVersion=3, content.signedData }
    return enc_uint8(3) + enc_choice(1, signed)


# ── ECIES-P256 + AES-128-CCM encryption ──────────────────────────────────────

def _x963_kdf(z: bytes, length: int, p1: bytes = b'') -> bytes:
    """ANSI X9.63 KDF2 with SHA-256.

    Per IEEE 1609.2 §5.3.5.1: Hash( Z || counter || P1 ).
    For certRecipInfo, P1 = SHA-256(COER(recipient_cert)).
    Placeholder: p1=b'' (zero-length) until MA cert is available.
    """
    out = b''
    counter = 1
    while len(out) < length:
        out += hashlib.sha256(z + struct.pack('>I', counter) + p1).digest()
        counter += 1
    return out[:length]


def build_encrypted_1609(signed_1609_bytes: bytes,
                          recipient_pub_uncompressed: bytes) -> bytes:
    """Build Ieee1609Dot2Data { encryptedData } wrapping signed_1609_bytes.

    Procedure:
      1. Generate random CEK (16 bytes) and nonce (12 bytes).
      2. Encrypt payload with AES-128-CCM(CEK, nonce).
      3. Generate ephemeral P-256 key; ECDH with recipient public key → Z.
      4. KDF(Z) → K_enc (16) || K_mac (16).
      5. c = AES-128-ECB(K_enc, CEK).
      6. t = HMAC-SHA256(K_mac, v_compressed || c)[0:16].
      7. Build EncryptedData structure.
    """
    # Step 1–2: AES-128-CCM encrypt the signed payload
    cek = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ct_with_tag = AESCCM(cek, tag_length=16).encrypt(nonce, signed_1609_bytes, None)

    # Step 3: ephemeral key + ECDH
    eph_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    eph_pub = eph_key.public_key()
    recip_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), recipient_pub_uncompressed
    )
    Z = eph_key.exchange(ECDH(), recip_pub)

    # Step 4: KDF — 48 bytes: K_enc (16) || K_mac (32).
    # P1 = SHA-256(COER(recipient_cert)); placeholder b'' until MA cert available.
    K = _x963_kdf(Z, 48)
    K_enc, K_mac = K[:16], K[16:48]

    # Step 5: encrypt CEK with stream cipher (XOR with KDF output) per §5.3.4.
    c = bytes(a ^ b for a, b in zip(cek, K_enc))  # 16 bytes

    # Step 6: MAC
    v_compressed = eph_pub.public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.CompressedPoint)
    t = _hmac.new(K_mac, v_compressed + c, hashlib.sha256).digest()[:16]

    # Encode EciesP256EncryptedKey { v EccP256CurvePoint, c OCTET STRING(16), t OCTET STRING(16) }
    v_encoded = enc_ecc_p256_compressed(eph_pub)
    ecies_key = v_encoded + c + t   # c and t are fixed 16 bytes each (no length)

    # EncryptedDataEncryptionKey CHOICE index 0 = eciesNistP256.
    enc_data_key = enc_choice(0, ecies_key)

    # PKRecipientInfo { recipientId HashedId8, encKey EncryptedDataEncryptionKey }
    # recipientId = last 8 bytes of SHA-256(OER(MA cert)).
    # Placeholder zeros until the RA/MA certificate is available.
    recip_id = bytes(8)
    pk_recip = enc_hashedid8(recip_id) + enc_data_key

    # RecipientInfo CHOICE index 2 = certRecipInfo (PKRecipientInfo). NOT extensible.
    recip_info = enc_choice(2, pk_recip)

    # SequenceOfRecipientInfo = SEQUENCE OF RecipientInfo
    recipients = enc_quantity(1) + recip_info

    # One28BitCcmCiphertext { nonce OCTET STRING(12), ccmCiphertext Opaque }
    ccm_ct = nonce + enc_octet_string_var(ct_with_tag)   # nonce is fixed 12 bytes

    # SymmetricCiphertext CHOICE index 0 = aes128ccm.
    sym_ct = enc_choice(0, ccm_ct)

    # EncryptedData { recipients, ciphertext }
    enc_data = recipients + sym_ct

    # Ieee1609Dot2Data { protocolVersion=3, content.encryptedData (index 2) }
    return enc_uint8(3) + enc_choice(2, enc_data)


# ── SaeJ3287Data wrapper ──────────────────────────────────────────────────────

def enc_sae_j3287_data(variant_index: int, inner_bytes: bytes) -> bytes:
    """SaeJ3287Data { version=1, content SaeJ3287MbrSec }.
    SaeJ3287MbrSec CHOICE:  0=plaintext, 1=signed, 2=sTE.
    """
    return enc_uint8(1) + enc_choice(variant_index, inner_bytes)


# ── Helpers ───────────────────────────────────────────────────────────────────

def tai32_now() -> int:
    """Current time as Time32: TAI seconds since 2004-01-01 00:00:00 UTC."""
    epoch = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)
    utc_now = datetime.datetime.now(tz=datetime.timezone.utc)
    return int((utc_now - epoch).total_seconds()) + 37   # +37 TAI–UTC leap seconds (current as of 2017-01-01; update when next leap second is announced)


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
    """Load a P-256 signing key from a PEM file or a raw 32-byte scalar file.

    Raw format: exactly 32 bytes, big-endian integer (e.g. certchain/s from
    an SCMS certificate store).  Any other size is treated as PEM.
    """
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) == 32:
        scalar = int.from_bytes(data, 'big')
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


# ── MBR building (SaeJ3287Mbr from input BSM) ─────────────────────────────────

def enc_three_d_location(lat: int, lon: int, elev: int) -> bytes:
    """ThreeDLocation OER encoding.

    NinetyDegreeInt  (lat):  { 4, 0 } → signed 32-bit big-endian (no offset).
    OneEightyDegreeInt (lon): { 4, 0 } → signed 32-bit big-endian (no offset).
    Elevation (elev): Uint16 { 2, 1 } → unsigned 16-bit big-endian.
    """
    return struct.pack('>i', lat) + struct.pack('>i', lon) + struct.pack('>H', elev)


def enc_mb_single_obs_long_acc(obs_id: int) -> bytes:
    """MbSingleObservation-BsmLongAcc { obsId Uint8, obs ANY }.
    obs=NULL is encoded as an empty open type (length 0).
    No preamble (first_extension=-1, no optionals).
    """
    return enc_uint8(obs_id) + enc_open_type(b'')


def enc_obs_by_target_bsm(tgt_id: int, obs_bytes_list: list) -> bytes:
    """ObservationsByTarget-Bsm { tgtId Uint8, observations SEQUENCE OF ANY }.
    Each observation is wrapped as an open type.
    No preamble (first_extension=-1, no optionals).
    """
    items = b''.join(enc_open_type(o) for o in obs_bytes_list)
    return enc_uint8(tgt_id) + enc_quantity(len(obs_bytes_list)) + items


def enc_v2x_pdu_stream(pdu_type: int, pdu_bytes_list: list,
                       subject_idx: int) -> bytes:
    """V2xPduStream { type, v2xPdus SIZE(1..255) OF ANY, certificate OPTIONAL,
    subjectPduIndex, ... }.

    Preamble bits: bit7=extensions_present(0), bit6=certificate_present(0) → 0x00.
    asn1c SET_OF_encode_oer ignores the SIZE constraint and always uses the
    variable-length quantity field (oer_put_quantity), so enc_quantity() is correct.
    Each PDU is wrapped as an open type.
    """
    items = b''.join(enc_open_type(p) for p in pdu_bytes_list)
    return (
        b'\x00'                                       # preamble
        + enc_uint8(pdu_type)                         # type
        + enc_quantity(len(pdu_bytes_list)) + items   # v2xPdus
        # certificate: absent → omitted
        + enc_uint8(subject_idx)                      # subjectPduIndex
    )


def enc_asr_bsm(obs_by_tgt_list: list, v2x_stream_list: list) -> bytes:
    """AsrBsm { observations, v2xPduEvidence, nonV2xPduEvidence=[] }.
    No preamble (first_extension=-1, no optionals).
    """
    observations = enc_quantity(len(obs_by_tgt_list)) + b''.join(obs_by_tgt_list)
    v2x_evidence = enc_quantity(len(v2x_stream_list)) + b''.join(v2x_stream_list)
    non_v2x      = enc_quantity(0)          # empty NonV2xPduEvidenceItemSequence-Bsm
    return observations + v2x_evidence + non_v2x


def enc_aid_specific_report(aid: int, content_bytes: bytes) -> bytes:
    """AidSpecificReport { aid Psid, content ANY (open type) }.
    No preamble (first_extension=-1, no optionals).
    """
    return enc_psid(aid) + enc_open_type(content_bytes)


def enc_sae_j3287_mbr(gen_time: int, lat: int, lon: int, elev: int,
                       report_bytes: bytes) -> bytes:
    """EtsiTs103759Mbr (= SaeJ3287Mbr) { generationTime, observationLocation, report }.
    No preamble (first_extension=-1, no optionals).
    report_bytes: encoded AidSpecificReport.
    """
    return (
        enc_uint64(gen_time)                       # Time64: 8-byte unsigned big-endian
        + enc_three_d_location(lat, lon, elev)
        + report_bytes
    )


def _extract_bsm_gen_time(bsm_json: dict) -> int:
    """Extract generationTime from a decoded Ieee1609Dot2Data JER dict."""
    t = (bsm_json
         .get("content", {})
         .get("signedData", {})
         .get("tbsData", {})
         .get("headerInfo", {})
         .get("generationTime"))
    if t is None:
        raise ValueError("BSM headerInfo does not contain generationTime")
    return t


def build_mbr_from_bsm(bsm_bytes: bytes,
                        lat: int = 0, lon: int = 0, elev: int = 0) -> bytes:
    """Build a SaeJ3287Mbr (EtsiTs103759Mbr) from an Ieee1609Dot2Data BSM.

    Hard-codes a LongAcc-ValueTooLarge observation (tgtId=5, obsId=4, obs=NULL).
    Extracts generationTime from the BSM headerInfo.
    """
    bsm_json = decode_oer("Ieee1609Dot2Data", bsm_bytes)
    gen_time = _extract_bsm_gen_time(bsm_json)

    # LongAcc-ValueTooLarge: obsId=4, obs=NULL (empty open type)
    obs = enc_mb_single_obs_long_acc(4)

    # ObservationsByTarget-Bsm: tgtId=5 (c-BsmTgt-LongAccCommon)
    obs_by_tgt = enc_obs_by_target_bsm(5, [obs])

    # V2xPduStream: type=2 (c-ObsPdu-ieee1609Dot2Data), subjectPduIndex=0
    stream = enc_v2x_pdu_stream(2, [bsm_bytes], 0)

    # AsrBsm
    asr = enc_asr_bsm([obs_by_tgt], [stream])

    # AidSpecificReport: aid=32 (c-AsrBsm = BSM PSID)
    report = enc_aid_specific_report(32, asr)

    # SaeJ3287Mbr
    return enc_sae_j3287_mbr(gen_time, lat, lon, elev, report)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Build SaeJ3287Data COER variants (plaintext / signed / sTE)"
    )
    p.add_argument("--certs-dir",
                   help="SCMS organisation cert store directory (e.g. certs/e0c324c643aca860); "
                        "the currently valid rsu-*/downloadFiles/ cert is selected automatically; "
                        "omit to skip signed and sTE variants")
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
    mbr_bytes = build_mbr_from_bsm(bsm_bytes, lat=lat, lon=lon, elev=args.elev)
    print("Writing:", file=sys.stderr)

    # Plaintext: SaeJ3287MbrSec.plaintext = SaeJ3287Mbr (raw MBR bytes)
    write_file(
        os.path.join(args.out_dir, "out_plaintext.coer"),
        enc_sae_j3287_data(0, mbr_bytes),
    )

    if signing_key is None:
        print("  (skipping signed and sTE variants: no --certs-dir provided)",
              file=sys.stderr)
        return

    cert_bytes = cert_bytes_selected

    # Signed: SaeJ3287MbrSec.signed = Ieee1609Dot2Data { signedData }
    signed_1609 = build_signed_1609(mbr_bytes, signing_key, cert_bytes, args.psid)
    write_file(
        os.path.join(args.out_dir, "out_signed.coer"),
        enc_sae_j3287_data(1, signed_1609),
    )

    if recipient_pub is None:
        print("  (skipping sTE variant: no --recipient-pub provided)", file=sys.stderr)
        return

    # sTE: SaeJ3287MbrSec.sTE = Ieee1609Dot2Data { encryptedData } over the signed wrapper
    ste_1609 = build_encrypted_1609(signed_1609, recipient_pub)
    write_file(
        os.path.join(args.out_dir, "out_ste.coer"),
        enc_sae_j3287_data(2, ste_1609),
    )


if __name__ == "__main__":
    main()
