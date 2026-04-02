#!/usr/bin/env python3
"""
encode_cert_json.py - Encode an IEEE 1609.2 ExplicitCertificate JSON to COER.

Reads a decoded-JER certificate JSON (e.g. from the SaeSol MA cert email) and
writes the canonical COER-encoded bytes to a .cert file.  Also prints the
values needed by create_mbr.py:

    HashedId8  (recipientId in PKRecipientInfo)
    P1         (SHA-256 of the cert — KDF2 P1 for ECIES)
    --recipient-pub  (compressed public key for --recipient-pub argument)

Supports the explicit-certificate subset present in MA certificates:
  issuer          sha256AndDigest | self | sha384AndDigest
  id              name | binaryId | none
  duration        any of the 7 Duration choices
  appPermissions  psid + optional opaque SSP
  encryptionKey   aes128Ccm + eciesNistP256 compressed
  verifyKeyIndicator  verificationKey ecdsaNistP256 compressed
  signature       ecdsaNistP256Signature

Usage:
    python3 encode_cert_json.py certs/ma_keys/saesol_ma_bublic_key.json
    python3 encode_cert_json.py certs/ma_keys/saesol_ma_bublic_key.json --out certs/ma_keys/saesol_ma_public_key.cert
"""

import argparse
import hashlib
import json
import struct
import sys

# ── OER/COER primitive encoders ───────────────────────────────────────────────

def enc_uint8(v: int) -> bytes:  return struct.pack('B', v)
def enc_uint16(v: int) -> bytes: return struct.pack('>H', v)
def enc_uint32(v: int) -> bytes: return struct.pack('>I', v)

def enc_length(n: int) -> bytes:
    """OER/COER length determinant."""
    if n < 0x80:    return bytes([n])
    if n < 0x100:   return bytes([0x81, n])
    if n < 0x10000: return bytes([0x82]) + struct.pack('>H', n)
    raise ValueError(f"length {n} too large")

def enc_octet_string(data: bytes) -> bytes:
    return enc_length(len(data)) + data

def enc_integer_var(v: int) -> bytes:
    """OER unconstrained non-negative INTEGER: length + minimum big-endian bytes."""
    if v == 0:
        return b'\x01\x00'
    n   = (v.bit_length() + 7) // 8
    raw = v.to_bytes(n, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return enc_length(len(raw)) + raw

def enc_choice(index: int, value: bytes) -> bytes:
    """OER CHOICE root alternative: tag = 0x80|index, no length wrapper."""
    if index > 62:
        raise ValueError(f"CHOICE index {index} out of range for root alternatives")
    return bytes([0x80 | index]) + value

def enc_enum(value: int) -> bytes:
    """OER ENUMERATED root value (0–127): single byte."""
    return bytes([value])

def enc_utf8string(s: str) -> bytes:
    data = s.encode('utf-8')
    return enc_length(len(data)) + data

# ── IEEE 1609.2 certificate field encoders ────────────────────────────────────

def enc_ecc_p256_curve_point(pt: dict) -> bytes:
    """
    EccP256CurvePoint CHOICE:
      x-only(0) | fill(1) | compressed-y-0(2) | compressed-y-1(3) | uncompressed(4)
    Input: {"x-only": hex} | {"compressed-y-0": hex} | {"compressed-y-1": hex}
    """
    if "x-only" in pt:
        return enc_choice(0, bytes.fromhex(pt["x-only"]))
    if "compressed-y-0" in pt:
        return enc_choice(2, bytes.fromhex(pt["compressed-y-0"]))
    if "compressed-y-1" in pt:
        return enc_choice(3, bytes.fromhex(pt["compressed-y-1"]))
    raise ValueError(f"Unsupported EccP256CurvePoint: {pt}")

def enc_duration(d: dict) -> bytes:
    """
    Duration CHOICE:
      microseconds(0) | milliseconds(1) | seconds(2) | minutes(3)
      | hours(4) | sixtyHours(5) | years(6)
    """
    for i, name in enumerate(
        ["microseconds", "milliseconds", "seconds", "minutes",
         "hours", "sixtyHours", "years"]
    ):
        if name in d:
            return enc_choice(i, enc_uint16(d[name]))
    raise ValueError(f"Unsupported Duration: {d}")

def enc_validity_period(vp: dict) -> bytes:
    """ValidityPeriod SEQUENCE { start Time32, duration Duration }."""
    return enc_uint32(vp["start"]) + enc_duration(vp["duration"])

def enc_ssp(ssp: dict) -> bytes:
    """ServiceSpecificPermissions CHOICE { opaque(0) | ... | bitmapSsp(1) }."""
    if "opaque" in ssp:
        return enc_choice(0, enc_octet_string(bytes.fromhex(ssp["opaque"])))
    raise ValueError(f"Unsupported ServiceSpecificPermissions: {ssp}")

def enc_psid_ssp(entry: dict) -> bytes:
    """
    PsidSsp SEQUENCE { psid Psid, ssp ServiceSpecificPermissions OPTIONAL }
    Presence bitmap (1 byte): bit7 = ssp present.
    """
    has_ssp = "ssp" in entry
    bitmap  = bytes([0x80 if has_ssp else 0x00])
    return bitmap + enc_integer_var(entry["psid"]) + (enc_ssp(entry["ssp"]) if has_ssp else b'')

def enc_seq_of_psid_ssp(perms: list) -> bytes:
    """SequenceOfPsidSsp = SEQUENCE OF PsidSsp (length-prefix then elements)."""
    return enc_integer_var(len(perms)) + b''.join(enc_psid_ssp(e) for e in perms)

def enc_public_enc_key(ek: dict) -> bytes:
    """
    PublicEncryptionKey SEQUENCE { supportedSymmAlg SymmAlgorithm, publicKey }.
    No presence bitmap (no OPTIONAL fields).
    BasePublicEncryptionKey CHOICE: eciesNistP256(0) | ...
    """
    SYMM_ALG = {"aes128Ccm": 0, "sm4Ccm": 1}
    alg = enc_enum(SYMM_ALG[ek["supportedSymmAlg"]])

    pk = ek["publicKey"]
    if "eciesNistP256" in pk:
        pt = enc_choice(0, enc_ecc_p256_curve_point(pk["eciesNistP256"]))
    else:
        raise ValueError(f"Unsupported BasePublicEncryptionKey: {pk}")
    return alg + pt

def enc_public_verif_key(vk: dict) -> bytes:
    """
    PublicVerificationKey CHOICE:
      ecdsaNistP256(0) | ecdsaBrainpoolP256r1(1) | ... | ecdsaNistP384(3) | ...
    """
    if "ecdsaNistP256" in vk:
        return enc_choice(0, enc_ecc_p256_curve_point(vk["ecdsaNistP256"]))
    if "ecdsaBrainpoolP256r1" in vk:
        return enc_choice(1, enc_ecc_p256_curve_point(vk["ecdsaBrainpoolP256r1"]))
    raise ValueError(f"Unsupported PublicVerificationKey: {vk}")

def enc_verify_key_indicator(vki: dict) -> bytes:
    """VerificationKeyIndicator CHOICE { verificationKey(0) | reconstructionValue(1) }."""
    if "verificationKey" in vki:
        return enc_choice(0, enc_public_verif_key(vki["verificationKey"]))
    if "reconstructionValue" in vki:
        return enc_choice(1, enc_ecc_p256_curve_point(vki["reconstructionValue"]))
    raise ValueError(f"Unsupported VerificationKeyIndicator: {vki}")

def enc_cert_id(cid: dict) -> bytes:
    """CertificateId CHOICE { linkageData(0) | name(1) | binaryId(2) | none(3) }."""
    if "name" in cid:
        return enc_choice(1, enc_utf8string(cid["name"]))
    if "none" in cid:
        return enc_choice(3, b'')
    if "binaryId" in cid:
        return enc_choice(2, enc_octet_string(bytes.fromhex(cid["binaryId"])))
    if "linkageData" in cid:
        raise NotImplementedError("linkageData CertificateId not supported")
    raise ValueError(f"Unsupported CertificateId: {cid}")

def enc_issuer_id(issuer: dict) -> bytes:
    """IssuerIdentifier CHOICE { sha256AndDigest(0) | self(1) | sha384AndDigest(2) }."""
    if "sha256AndDigest" in issuer:
        return enc_choice(0, bytes.fromhex(issuer["sha256AndDigest"]))
    if "self" in issuer:
        HASH_ALG = {"sha256": 0, "sha384": 1, "sm3": 2}
        return enc_choice(1, enc_enum(HASH_ALG[issuer["self"]]))
    if "sha384AndDigest" in issuer:
        return enc_choice(2, bytes.fromhex(issuer["sha384AndDigest"]))
    raise ValueError(f"Unsupported IssuerIdentifier: {issuer}")

def enc_ecdsa_p256_sig(sig: dict) -> bytes:
    """EcdsaP256Signature { rSig EccP256CurvePoint, sSig OCTET STRING(SIZE(32)) }."""
    r = enc_ecc_p256_curve_point(sig["rSig"])
    s = bytes.fromhex(sig["sSig"])
    if len(s) != 32:
        raise ValueError(f"sSig must be 32 bytes, got {len(s)}")
    return r + s

def enc_signature(sig: dict) -> bytes:
    """Signature CHOICE { ecdsaNistP256Signature(0) | ... }."""
    if "ecdsaNistP256Signature" in sig:
        return enc_choice(0, enc_ecdsa_p256_sig(sig["ecdsaNistP256Signature"]))
    raise ValueError(f"Unsupported Signature: {sig}")

def enc_tbs_cert(tbs: dict) -> bytes:
    """
    ToBeSignedCertificate SEQUENCE (extension marker present, 7 optional root fields).

    Presence bitmap (1 byte):
      bit7: extension additions present flag  (0 = none)
      bit6: region
      bit5: assuranceLevel
      bit4: appPermissions
      bit3: certIssuePermissions
      bit2: certRequestPermissions
      bit1: canRequestRollover
      bit0: encryptionKey
    """
    has_region      = "region"                in tbs
    has_assurance   = "assuranceLevel"         in tbs
    has_app_perms   = "appPermissions"         in tbs
    has_cert_issue  = "certIssuePermissions"   in tbs
    has_cert_req    = "certRequestPermissions" in tbs
    has_rollover    = "canRequestRollover"     in tbs
    has_enc_key     = "encryptionKey"          in tbs

    for unsupported, label in [
        (has_region,     "region"),
        (has_assurance,  "assuranceLevel"),
        (has_cert_issue, "certIssuePermissions"),
        (has_cert_req,   "certRequestPermissions"),
        (has_rollover,   "canRequestRollover"),
    ]:
        if unsupported:
            raise NotImplementedError(f"ToBeSignedCertificate.{label} not implemented")

    bitmap = (
        (int(has_region)     << 6) |
        (int(has_assurance)  << 5) |
        (int(has_app_perms)  << 4) |
        (int(has_cert_issue) << 3) |
        (int(has_cert_req)   << 2) |
        (int(has_rollover)   << 1) |
        int(has_enc_key)
        # bit7 (extension flag) = 0: no extension additions
    )

    body  = bytes([bitmap])
    body += enc_cert_id(tbs["id"])
    body += bytes.fromhex(tbs["cracaId"])   # HashedId3 — fixed 3 bytes
    body += enc_uint16(tbs["crlSeries"])
    body += enc_validity_period(tbs["validityPeriod"])
    if has_app_perms:
        body += enc_seq_of_psid_ssp(tbs["appPermissions"])
    if has_enc_key:
        body += enc_public_enc_key(tbs["encryptionKey"])
    body += enc_verify_key_indicator(tbs["verifyKeyIndicator"])
    return body

def enc_certificate(cert: dict) -> bytes:
    """
    CertificateBase SEQUENCE (no extension marker, 1 optional field: signature).

    Presence bitmap (1 byte):
      bit7: signature present
    """
    has_sig  = "signature" in cert
    CERT_TYPE = {"explicit": 0, "implicit": 1}

    body  = bytes([0x80 if has_sig else 0x00])   # presence bitmap
    body += enc_uint8(cert["version"])
    body += enc_enum(CERT_TYPE[cert["type"]])
    body += enc_issuer_id(cert["issuer"])
    body += enc_tbs_cert(cert["toBeSigned"])
    if has_sig:
        body += enc_signature(cert["signature"])
    return body

# ── Validation: re-parse and print key fields ─────────────────────────────────

def _verify(coer: bytes, original_json: dict) -> None:
    """
    Spot-check the COER output by confirming a few known field positions
    match expected values from the JSON.  Raises AssertionError on mismatch.
    """
    # CertificateBase: version at offset 1
    assert coer[1] == original_json["version"], \
        f"version mismatch: {coer[1]} != {original_json['version']}"

    # type at offset 2: 0=explicit, 1=implicit
    expected_type = 0 if original_json["type"] == "explicit" else 1
    assert coer[2] == expected_type, \
        f"type mismatch: {coer[2]} != {expected_type}"

    # If signature present, last 32 bytes should be sSig
    if "signature" in original_json:
        sig = original_json["signature"]
        if "ecdsaNistP256Signature" in sig:
            expected_s = bytes.fromhex(sig["ecdsaNistP256Signature"]["sSig"])
            assert coer[-32:] == expected_s, \
                f"sSig tail mismatch: {coer[-32:].hex()} != {expected_s.hex()}"

# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encode an IEEE 1609.2 explicit certificate JSON to COER"
    )
    parser.add_argument("input",  help="Input JSON file")
    parser.add_argument("--out",  help="Output .cert file (default: <input>.cert)")
    parser.add_argument("--hex",  action="store_true",
                        help="Also print the full COER hex to stdout")
    args = parser.parse_args()

    with open(args.input) as fh:
        cert_json = json.load(fh)

    coer = enc_certificate(cert_json)
    _verify(coer, cert_json)

    out_path = args.out or (args.input.rsplit('.', 1)[0] + '.cert')
    with open(out_path, 'wb') as fh:
        fh.write(coer)

    digest    = hashlib.sha256(coer).digest()
    hashed_id = digest[-8:].hex().upper()
    p1_hex    = digest.hex().upper()

    # Derive recipient pub key string for --recipient-pub
    enc_key = cert_json["toBeSigned"]["encryptionKey"]["publicKey"]
    if "eciesNistP256" in enc_key:
        pt = enc_key["eciesNistP256"]
        if "compressed-y-1" in pt:
            recip_pub = "03" + pt["compressed-y-1"]
        elif "compressed-y-0" in pt:
            recip_pub = "02" + pt["compressed-y-0"]
        else:
            recip_pub = "(uncompressed — not directly usable as --recipient-pub)"
    else:
        recip_pub = "(non-P256 key — not supported)"

    print(f"Output:           {out_path}  ({len(coer)} bytes)")
    print(f"HashedId8:        {hashed_id}  ← recipientId in PKRecipientInfo")
    print(f"P1 (SHA256 cert): {p1_hex}  ← KDF2 P1 for ECIES")
    print(f"--recipient-pub:  {recip_pub}")

    if args.hex:
        print(f"\nCOER hex:\n{coer.hex().upper()}")


if __name__ == "__main__":
    main()
