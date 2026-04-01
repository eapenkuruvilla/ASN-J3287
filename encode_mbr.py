#!/usr/bin/env python3
"""
encode_mbr.py - Build SaeJ3287 messages encoded via asn1c (libdecode.so).

Public API:
    build_mbr_from_bsm(bsm_bytes, lat, lon, elev) -> bytes  SaeJ3287Mbr COER
    build_signed_1609(mbr_bytes, signing_key, cert_bytes, psid) -> bytes
    build_encrypted_1609(signed_1609_bytes, recipient_pub_uncompressed) -> bytes

All structural encoding is delegated to encode_jer() / decode_oer() which call
the asn1c-generated codec in lib/libdecode.so.
"""

import hashlib
import hmac as _hmac
import secrets
import struct

from asn1c_lib import decode_oer, encode_jer

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


# ── IEEE 1609.2 crypto helpers ────────────────────────────────────────────────

def _sign_digest(signing_key, digest32: bytes) -> tuple:
    """ECDSA P-256 sign a pre-computed 32-byte digest. Returns (r, s)."""
    try:
        prehashed = Prehashed(hashes.SHA256())
    except TypeError:
        prehashed = Prehashed()
    sig_der = signing_key.sign(digest32, ec.ECDSA(prehashed))
    return decode_dss_signature(sig_der)


def _1609_data_signing_hash(cert_bytes: bytes, tbs_bytes: bytes) -> bytes:
    """IEEE 1609.2 data signing hash (§5.3.1.2.2).
    = SHA-256( SHA-256(tbsData) || SHA-256(cert) )
    """
    tbs_hash  = hashlib.sha256(tbs_bytes).digest()
    cert_hash = hashlib.sha256(cert_bytes).digest()
    return hashlib.sha256(tbs_hash + cert_hash).digest()


def _x963_kdf(z: bytes, length: int, p1: bytes = b'') -> bytes:
    """ANSI X9.63 KDF2 with SHA-256 (IEEE 1609.2 §5.3.5.1).
    Hash( Z || counter || P1 ).
    P1 = SHA-256(COER(recipient_cert)) for certRecipInfo.
    """
    out, counter = b'', 1
    while len(out) < length:
        out += hashlib.sha256(z + struct.pack('>I', counter) + p1).digest()
        counter += 1
    return out[:length]


# ── MBR building ──────────────────────────────────────────────────────────────

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
    """Build a SaeJ3287Mbr from an Ieee1609Dot2Data BSM.

    Hard-codes a LongAcc-ValueTooLarge observation (tgtId=5, obsId=4, obs=NULL).
    Extracts generationTime from the BSM headerInfo.
    Encoding is schema-validated via libdecode.so (encode_jer).
    """
    bsm_json = decode_oer("Ieee1609Dot2Data", bsm_bytes)
    gen_time = _extract_bsm_gen_time(bsm_json)

    obs_coer = encode_jer("MbSingleObservation_BsmLongAcc", {"obsId": 4, "obs": ""})

    return encode_jer("SaeJ3287Mbr", {
        "generationTime": gen_time,
        "observationLocation": {
            "latitude":  lat,
            "longitude": lon,
            "elevation": elev,
        },
        "report": {
            "aid": 32,
            "content": {
                "observations": [
                    {
                        "tgtId": 5,
                        "observations": [obs_coer.hex().upper()],
                    }
                ],
                "v2xPduEvidence": [
                    {
                        "type": 2,
                        "v2xPdus": [bsm_bytes.hex().upper()],
                        "subjectPduIndex": 0,
                    }
                ],
                "nonV2xPduEvidence": [],
            },
        },
    })


# ── 1609.2 signing ────────────────────────────────────────────────────────────

def build_signed_1609(mbr_bytes: bytes, signing_key,
                      cert_bytes: bytes, psid: int = 38) -> bytes:
    """Build Ieee1609Dot2Data { signedData } over mbr_bytes.

    Two-pass: encode ToBeSignedData first (COER bytes for signing hash),
    then encode the full Ieee1609Dot2Data with the computed signature.
    """
    tbs_dict = {
        "payload": {
            "data": {
                "protocolVersion": 3,
                "content": {"unsecuredData": mbr_bytes.hex().upper()},
            }
        },
        "headerInfo": {"psid": psid},
    }

    tbs_coer = encode_jer("ToBeSignedData", tbs_dict)
    digest   = _1609_data_signing_hash(cert_bytes, tbs_coer)
    r, s     = _sign_digest(signing_key, digest)

    cert_dict = decode_oer("Certificate", cert_bytes)

    return encode_jer("Ieee1609Dot2Data", {
        "protocolVersion": 3,
        "content": {
            "signedData": {
                "hashId": "sha256",
                "tbsData": tbs_dict,
                "signer": {"certificate": [cert_dict]},
                "signature": {
                    "ecdsaNistP256Signature": {
                        "rSig": {"x-only": r.to_bytes(32, "big").hex().upper()},
                        "sSig": s.to_bytes(32, "big").hex().upper(),
                    }
                },
            }
        },
    })


# ── ECIES-P256 + AES-128-CCM encryption ──────────────────────────────────────

def build_encrypted_1609(signed_1609_bytes: bytes,
                          recipient_pub_uncompressed: bytes) -> bytes:
    """Build Ieee1609Dot2Data { encryptedData } wrapping signed_1609_bytes.

    IEEE 1609.2 §5.3.5 ECIES-P256:
      1. AES-128-CCM encrypt the payload with a random CEK and nonce.
      2. Generate ephemeral P-256 key; ECDH → shared secret Z.
      3. KDF2(Z) → K_enc (16 bytes) || K_mac (32 bytes).
      4. c = K_enc ⊕ CEK  (encrypted CEK).
      5. t = HMAC-SHA256(K_mac, c)[0:16]  (MAC over c only, per §5.3.5.1).
    """
    cek   = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ct_with_tag = AESCCM(cek, tag_length=16).encrypt(nonce, signed_1609_bytes, None)

    eph_key   = ec.generate_private_key(ec.SECP256R1(), default_backend())
    eph_pub   = eph_key.public_key()
    recip_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), recipient_pub_uncompressed
    )
    Z = eph_key.exchange(ECDH(), recip_pub)

    K            = _x963_kdf(Z, 48)
    K_enc, K_mac = K[:16], K[16:48]
    c = bytes(a ^ b for a, b in zip(cek, K_enc))
    t = _hmac.new(K_mac, c, hashlib.sha256).digest()[:16]

    eph_raw = eph_pub.public_bytes(serialization.Encoding.X962,
                                    serialization.PublicFormat.CompressedPoint)
    v_dict = ({"compressed-y-0": eph_raw[1:].hex().upper()} if eph_raw[0] == 0x02
              else {"compressed-y-1": eph_raw[1:].hex().upper()})

    # recipientId = SHA-256(COER(MA cert))[-8:]; placeholder zeros until cert integrated
    recip_id = bytes(8)

    return encode_jer("Ieee1609Dot2Data", {
        "protocolVersion": 3,
        "content": {
            "encryptedData": {
                "recipients": [
                    {
                        "certRecipInfo": {
                            "recipientId": recip_id.hex().upper(),
                            "encKey": {
                                "eciesNistP256": {
                                    "v": v_dict,
                                    "c": c.hex().upper(),
                                    "t": t.hex().upper(),
                                }
                            },
                        }
                    }
                ],
                "ciphertext": {
                    "aes128ccm": {
                        "nonce":         nonce.hex().upper(),
                        "ccmCiphertext": ct_with_tag.hex().upper(),
                    }
                },
            }
        },
    })
