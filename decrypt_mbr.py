#!/usr/bin/env python3
"""
decrypt_mbr.py - Decrypt an sTE MBR via the ISS virtual device API.

Usage:
    python3 decrypt_mbr.py [file] --api-key <token> [--url <base_url>]

Arguments:
    file        COER file to decrypt (default: coer/out_ste.coer).
                Accepts either:
                  - SaeJ3287Data (first byte 0x01) — inner content.sTE
                    Ieee1609Dot2Data is extracted automatically.
                  - Bare Ieee1609Dot2Data with encryptedData — posted directly.

    --api-key   x-virtual-api-key token for the ISS virtual device.
                The virtual device must have been the encryption recipient
                (message encrypted via rekRecipInfo using the device's
                message_encryption key).

    --url       ISS DMS base URL (default: https://api.dm.preprod.v2x.isscms.com)

Note:
    POST /virtual-device/decrypt requires rekRecipInfo recipients.  Messages
    encrypted to a certificate (certRecipInfo, as produced by --recipient-cert)
    cannot be decrypted via this API — those require the recipient MA's private
    key (backend HSM).  To produce a rekRecipInfo-encrypted file suitable for
    this script use --encrypt-api-key in create_mbr.py.

Requires: requests  (pip install requests)
"""

import argparse
import base64
import json
import sys

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is not installed.  Run: pip install requests",
          file=sys.stderr)
    sys.exit(1)

from asn1c_lib import decode_oer, encode_jer

DEFAULT_URL  = "https://api.dm.preprod.v2x.isscms.com"
DECRYPT_PATH = "/api/v3/virtual-device/decrypt"


def extract_encrypted_bytes(raw: bytes) -> bytes:
    """Return raw Ieee1609Dot2Data bytes from either a SaeJ3287Data or
    a bare Ieee1609Dot2Data file.

    SaeJ3287Data starts with version byte 0x01.  In that case decode the
    outer wrapper and re-encode content.sTE as Ieee1609Dot2Data bytes.
    """
    if not raw:
        print("ERROR: input file is empty.", file=sys.stderr)
        sys.exit(1)
    if raw[0] == 0x01:
        outer   = decode_oer("SaeJ3287Data", raw)
        content = outer.get("content", {})
        if "sTE" not in content:
            print("ERROR: SaeJ3287Data.content does not contain an 'sTE' variant.",
                  file=sys.stderr)
            print(f"  content keys present: {list(content.keys())}", file=sys.stderr)
            if "signed" in content:
                print("  Hint: this looks like a signed (not encrypted) message — "
                      "use validate_mbr.py instead.", file=sys.stderr)
            sys.exit(1)
        return encode_jer("Ieee1609Dot2Data", content["sTE"])
    return raw


def print_decrypted_payload(b64: str) -> None:
    """Decode and display the decryptedData returned by the decrypt endpoint."""
    try:
        raw = base64.b64decode(b64)
    except Exception as exc:
        print(f"  (could not base64-decode decryptedData: {exc})")
        return

    print(f"  decryptedData: {len(raw)} bytes")

    # Try to decode as Ieee1609Dot2Data (signed inner payload)
    try:
        inner = decode_oer("Ieee1609Dot2Data", raw)
        print("  Decoded as Ieee1609Dot2Data:")
        print(json.dumps(inner, indent=4))
        return
    except Exception:
        pass

    # Try to decode as SaeJ3287Mbr
    try:
        mbr = decode_oer("SaeJ3287Mbr", raw)
        print("  Decoded as SaeJ3287Mbr:")
        print(json.dumps(mbr, indent=4))
        return
    except Exception:
        pass

    # Fall back to hex preview
    hex_preview = raw.hex().upper()
    if len(hex_preview) > 120:
        hex_preview = hex_preview[:120] + f"…({len(raw)} bytes)"
    print(f"  decryptedData (hex): {hex_preview}")


def main():
    p = argparse.ArgumentParser(
        description="Decrypt an sTE MBR via the ISS SCMS virtual device API"
    )
    p.add_argument("file", nargs="?", default="coer/out_ste.coer",
                   help="COER file to decrypt (default: coer/out_ste.coer)")
    p.add_argument("--api-key", required=True,
                   help="x-virtual-api-key token for the ISS virtual device")
    p.add_argument("--url", default=DEFAULT_URL,
                   help=f"ISS DMS base URL (default: {DEFAULT_URL})")
    args = p.parse_args()

    # ── Read and extract Ieee1609Dot2Data bytes ───────────────────────────────
    with open(args.file, "rb") as f:
        raw = f.read()
    print(f"Input:  {args.file} ({len(raw)} bytes)", file=sys.stderr)

    enc_bytes = extract_encrypted_bytes(raw)
    print(f"Sending Ieee1609Dot2Data: {len(enc_bytes)} bytes", file=sys.stderr)

    # ── POST to decrypt endpoint ──────────────────────────────────────────────
    url     = args.url.rstrip("/") + DECRYPT_PATH
    payload = {"message": base64.b64encode(enc_bytes).decode()}
    headers = {
        "Content-Type":      "application/json",
        "x-virtual-api-key": args.api_key,
    }

    print(f"POST {url}", file=sys.stderr)
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
    except requests.exceptions.RequestException as exc:
        print(f"ERROR: request failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Parse and display result ──────────────────────────────────────────────
    print(f"HTTP {resp.status_code}", file=sys.stderr)

    try:
        body = resp.json()
    except Exception:
        print(f"ERROR: non-JSON response body:\n{resp.text}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code == 200 and "decryptedData" in body:
        print("\nDecryption successful.")
        print_decrypted_payload(body["decryptedData"])
    else:
        print("\nDecryption FAILED.")
        print()

        if "rekRecipInfo" in str(body):
            print("  Hint: POST /virtual-device/decrypt requires rekRecipInfo recipients.")
            print("  Messages encrypted to a certificate (certRecipInfo, i.e. --recipient-cert)")
            print("  cannot be decrypted via this API — the MA holds the private key.")
            print("  To produce a rekRecipInfo-encrypted file, use --encrypt-api-key")
            print("  in create_mbr.py (encrypts to the virtual device's own key).")
            print()

        print("  Full response body:")
        print(json.dumps(body, indent=4))

        if resp.status_code != 200:
            sys.exit(1)


if __name__ == "__main__":
    main()
