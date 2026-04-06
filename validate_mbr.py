#!/usr/bin/env python3
"""
validate_mbr.py - Validate a signed MBR against the ISS SCMS virtual device API.

Usage:
    python3 validate_mbr.py [file] --api-key <token> [--url <base_url>]

Arguments:
    file        COER file to validate (default: coer/out_signed.coer).
                Accepts either:
                  - SaeJ3287Data (first byte 0x01) — inner Ieee1609Dot2Data is
                    extracted automatically from content.signed before posting.
                  - Bare Ieee1609Dot2Data — posted directly.

    --api-key   x-virtual-api-key token for the ISS virtual device.
                The virtual device must have PSID 38 (MBR) in its enrollment.

    --url       ISS DMS base URL (default: https://api.dm.preprod.v2x.isscms.com)

The script posts the Ieee1609Dot2Data to POST /virtual-device/validate and prints
the validation status.  On failure it prints all available diagnostic information
to assist with troubleshooting.

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

DEFAULT_URL   = "https://api.dm.preprod.v2x.isscms.com"
VALIDATE_PATH = "/api/v3/virtual-device/validate"


def extract_ieee1609_bytes(raw: bytes) -> bytes:
    """Return raw Ieee1609Dot2Data bytes from either a SaeJ3287Data or
    a bare Ieee1609Dot2Data file.

    SaeJ3287Data starts with version byte 0x01.  In that case decode the
    outer wrapper and re-encode content.signed as Ieee1609Dot2Data bytes.
    """
    if not raw:
        print("ERROR: input file is empty.", file=sys.stderr)
        sys.exit(1)
    if raw[0] == 0x01:
        outer = decode_oer("SaeJ3287Data", raw)
        content = outer.get("content", {})
        if "signed" not in content:
            print("ERROR: SaeJ3287Data.content does not contain a 'signed' variant.",
                  file=sys.stderr)
            print(f"  content keys present: {list(content.keys())}", file=sys.stderr)
            sys.exit(1)
        return encode_jer("Ieee1609Dot2Data", content["signed"])
    return raw


def print_inner_payload(b64: str) -> None:
    """Decode and display the innerPayload returned by the validate endpoint."""
    try:
        raw = base64.b64decode(b64)
    except Exception as exc:
        print(f"  (could not base64-decode innerPayload: {exc})")
        return

    print(f"  innerPayload: {len(raw)} bytes")

    # Try to decode as SaeJ3287Mbr
    try:
        mbr = decode_oer("SaeJ3287Mbr", raw)
        print("  Decoded as SaeJ3287Mbr:")
        print(json.dumps(mbr, indent=4))
        return
    except Exception:
        pass

    # Fall back to hex
    hex_preview = raw.hex().upper()
    if len(hex_preview) > 120:
        hex_preview = hex_preview[:120] + f"…({len(raw)} bytes)"
    print(f"  innerPayload (hex): {hex_preview}")


def main():
    p = argparse.ArgumentParser(
        description="Validate a signed MBR via the ISS SCMS virtual device API"
    )
    p.add_argument("file", nargs="?", default="coer/out_signed.coer",
                   help="COER file to validate (default: coer/out_signed.coer)")
    p.add_argument("--api-key", required=True,
                   help="x-virtual-api-key token for the ISS virtual device")
    p.add_argument("--url", default=DEFAULT_URL,
                   help=f"ISS DMS base URL (default: {DEFAULT_URL})")
    p.add_argument("--dump-response", action="store_true",
                   help="Print the raw JSON response body from the ISS API")
    args = p.parse_args()

    # ── Read and extract Ieee1609Dot2Data bytes ───────────────────────────────
    with open(args.file, "rb") as f:
        raw = f.read()
    print(f"Input:  {args.file} ({len(raw)} bytes)", file=sys.stderr)

    ieee_bytes = extract_ieee1609_bytes(raw)
    print(f"Sending Ieee1609Dot2Data: {len(ieee_bytes)} bytes", file=sys.stderr)

    # ── POST to validate endpoint ─────────────────────────────────────────────
    url = args.url.rstrip("/") + VALIDATE_PATH
    payload = {
        "message":        base64.b64encode(ieee_bytes).decode(),
        "shouldValidate": True,
    }
    headers = {
        "Content-Type":    "application/json",
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

    status = body.get("status", "(no status field)")
    print(f"\nValidation status: {status}")

    if status in ("valid", "success"):
        print("  Signature is VALID — certificate chain recognized by ISS SCMS.")
        if args.dump_response:
            print("\n  Raw API response:")
            print(json.dumps(body, indent=4))
        if "innerPayload" in body:
            print_inner_payload(body["innerPayload"])

    else:
        print("  Signature validation FAILED.")
        print()

        # Status-specific guidance
        hints = {
            "failure":             "Cryptographic verification failed — signature does not match the certificate.",
            "not_signed":          "Message was not recognized as a signed Ieee1609Dot2Data.",
            "unrecognized_issuer": "The signer's certificate chain is not known to the ISS SCMS.",
            "unknown_cert":        "A digest signer type was used but the digest is unknown to ISS.",
        }
        if status in hints:
            print(f"  Hint: {hints[status]}")
            print()

        # Troubleshooting: dump full response
        print("  Full response body:")
        print(json.dumps(body, indent=4))

        # Troubleshooting: decode the message we sent to show what ISS received
        print()
        print("  Decoded Ieee1609Dot2Data sent to ISS:")
        try:
            decoded = decode_oer("Ieee1609Dot2Data", ieee_bytes)
            print(json.dumps(decoded, indent=4))
        except Exception as exc:
            print(f"    (decode failed: {exc})")

        sys.exit(1)


if __name__ == "__main__":
    main()
