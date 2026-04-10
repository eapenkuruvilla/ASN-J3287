#!/usr/bin/env python3
"""
upload_mbr.py — Upload a SaeJ3287Data COER file to the Misbehavior Report
Upload Receiver (MUR) via the REST API defined in SAE J3287 section 6.

Usage:
    python3 upload_mbr.py --mbr <file.coer> --certs-dir <bundle-dir>
    python3 upload_mbr.py --mbr <file.coer> --mur-url https://ra.preprod.v2x.isscms.com

The script:
  1. Reads the COER file and auto-detects the content type (plaintext / signed /
     sTE) from the SaeJ3287MbrSec CHOICE tag at byte offset 1.
  2. Auto-discovers the MUR URL from trustedcerts/ra (IEEE 1609.2.1 §7.6.3.10)
     when --certs-dir is supplied.
  3. Probes common version prefixes to find the live upload endpoint.
  4. POSTs the raw COER bytes with Content-Type: application/octet-stream.

SAE J3287 §6 — upload service names:
    mbr-upload-plaintext   POST SaeJ3287Data { plaintext: SaeJ3287Mbr }
    mbr-upload-signed      POST SaeJ3287Data { signed: SaeJ3287Mbr-Signed }
    mbr-upload-STE         POST SaeJ3287Data { sTE: SaeJ3287Mbr-STE }

Standards reference:
    SAE J3287 (Jan 2024)   §6   Misbehavior report upload
    IEEE 1609.2.1-2022     §7.6.3.10  RA certificate id field
"""

import argparse
import os
import sys

import requests

# ---------------------------------------------------------------------------
# SaeJ3287Data COER layout
#
# SaeJ3287Data ::= SEQUENCE {     -- no optional fields, no extension marker
#   version  Uint8(1),            -- byte 0: 0x01
#   content  SaeJ3287MbrSec       -- byte 1: CHOICE tag (AUTOMATIC TAGS)
# }
#
# SaeJ3287MbrSec CHOICE tags (AUTOMATIC TAGS → context [0],[1],[2]):
#   0x80  [0] plaintext  SaeJ3287Mbr
#   0x81  [1] signed     SaeJ3287Mbr-Signed
#   0x82  [2] sTE        SaeJ3287Mbr-STE
# ---------------------------------------------------------------------------

_CHOICE_TAG_TO_SERVICE = {
    0x80: ("plaintext", "mbr-upload-plaintext"),
    0x81: ("signed",    "mbr-upload-signed"),
    0x82: ("sTE",       "mbr-upload-STE"),
}

_VERSION_PREFIXES = ["", "/v1", "/v2", "/v3", "/scms/v1", "/scms/v3", "/api/v3"]


def detect_content_type(mbr_bytes: bytes) -> tuple[str, str]:
    """Return (content_type_label, service_name) by inspecting the CHOICE tag.

    SaeJ3287Data is a SEQUENCE with no optional fields and no extension marker,
    so there is no preamble byte.  Layout: version(1) | content CHOICE tag(1) ...
    """
    if len(mbr_bytes) < 2:
        raise ValueError("File too short to be a SaeJ3287Data COER structure")

    version_byte = mbr_bytes[0]
    if version_byte != 0x01:
        raise ValueError(
            f"Unexpected version byte 0x{version_byte:02X} (expected 0x01); "
            "file may not be a SaeJ3287Data COER file")

    choice_tag = mbr_bytes[1]
    if choice_tag not in _CHOICE_TAG_TO_SERVICE:
        raise ValueError(
            f"Unknown SaeJ3287MbrSec CHOICE tag 0x{choice_tag:02X}; "
            "expected 0x80 (plaintext), 0x81 (signed), or 0x82 (sTE)")

    return _CHOICE_TAG_TO_SERVICE[choice_tag]


def mur_url_from_cert(certs_dir: str) -> str | None:
    """Return the MUR URL from the RA certificate in the bundle directory.

    Delegates to asn1c_lib.ra_url_from_bundle(); prints a message when not found.
    """
    from asn1c_lib import ra_url_from_bundle
    url = ra_url_from_bundle(certs_dir)
    if url is None:
        print(f"  trustedcerts/ra not found in {certs_dir}", file=sys.stderr)
    return url


def upload_mbr(mur_url: str, service: str, mbr_bytes: bytes,
               api_key: str | None) -> bool:
    """
    Probe version prefixes and POST mbr_bytes to the first responding endpoint.
    Returns True on success (2xx response), False otherwise.
    """
    headers = {"Content-Type": "application/octet-stream"}
    if api_key:
        headers["x-virtual-api-key"] = api_key

    base = mur_url.rstrip("/")
    for prefix in _VERSION_PREFIXES:
        url = f"{base}{prefix}/{service}"
        try:
            resp = requests.post(url, data=mbr_bytes, headers=headers, timeout=30)
            print(f"  POST {resp.url} → {resp.status_code}")
            if resp.status_code in (200, 201, 202, 204):
                if resp.content:
                    print(f"  Response body: {resp.content[:500]}")
                return True
            if resp.status_code == 404:
                continue
            # Any non-404 failure (400, 401, 403, 500 …) — report and stop probing
            print(f"  Response: {resp.text[:500]}")
            return False
        except requests.RequestException as exc:
            print(f"  {url} — {exc}")

    print("  All version prefixes exhausted without a successful response.")
    return False


def main():
    ap = argparse.ArgumentParser(
        description="Upload a SaeJ3287Data COER file to the MUR (SAE J3287 §6)"
    )
    ap.add_argument("--mbr", required=True,
                    help="SaeJ3287Data COER file to upload "
                         "(out_plaintext.coer / out_signed.coer / out_ste.coer)")
    ap.add_argument("--certs-dir", default=None,
                    help="SCMS bundle directory; MUR URL auto-discovered from "
                         "trustedcerts/ra (IEEE 1609.2.1 §7.6.3.10)")
    ap.add_argument("--mur-url", default=None,
                    help="MUR base URL override (e.g. https://ra.preprod.v2x.isscms.com)")
    ap.add_argument("--api-key", default=None,
                    help="x-virtual-api-key header value (try without first)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Detect content type and resolve URL but do not POST")
    args = ap.parse_args()

    if not args.certs_dir and not args.mur_url:
        ap.error("Supply --certs-dir or --mur-url")

    SEP = "─" * 70
    print(SEP)
    print("SAE J3287 MBR upload")
    print(SEP)

    # ---- Step 1: read and detect content type ----
    print(f"\n[1] Reading {args.mbr} ...")
    mbr_bytes = open(args.mbr, "rb").read()
    print(f"  {len(mbr_bytes)} bytes")

    try:
        content_label, service = detect_content_type(mbr_bytes)
    except ValueError as exc:
        print(f"  ERROR: {exc}")
        sys.exit(1)
    print(f"  Content type : {content_label}  (SaeJ3287MbrSec CHOICE tag "
          f"0x{mbr_bytes[1]:02X})")
    print(f"  Service      : {service}")

    # ---- Step 2: resolve MUR URL ----
    mur_url = args.mur_url
    if mur_url is None:
        print(f"\n[2] Auto-discovering MUR URL from "
              f"{args.certs_dir}/trustedcerts/ra ...")
        mur_url = mur_url_from_cert(args.certs_dir)
        if mur_url:
            print(f"  MUR URL: {mur_url}")
        else:
            print("  Could not read RA cert.  Supply --mur-url explicitly.")
            sys.exit(1)
    else:
        print(f"\n[2] Using supplied MUR URL: {mur_url}")

    if args.dry_run:
        print(f"\n[DRY RUN] Would POST {len(mbr_bytes)} bytes to "
              f"{mur_url}/<version>/{service}")
        print(SEP)
        return

    # ---- Step 3: upload ----
    print(f"\n[3] Uploading to {mur_url} ...")
    success = upload_mbr(mur_url, service, mbr_bytes, args.api_key)

    print(SEP)
    if success:
        print(f"  Upload succeeded  ({content_label})")
    else:
        print(f"  Upload FAILED  ({content_label})")
        sys.exit(1)
    print(SEP)


if __name__ == "__main__":
    main()
