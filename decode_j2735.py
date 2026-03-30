#!/usr/bin/env python3
"""
decode_j2735.py - Decode a J2735 MessageFrame from a UPER hex string.

Usage:
    python3 decode_j2735.py <hex>

The hex string is the raw UPER-encoded J2735 MessageFrame (e.g. the
unsecuredData field from decode_mbr.py output).  Spaces are ignored.

Requires: pycrate  (pip install pycrate)
          asn/J2735ASN_202409/  directory of J2735 ASN.1 schema files
"""

import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(SCRIPT_DIR, "asn", "J2735ASN_202409")


def load_j2735():
    try:
        from pycrate_asn1c.asnproc import (
            compile_text, generate_modules, PycrateGenerator, make_GLOBAL,
        )
        import pycrate_asn1rt.asnobj as _ao
    except ImportError:
        print("ERROR: pycrate not installed. Run: pip install pycrate", file=sys.stderr)
        sys.exit(1)

    asn_files = sorted(f for f in os.listdir(SCHEMA_DIR) if f.endswith(".asn"))
    if not asn_files:
        print(f"ERROR: no .asn files found in {SCHEMA_DIR}", file=sys.stderr)
        sys.exit(1)

    # Suppress constraint violations — input may intentionally violate constraints
    _ao.ASN1Obj._safechk_bnd = lambda self, val: None

    import pycrate_asn1c.asnproc as _asnproc
    _asnproc.asnlog = lambda msg: None

    make_GLOBAL()
    texts = [
        open(os.path.join(SCHEMA_DIR, f), encoding="latin-1").read()
        for f in asn_files
    ]
    compile_text(texts)

    # Generate a pycrate_asn1rt Python module to a temp file and import it.
    # compile_text() produces compiler-level objects; only the generated module
    # has the runtime encoding/decoding methods (from_uper, get_val, etc.).
    import importlib.util, tempfile
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        tmp_path = tmp.name
    generate_modules(PycrateGenerator, destfile=tmp_path)

    spec = importlib.util.spec_from_file_location("_j2735_rt", tmp_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    os.unlink(tmp_path)

    return mod.MessageFrame.MessageFrame


def main():
    parser = argparse.ArgumentParser(
        description="Decode a J2735 MessageFrame from UPER hex"
    )
    parser.add_argument("hex", help="UPER hex string (spaces ignored)")
    args = parser.parse_args()

    hex_str = args.hex.replace(" ", "")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError as e:
        print(f"ERROR: invalid hex string: {e}", file=sys.stderr)
        sys.exit(1)

    print("Loading J2735 schemas...", file=sys.stderr)
    MessageFrame = load_j2735()

    try:
        MessageFrame.from_uper(data)
    except Exception as e:
        print(f"ERROR: UPER decode failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(MessageFrame.get_val(), indent=2, default=str))


if __name__ == "__main__":
    main()
