#!/usr/bin/env python3
"""
decode_j2735.py - Decode a J2735 MessageFrame to JSON.

Supports two input forms:

  Hex string  — raw UPER-encoded J2735 MessageFrame bytes (spaces ignored).
                Used when the hex is copied directly from decode_mbr.py output.

  COER file   — Ieee1609Dot2Data COER file (e.g. files in coer/).
                Prints the IEEE 1609.2 wrapper (signer, signature, headerInfo)
                followed by the decoded J2735 MessageFrame.

  Directory   — decodes all COER files in the directory.

Usage:
    python3 decode_j2735.py <hex>              # UPER hex string (MessageFrame)
    python3 decode_j2735.py <file.coer>        # Ieee1609Dot2Data COER file
    python3 decode_j2735.py <directory>        # all COER files in directory

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

    import io, contextlib
    make_GLOBAL()
    texts = [
        open(os.path.join(SCHEMA_DIR, f), encoding="latin-1").read()
        for f in asn_files
    ]
    with contextlib.redirect_stdout(io.StringIO()):
        compile_text(texts)

    import importlib.util, tempfile
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        generate_modules(PycrateGenerator, destfile=tmp_path)
        spec = importlib.util.spec_from_file_location("_j2735_rt", tmp_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        os.unlink(tmp_path)

    return mod.MessageFrame.MessageFrame


def _find_signed_data(obj):
    """Return the signedData dict if present at the top level of Ieee1609Dot2Data."""
    # content: ('signedData', {...})  or  content: {'signedData': {...}}
    content = obj.get("content") if isinstance(obj, dict) else None
    if isinstance(content, (list, tuple)) and len(content) == 2:
        if content[0] == "signedData":
            return content[1]
    if isinstance(content, dict):
        return content.get("signedData")
    return None


def _extract_wrapper(decoded):
    """Return a dict with IEEE 1609.2 signing info suitable for display."""
    sd = _find_signed_data(decoded)
    if sd is None:
        return None
    wrapper = {}
    # headerInfo
    tbs = sd.get("tbsData") or {}
    header = tbs.get("headerInfo")
    if header:
        wrapper["headerInfo"] = header
    # signer
    signer = sd.get("signer")
    if signer is not None:
        wrapper["signer"] = signer
    # signature
    sig = sd.get("signature")
    if sig is not None:
        wrapper["signature"] = sig
    return wrapper


def find_unsecured_data(obj):
    """Recursively search a decoded dict/list for unsecuredData values."""
    results = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "unsecuredData" and isinstance(v, str):
                results.append(v)
            else:
                results.extend(find_unsecured_data(v))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(find_unsecured_data(item))
    return results


def decode_coer_file(path):
    """Decode a COER file.

    Returns (wrapper_dict_or_None, [uper_hex_string, ...]).
    wrapper_dict contains IEEE 1609.2 signing info when present.
    """
    from asn1c_lib import decode_oer
    data = open(path, "rb").read()
    try:
        decoded = decode_oer("Ieee1609Dot2Data", data)
    except Exception as e:
        raise ValueError(f"Could not decode {path} as Ieee1609Dot2Data: {e}")
    wrapper = _extract_wrapper(decoded)
    hex_list = find_unsecured_data(decoded)
    if not hex_list:
        raise ValueError(f"No unsecuredData field found in {path}")
    return wrapper, hex_list


def decode_uper(MessageFrame, hex_str, label=""):
    data = bytes.fromhex(hex_str.replace(" ", ""))
    try:
        MessageFrame.from_uper(data)
    except Exception as e:
        print(f"ERROR: UPER decode failed{' for ' + label if label else ''}: {e}",
              file=sys.stderr)
        return
    print(json.dumps(MessageFrame.get_val(), indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(
        description="Decode a J2735 MessageFrame from UPER hex or COER file"
    )
    parser.add_argument(
        "input",
        help="UPER hex string, path to a COER file, or path to a directory of COER files"
    )
    args = parser.parse_args()

    print("Loading J2735 schemas...", file=sys.stderr)
    MessageFrame = load_j2735()

    inp = args.input

    if os.path.isdir(inp):
        # Decode all files in directory
        files = sorted(
            os.path.join(inp, f) for f in os.listdir(inp)
            if os.path.isfile(os.path.join(inp, f))
        )
        if not files:
            print(f"No files found in {inp}", file=sys.stderr)
            sys.exit(1)
        for fpath in files:
            print(f"\n--- {fpath} ---", file=sys.stderr)
            try:
                wrapper, hex_list = decode_coer_file(fpath)
            except ValueError as e:
                print(f"  Skipping: {e}", file=sys.stderr)
                continue
            if wrapper:
                print(json.dumps({"ieee1609dot2": wrapper}, indent=2, default=str))
            for i, hex_str in enumerate(hex_list):
                label = f"{fpath}[{i}]" if len(hex_list) > 1 else fpath
                decode_uper(MessageFrame, hex_str, label)

    elif os.path.isfile(inp):
        # Single COER file
        try:
            wrapper, hex_list = decode_coer_file(inp)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        if wrapper:
            print(json.dumps({"ieee1609dot2": wrapper}, indent=2, default=str))
        for i, hex_str in enumerate(hex_list):
            label = f"{inp}[{i}]" if len(hex_list) > 1 else inp
            decode_uper(MessageFrame, hex_str, label)

    else:
        # Treat as raw hex string
        try:
            bytes.fromhex(inp.replace(" ", ""))
        except ValueError as e:
            print(f"ERROR: '{inp}' is not a file, directory, or valid hex string: {e}",
                  file=sys.stderr)
            sys.exit(1)
        decode_uper(MessageFrame, inp)


if __name__ == "__main__":
    main()
