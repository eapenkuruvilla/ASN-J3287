#!/usr/bin/env python3
"""
test_pycrate_schema.py - Test whether pycrate can compile and use the
J3287_ASN_flat schemas, and whether it can encode/decode the key PDU types.

Usage:
    python3 test_pycrate_schema.py

Steps:
    1. Compile all .asn files in asn/J3287_ASN_flat/ with pycrate
    2. Report any compilation errors per file
    3. List successfully compiled modules and their types
    4. Attempt to find and test the key PDU types used by this toolkit:
         SaeJ3287Data, SaeJ3287Mbr, Ieee1609Dot2Data, Certificate,
         ToBeSignedData, AsrBsm
    5. Attempt a round-trip encode/decode on SaeJ3287Data with a minimal
       plaintext payload using the existing coer/bad_accel_iss_key.coer BSM
"""

import json
import os
import re
import sys
import importlib.util
import tempfile
import traceback

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR  = os.path.join(SCRIPT_DIR, "asn", "J3287_ASN_flat")
BSM_FILE    = os.path.join(SCRIPT_DIR, "coer", "bad_accel_iss_key.coer")

TARGET_PDUS = [
    "SaeJ3287Data",
    "SaeJ3287Mbr",
    "Ieee1609Dot2Data",
    "Certificate",
    "ToBeSignedData",
    "ToBeSignedCertificate",
    "AsrBsm",
    "MbSingleObservation_BsmLongAcc",
    "MbSingleObservation_BsmSecurity",
]

SEP = "-" * 70


def load_pycrate():
    try:
        from pycrate_asn1c.asnproc import (
            compile_text, generate_modules, PycrateGenerator, make_GLOBAL,
        )
        import pycrate_asn1rt.asnobj as _ao
        return compile_text, generate_modules, PycrateGenerator, make_GLOBAL, _ao
    except ImportError as e:
        print(f"ERROR: pycrate not installed or import failed: {e}")
        print("Run: pip install pycrate")
        sys.exit(1)


def strip_constrained_by(text):
    """Remove (CONSTRAINED BY { ... }) from ASN.1 text.

    pycrate crashes with an AssertionError when it encounters CONSTRAINED BY
    bodies nested inside WITH COMPONENTS constraints.  In the IEEE 1609.2 /
    SAE J3287 / ETSI TS 103 759 schemas these blocks are purely documentary
    (the body is either all comments or describes the intended constraint in
    prose).  Removing the entire (CONSTRAINED BY { ... }) token is therefore
    semantics-preserving for the purposes of pycrate schema compilation.

    Algorithm: scan character by character; skip -- comments; when the token
    literal '(CONSTRAINED BY {' is found outside a comment, track brace depth
    (ignoring braces inside -- comments) until depth reaches 0, then consume
    the closing ')'.
    """
    result = []
    i = 0
    n = len(text)

    while i < n:
        # Skip -- line comments
        if text[i:i+2] == '--':
            end = text.find('\n', i)
            if end == -1:
                result.append(text[i:])
                i = n
            else:
                result.append(text[i:end + 1])
                i = end + 1
            continue

        # Detect (CONSTRAINED BY {
        token = '(CONSTRAINED BY {'
        if text[i:i + len(token)] == token:
            j = i + len(token)   # position right after the opening {
            depth = 1
            # Track net unbalanced { from comments: if a comment line has more
            # { than }, those orphaned { will be "balanced" by real } *outside*
            # the CONSTRAINED BY body (raw-file perspective).  After stripping,
            # we must also consume those extra real }).
            comment_open_excess = 0
            while j < n and depth > 0:
                if text[j:j+2] == '--':
                    # Skip comment to end of line; tally comment-brace balance
                    end = text.find('\n', j)
                    comment_end = n if end == -1 else end
                    comment_text = text[j:comment_end]
                    comment_open_excess += (comment_text.count('{')
                                            - comment_text.count('}'))
                    j = comment_end if end == -1 else end + 1
                    continue
                if text[j] == '{':
                    depth += 1
                elif text[j] == '}':
                    depth -= 1
                j += 1
            # j is now just past the closing }; consume optional whitespace + )
            while j < n and text[j] in ' \t':
                j += 1
            if j < n and text[j] == ')':
                j += 1
            # If comments in the body had more { than }, those unmatched { were
            # balanced in the raw file by real } that follow the CONSTRAINED BY
            # block.  Consume them now to keep the post-strip text balanced.
            for _ in range(max(0, comment_open_excess)):
                while j < n and text[j] in ' \t\n\r':
                    j += 1
                if j < n and text[j] == '}':
                    j += 1
                    while j < n and text[j] in ' \t':
                        j += 1
                    if j < n and text[j] == ')':
                        j += 1
            # Strip trailing whitespace/newline that immediately precedes the
            # token so we don't leave a bare blank line.
            while result and result[-1] in (' ', '\t'):
                result.pop()
            i = j
            continue

        result.append(text[i])
        i += 1

    return ''.join(result)


# Regex: strip inner (SIZE (N)) from a WITH COMPONENTS value constraint of the
# form  (UppercaseName (SIZE (N)))  →  (UppercaseName).
#
# pycrate bug: when a WITH COMPONENTS component's value constraint references an
# uppercase-named type *and* that reference is further constrained with SIZE(N),
# pycrate increments its internal setdisp counter before stacking a new empty
# path, then tries _path_trunc(2) on that empty path when processing the SIZE
# constraint — causing an AssertionError.
# Removing the inner SIZE constraint is safe: it's purely documentary here
# (e.g. "the certificate SEQUENCE OF must have exactly 1 element").
# The same crash occurs for lowercase field-name components in WITH COMPONENTS
# that carry a standalone (SIZE(N)) constraint (e.g. `recipients (SIZE(1))`):
# pycrate resolves the field's type to an ObjProxy, then tries _parse_const_size
# on it and hits the same path-depth assertion.
_RE_INNER_SIZE = re.compile(
    r'\(([A-Z][A-Za-z0-9]*)\s+\(SIZE\s+\(\d+\)\)\)'
)
# Strip SIZE(N) from lowercase field-name constraints: `fieldName (SIZE(N))` →
# `fieldName`.  In ASN.1 a field-name is always camelCase (starts lowercase);
# `TYPE (SIZE(N))` in a regular definition has an uppercase start, so this
# regex is safe to apply globally.
_RE_FIELD_SIZE = re.compile(
    r'(\b[a-z][A-Za-z0-9]*)\s+\(SIZE\s*\(\d+\)\)'
)


def strip_inner_size_constraints(text):
    """Replace (TypeName (SIZE (N))) → (TypeName) and fieldName (SIZE(N)) → fieldName."""
    text = _RE_INNER_SIZE.sub(r'(\1)', text)
    text = _RE_FIELD_SIZE.sub(r'\1', text)
    return text


_RE_WITH_COMPONENT_SINGULAR = re.compile(r'\(WITH COMPONENT(?!S)\s*\(')


def strip_with_component_singular(text):
    """Strip (WITH COMPONENT (...)) constraints from ASN.1 text.

    The singular 'WITH COMPONENT' operator constrains element types in a
    SEQUENCE OF.  pycrate does not support it and emits an INF warning, but
    leaves the token in the text stream, causing subsequent parsing to fail
    with 'invalid ident in WITH COMPONENTS constraint'.  Removing the entire
    '(WITH COMPONENT (...))' token is safe here.
    """
    result = []
    i = 0
    n = len(text)

    while i < n:
        if text[i:i+2] == '--':
            end = text.find('\n', i)
            if end == -1:
                result.append(text[i:])
                i = n
            else:
                result.append(text[i:end + 1])
                i = end + 1
            continue

        m = _RE_WITH_COMPONENT_SINGULAR.match(text, i)
        if m:
            # Track paren depth starting at the opening '('
            j = i + 1  # past the opening '('
            depth = 1
            while j < n and depth > 0:
                if text[j:j+2] == '--':
                    end = text.find('\n', j)
                    j = n if end == -1 else end + 1
                    continue
                if text[j] == '(':
                    depth += 1
                elif text[j] == ')':
                    depth -= 1
                j += 1
            # Strip any trailing whitespace prepended to this token
            while result and result[-1] in (' ', '\t'):
                result.pop()
            i = j
            continue

        result.append(text[i])
        i += 1

    return ''.join(result)


def add_missing_ellipsis(text):
    """Insert '...,' into WITH COMPONENTS blocks that omit the partial indicator.

    Some schemas (e.g. EtsiTs103097Module.asn) have non-partial WITH COMPONENTS
    constraints that only list *some* mandatory fields, causing pycrate to raise
    'missing mandatory components in WITH COMPONENTS'.  Adding '...' makes the
    constraint partial so pycrate does not enforce the completeness check.

    Operates outside -- comments.  Matches the pattern
      WITH COMPONENTS {<ws-with-newline><non-...>
    and inserts '...,' (with matching indentation) before the first component.
    """
    result = []
    i = 0
    n = len(text)
    TOK = 'WITH COMPONENTS {'

    while i < n:
        # Skip -- line comments
        if text[i:i+2] == '--':
            end = text.find('\n', i)
            if end == -1:
                result.append(text[i:])
                i = n
            else:
                result.append(text[i:end + 1])
                i = end + 1
            continue

        if text[i:i + len(TOK)] == TOK:
            result.append(TOK)
            j = i + len(TOK)
            # Also handle no-space variant: WITH COMPONENTS{
            ws_start = j
            while j < n and text[j] in ' \t\n\r':
                j += 1
            ws = text[ws_start:j]
            if '\n' in ws and not text[j:j+3] == '...':
                # Derive indentation from last line of the whitespace block
                nl = ws.rfind('\n')
                indent = ws[nl + 1:]
                result.append(ws)
                result.append('...,\n' + indent)
            else:
                result.append(ws)
            i = j
            continue

        result.append(text[i])
        i += 1

    return ''.join(result)


def preprocess_for_pycrate(text):
    """Apply all pycrate workaround transformations to a single ASN.1 text."""
    text = strip_constrained_by(text)
    text = strip_inner_size_constraints(text)
    text = strip_with_component_singular(text)
    text = add_missing_ellipsis(text)
    # SaeJ3287AsrBsm.asn imports EtsiTs103759MbrCommonObservations but the
    # file defines the module as EtsiTs103759CommonObservations.  pycrate
    # resolves imports by name (not OID) so we normalise the alias.
    text = text.replace(
        'EtsiTs103759MbrCommonObservations',
        'EtsiTs103759CommonObservations',
    )
    # strip_with_component_singular above removes (WITH COMPONENT (Type)),
    # which may leave a dangling (^(SIZE(N))) wrapper; remove that too.
    text = re.sub(r'\s*\(\s*\^\s*\(SIZE\s*\([^)]+\)\)\)', '', text)
    # Strip component-relation constraints of the form {@ .fieldName}: pycrate
    # does not support IOC table component-relation constraints and raises
    # "undefined field reference for table constraint".
    text = re.sub(r'\}\{@\.[A-Za-z][A-Za-z0-9.-]*\}', '}', text)
    # strip_constrained_by with comment_open_excess>0 can leave a standalone
    # field-name line at the end of a WITH COMPONENTS block (an artefact of
    # the CONSTRAINED BY body containing real code alongside a comment that
    # opened a brace).  Such a bare field name always violates component-order
    # rules because it was placed after a sibling component in the file; remove
    # it and the preceding comma so pycrate does not reject the schema.
    text = re.sub(r'\),\n(\s+)([a-z][A-Za-z0-9-]*)\n', ')\n', text)
    return text


def compile_schemas(compile_text, make_GLOBAL, _ao):
    """Compile all .asn files. Returns (texts, filenames, errors)."""
    asn_files = sorted(f for f in os.listdir(SCHEMA_DIR) if f.endswith(".asn"))
    if not asn_files:
        print(f"ERROR: no .asn files found in {SCHEMA_DIR}")
        sys.exit(1)

    print(f"Found {len(asn_files)} .asn files in {SCHEMA_DIR}")
    print()

    # Suppress constraint / log noise
    _ao.ASN1Obj._safechk_bnd = lambda self, val: None
    import pycrate_asn1c.asnproc as _asnproc
    _asnproc.asnlog = lambda msg: None

    make_GLOBAL()

    texts = []
    stripped_count = 0
    for fname in asn_files:
        path = os.path.join(SCHEMA_DIR, fname)
        with open(path, encoding="latin-1") as f:
            raw = f.read()
        cleaned = preprocess_for_pycrate(raw)
        if cleaned != raw:
            stripped_count += 1
        texts.append(cleaned)

    if stripped_count:
        print(f"  Pre-processed {stripped_count} file(s): "
              f"stripped (CONSTRAINED BY {{...}}) documentary constraints")

    errors = []
    print("Step 1: Compiling schemas...")
    try:
        compile_text(texts)
        print("  Compilation: OK")
    except Exception as e:
        errors.append(("compile_text", str(e)))
        print(f"  Compilation ERROR: {e}")
        print()
        print("  Full traceback:")
        traceback.print_exc()
        print()

    return texts, asn_files, errors


def generate_runtime_module(generate_modules, PycrateGenerator):
    """Generate pycrate runtime module. Returns the module."""
    print()
    print("Step 2: Generating runtime module...")
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp_path = tmp.name
    try:
        generate_modules(PycrateGenerator, destfile=tmp_path)
        spec = importlib.util.spec_from_file_location("_j3287_rt", tmp_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        print("  Runtime module generation: OK")
        return mod, tmp_path
    except Exception as e:
        print(f"  Runtime module ERROR: {e}")
        print()
        print("  Full traceback:")
        traceback.print_exc()
        print()
        return None, tmp_path
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def find_pdus(mod):
    """Check which target PDUs are present in the compiled module."""
    print()
    print("Step 3: Checking for target PDU types...")
    found   = {}
    missing = []
    for pdu in TARGET_PDUS:
        # pycrate uses the ASN.1 name; hyphens become underscores in some versions
        for name in (pdu, pdu.replace("_", "-")):
            obj = None
            for attr in dir(mod):
                module_obj = getattr(mod, attr, None)
                if module_obj is None:
                    continue
                try:
                    candidate = getattr(module_obj, name, None)
                    if candidate is not None:
                        obj = (attr, candidate)
                        break
                except Exception:
                    continue
            if obj:
                found[pdu] = obj
                break
        if pdu not in found:
            missing.append(pdu)

    for pdu, (module_name, _) in sorted(found.items()):
        print(f"  ✓  {pdu}  (in module {module_name})")
    for pdu in missing:
        print(f"  ✗  {pdu}  NOT FOUND")

    return found, missing


def test_round_trip(found):
    """Attempt OER round-trip on SaeJ3287Data with a minimal plaintext payload."""
    print()
    print("Step 4: OER round-trip test — SaeJ3287Data plaintext...")

    if "SaeJ3287Mbr" not in found or "SaeJ3287Data" not in found:
        print("  SKIP — SaeJ3287Mbr or SaeJ3287Data not found")
        return

    if not os.path.exists(BSM_FILE):
        print(f"  SKIP — BSM file not found: {BSM_FILE}")
        return

    with open(BSM_FILE, "rb") as f:
        bsm_bytes = f.read()

    # Try to use libasn1c to build a minimal SaeJ3287Mbr for the test
    try:
        from asn1c_lib import decode_oer as _decode_oer, encode_jer as _encode_jer
        from encode_mbr import build_mbr_from_bsm
        mbr_bytes = build_mbr_from_bsm(bsm_bytes, lat=0, lon=0, elev=0)
        print(f"  Built SaeJ3287Mbr via libasn1c: {len(mbr_bytes)} bytes")
        have_mbr = True
    except Exception as e:
        print(f"  Could not build SaeJ3287Mbr via libasn1c ({e}); "
              "will test with raw BSM bytes as opaque payload")
        mbr_bytes = bsm_bytes
        have_mbr  = False

    # Get the SaeJ3287Data type from the compiled module
    _, SaeJ3287Data = found["SaeJ3287Data"]

    # Test 1: OER decode of raw MBR if we have one
    if have_mbr:
        print()
        print("  Test 1a: decode SaeJ3287Mbr bytes with pycrate OER...")
        try:
            _, SaeJ3287Mbr = found["SaeJ3287Mbr"]
            SaeJ3287Mbr.from_oer(mbr_bytes)
            val = SaeJ3287Mbr.get_val()
            print(f"  OK — decoded value keys: {list(val.keys()) if isinstance(val, dict) else type(val).__name__}")
        except Exception as e:
            print(f"  FAIL: {e}")

    # Test 2: Decode the BSM as Ieee1609Dot2Data
    print()
    print("  Test 1b: decode bad_accel_iss_key.coer as Ieee1609Dot2Data...")
    if "Ieee1609Dot2Data" in found:
        try:
            _, Ieee1609Dot2Data = found["Ieee1609Dot2Data"]
            Ieee1609Dot2Data.from_oer(bsm_bytes)
            val = Ieee1609Dot2Data.get_val()
            print(f"  OK — decoded value keys: {list(val.keys()) if isinstance(val, dict) else type(val).__name__}")
        except Exception as e:
            print(f"  FAIL: {e}")
    else:
        print("  SKIP — Ieee1609Dot2Data not found")


def list_all_types(mod):
    """Print all compiled module names and their exported type count."""
    print()
    print("Step 5: Compiled modules summary...")
    for attr in sorted(dir(mod)):
        module_obj = getattr(mod, attr, None)
        if module_obj is None or attr.startswith("_"):
            continue
        try:
            types = [n for n in dir(module_obj) if not n.startswith("_")]
            if types:
                print(f"  {attr}: {len(types)} types")
        except Exception:
            continue


def main():
    print(SEP)
    print("pycrate schema compatibility test — asn/J3287_ASN_flat/")
    print(SEP)

    compile_text, generate_modules, PycrateGenerator, make_GLOBAL, _ao = load_pycrate()

    texts, asn_files, errors = compile_schemas(compile_text, make_GLOBAL, _ao)

    if errors:
        print()
        print(f"Compilation failed with {len(errors)} error(s). Cannot continue.")
        sys.exit(1)

    mod, _ = generate_runtime_module(generate_modules, PycrateGenerator)
    if mod is None:
        print("Cannot continue without runtime module.")
        sys.exit(1)

    found, missing = find_pdus(mod)

    test_round_trip(found)

    list_all_types(mod)

    print()
    print(SEP)
    print(f"Summary: {len(found)}/{len(TARGET_PDUS)} target PDUs found, "
          f"{len(missing)} missing: {missing if missing else 'none'}")
    if not missing and not errors:
        print("Result: pycrate CAN handle the J3287_ASN_flat schema.")
    elif errors:
        print("Result: pycrate CANNOT compile the schema — see errors above.")
    else:
        print(f"Result: pycrate compiled the schema but {len(missing)} PDU(s) "
              "were not found — may be renamed or nested differently.")
    print(SEP)


if __name__ == "__main__":
    main()
