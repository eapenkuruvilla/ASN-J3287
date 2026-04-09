#!/usr/bin/env python3
"""
check_crl.py — Download the IEEE 1609.2 CRL from the ISS RA and check whether
any pseudonym certificates are revoked.

Usage:
    python3 check_crl.py \
        --ra-url https://ra.proprod.v2x.isscms.com \
        --api-key <x-virtual-api-key>               \
        [--certs-dir certs/ISS/pseudonym/9b09e9e5e5c99a9e]
        [--craca-hex 93232614ee5e6f5b]              \
        [--crl-series 1]                             \
        [--save-crl crl.coer]

Standards reference:
  IEEE 1609.2-2022    §7.3  CRL data structures
  IEEE 1609.2.1-2022  §6.3.5.10  Individual CRL download API
                      §6.3.5.8   Composite CRL download API
"""

import argparse
import hashlib
import os
import struct
import sys

import requests

# ---------------------------------------------------------------------------
# Optional pycrate import for structured CRL display
# ---------------------------------------------------------------------------
_pycrate_mod = None

def _get_pycrate_mod():
    global _pycrate_mod
    if _pycrate_mod is not None:
        return _pycrate_mod
    try:
        from test_pycrate_schema import load_pycrate, compile_schemas, generate_runtime_module
        ct, gm, pg, mg, ao = load_pycrate()
        _, _, errors = compile_schemas(ct, mg, ao)
        if errors:
            return None
        mod, _ = generate_runtime_module(gm, pg)
        _pycrate_mod = mod
        return mod
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Certificate parsing helpers
# ---------------------------------------------------------------------------

def hash_cert_bytes(cert_bytes: bytes) -> bytes:
    """SHA-256 of raw cert bytes; returns full 32-byte digest."""
    return hashlib.sha256(cert_bytes).digest()


def hashed_id8(cert_bytes: bytes) -> bytes:
    """Low-order 8 bytes of SHA-256(cert) — HashedId8."""
    return hash_cert_bytes(cert_bytes)[-8:]


def hashed_id10(cert_bytes: bytes) -> bytes:
    """Low-order 10 bytes of SHA-256(cert) — HashedId10 (for hash-based CRL)."""
    return hash_cert_bytes(cert_bytes)[-10:]


def parse_cert(cert_bytes: bytes) -> dict | None:
    """
    Parse an IEEE 1609.2 Certificate using pycrate.
    Returns a dict with keys: iCert, linkage_value, group_jvalue,
    cracaId_hex (HashedId8 of CRACA found via trustedcerts), crl_series.
    Returns None if pycrate is unavailable.
    """
    mod = _get_pycrate_mod()
    if mod is None:
        return None
    try:
        Ieee1609Dot2 = mod.Ieee1609Dot2
        C = Ieee1609Dot2.Certificate
        C.from_oer(cert_bytes)
        v = C.get_val()
        tbs = v.get("toBeSigned", {})
        cert_id = tbs.get("id", [None, None])
        if cert_id[0] != "linkageData":
            return {"type": "hash_based", "craca_id3": tbs.get("cracaId", b""), "crl_series": tbs.get("crlSeries", 0)}
        ld = cert_id[1]
        i_cert = ld.get("iCert", 0)
        lv = ld.get("linkage-value", b"")
        if isinstance(lv, str):
            lv = lv.encode("latin-1")
        glv = ld.get("group-linkage-value", {})
        j_val = glv.get("jValue", b"")
        if isinstance(j_val, str):
            j_val = j_val.encode("latin-1")
        craca_raw = tbs.get("cracaId", b"")
        if isinstance(craca_raw, str):
            craca_raw = craca_raw.encode("latin-1")
        return {
            "type": "linkage",
            "i_cert": i_cert,
            "linkage_value": lv if isinstance(lv, bytes) else bytes(lv),
            "j_value": j_val if isinstance(j_val, bytes) else bytes(j_val),
            "craca_id3": craca_raw if isinstance(craca_raw, bytes) else bytes(craca_raw),
            "crl_series": tbs.get("crlSeries", 0),
        }
    except Exception as e:
        print(f"  [parse_cert] {e}")
        return None


# ---------------------------------------------------------------------------
# CRACA identification
# ---------------------------------------------------------------------------

def ra_url_from_cert(certs_dir: str) -> str | None:
    """
    IEEE 1609.2.1 §7.6.3.10: the RA certificate's toBeSigned.id field SHALL be
    of type name and SHALL equal the RA identifying URL.
    Extract it from trustedcerts/ra.
    """
    ra_cert_path = os.path.join(certs_dir, "trustedcerts", "ra")
    if not os.path.exists(ra_cert_path):
        return None
    mod = _get_pycrate_mod()
    if mod is None:
        return None
    try:
        Cert = mod.Ieee1609Dot2.Certificate
        data = open(ra_cert_path, "rb").read()
        Cert.from_oer(data)
        v = Cert.get_val()
        cert_id = v.get("toBeSigned", {}).get("id", [None, None])
        if isinstance(cert_id, (list, tuple)) and cert_id[0] == "name":
            hostname = cert_id[1]
            return f"https://{hostname}"
    except Exception as e:
        print(f"  [ra_url_from_cert] {e}")
    return None


def find_craca(certs_dir: str) -> tuple[str, bytes] | tuple[None, None]:
    """
    Search trustedcerts/ for the certificate whose SHA-256[-3:] matches the
    cracaId (HashedId3) of the first pseudonym certificate found.
    Returns (craca_hashed_id8_hex, craca_cert_bytes).
    """
    # Find first pseudonym cert
    download_dir = os.path.join(certs_dir, "download")
    first_cert_bytes = None
    for week in sorted(os.listdir(download_dir)):
        week_dir = os.path.join(download_dir, week)
        for f in sorted(os.listdir(week_dir)):
            if f.endswith(".cert"):
                first_cert_bytes = open(os.path.join(week_dir, f), "rb").read()
                break
        if first_cert_bytes:
            break
    if not first_cert_bytes:
        print("  No pseudonym cert found.")
        return None, None

    parsed = parse_cert(first_cert_bytes)
    if parsed is None:
        print("  pycrate unavailable — cannot parse cert to find cracaId.")
        return None, None

    craca_id3 = parsed["craca_id3"]
    print(f"  Cert cracaId (HashedId3): {craca_id3.hex()}")

    trusted_dir = os.path.join(certs_dir, "trustedcerts")
    for fname in os.listdir(trusted_dir):
        path = os.path.join(trusted_dir, fname)
        data = open(path, "rb").read()
        digest = hashlib.sha256(data).digest()
        hid3 = digest[-3:]
        hid8 = digest[-8:]
        if hid3 == craca_id3:
            print(f"  CRACA identified: trustedcerts/{fname}  HashedId8={hid8.hex()}")
            return hid8.hex(), data

    print(f"  WARNING: No trustedcert matched cracaId {craca_id3.hex()}")
    return None, None


# ---------------------------------------------------------------------------
# CRL download
# ---------------------------------------------------------------------------

def download_crl(ra_url: str, craca_hex: str, crl_series: int, api_key: str | None) -> bytes | None:
    """
    IEEE 1609.2.1 §6.3.5.10 — Individual CRL download.
    GET {ra_url}/{version}/crl?craca={cracaHex}&crlSeries={crlSeries}

    Tries several common version prefixes used by SCMS deployments.
    """
    version_prefixes = ["", "/v3", "/v2", "/v1", "/scms/v3", "/scms/v2", "/api/v3"]
    headers = {}
    if api_key:
        headers["x-virtual-api-key"] = api_key

    for prefix in version_prefixes:
        url = f"{ra_url.rstrip('/')}{prefix}/crl"
        params = {"craca": craca_hex, "crlSeries": str(crl_series)}
        try:
            r = requests.get(url, params=params, headers=headers, timeout=15)
            print(f"  GET {r.url} → {r.status_code}")
            if r.status_code == 200 and r.content:
                return r.content
        except requests.RequestException as e:
            print(f"  {url} — {e}")

    # Also try composite CRL (no cracaId needed, but needs ctlSeriesId)
    print("  Individual CRL endpoints failed.  Trying composite CRL (no ctlSeriesId — may fail)...")
    for prefix in version_prefixes:
        url = f"{ra_url.rstrip('/')}{prefix}/composite-crl"
        try:
            r = requests.get(url, headers=headers, timeout=15)
            print(f"  GET {r.url} → {r.status_code}")
            if r.status_code == 200 and r.content:
                return r.content
        except requests.RequestException as e:
            print(f"  {url} — {e}")

    return None


# ---------------------------------------------------------------------------
# CRL parsing
# ---------------------------------------------------------------------------

def parse_crl_pycrate(crl_bytes: bytes) -> dict | None:
    """Parse a SecuredCrl using pycrate. Returns raw value dict."""
    mod = _get_pycrate_mod()
    if mod is None:
        return None
    try:
        Ieee1609Dot2Crl = mod.Ieee1609Dot2Crl
        SC = Ieee1609Dot2Crl.SecuredCrl
        SC.from_oer(crl_bytes)
        return SC.get_val()
    except Exception as e:
        print(f"  [parse_crl] {e}")
        return None


def extract_crl_contents(crl_val: dict) -> dict | None:
    """
    Drill into SecuredCrl → signedData → tbsData → payload → data →
    content → unsecuredData to reach the raw CrlContents bytes,
    then re-parse as CrlContents.
    """
    try:
        content = crl_val["content"]           # Ieee1609Dot2Content
        sd = content[1] if isinstance(content, (list, tuple)) else content.get("signedData")
        if isinstance(sd, (list, tuple)):
            sd = sd[1]
        tbs = sd["tbsData"]
        payload = tbs["payload"]
        data = payload["data"]
        inner_content = data["content"]
        if isinstance(inner_content, (list, tuple)):
            # [choice_name, value]
            choice_name, choice_val = inner_content
            unsecured = choice_val
        else:
            unsecured = inner_content.get("unsecuredData")
        # unsecured should be raw bytes of CrlContents
        if isinstance(unsecured, (bytes, bytearray)):
            return _parse_crl_contents_bytes(bytes(unsecured))
    except Exception as e:
        print(f"  [extract_crl_contents] {e}")
    return None


def _parse_crl_contents_bytes(data: bytes) -> dict | None:
    mod = _get_pycrate_mod()
    if mod is None:
        return None
    try:
        Ieee1609Dot2CrlBaseTypes = mod.Ieee1609Dot2CrlBaseTypes
        CC = Ieee1609Dot2CrlBaseTypes.CrlContents
        CC.from_oer(data)
        return CC.get_val()
    except Exception as e:
        print(f"  [parse_crl_contents] {e}")
        return None


# ---------------------------------------------------------------------------
# Linkage value computation (IEEE 1609.2 Annex B)
# ---------------------------------------------------------------------------

def _aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = c.encryptor()
    return enc.update(plaintext) + enc.finalize()


def compute_linkage_value(seed1: bytes, seed2: bytes, i: int) -> bytes:
    """
    IEEE 1609.2 Annex B — compute linkage value from two 16-byte seeds and
    the i-period value.

    LV = AES-128-ECB(key=seed1, data=i_padded) XOR
         AES-128-ECB(key=seed2, data=i_padded)

    The resulting 16-byte XOR is truncated to 9 bytes (the linkage-value size).
    """
    i_padded = i.to_bytes(16, "big")
    prf1 = _aes_ecb(seed1, i_padded)
    prf2 = _aes_ecb(seed2, i_padded)
    xored = bytes(a ^ b for a, b in zip(prf1, prf2))
    return xored[:9]


# ---------------------------------------------------------------------------
# Revocation checking
# ---------------------------------------------------------------------------

def collect_certs(certs_dir: str) -> list[dict]:
    """
    Load and parse every .cert file under download/.
    Returns list of dicts with cert metadata + raw bytes.
    """
    download_dir = os.path.join(certs_dir, "download")
    certs = []
    for week in sorted(os.listdir(download_dir)):
        week_dir = os.path.join(download_dir, week)
        if not os.path.isdir(week_dir):
            continue
        for fname in sorted(os.listdir(week_dir)):
            if not fname.endswith(".cert"):
                continue
            path = os.path.join(week_dir, fname)
            raw = open(path, "rb").read()
            info = parse_cert(raw) or {}
            info["path"] = os.path.join(week, fname)
            info["raw"] = raw
            info["hid10"] = hashed_id10(raw).hex()
            certs.append(info)
    return certs


def check_hash_based(crl_contents: dict, certs: list[dict]) -> list[dict]:
    """Check hash-based CRL entries against cert HashedId10s."""
    revoked = []
    ts = crl_contents.get("typeSpecific", [None, None])
    choice_name = ts[0] if isinstance(ts, (list, tuple)) else None
    if choice_name not in ("fullHashCrl", "deltaHashCrl"):
        return revoked
    tbs = ts[1] if isinstance(ts, (list, tuple)) else ts
    entries = tbs.get("entries", [])
    hid10_set = {}
    for entry in entries:
        raw_id = entry.get("id", b"")
        if isinstance(raw_id, str):
            raw_id = raw_id.encode("latin-1")
        hid10_set[raw_id.hex()] = entry.get("expiry")
    for cert in certs:
        if cert.get("hid10") in hid10_set:
            revoked.append({**cert, "reason": "hash-based", "expiry": hid10_set[cert["hid10"]]})
    return revoked


def check_linkage_based(crl_contents: dict, certs: list[dict]) -> list[dict]:
    """
    Check linkage-based CRL entries against cert linkage values.
    Tries both individual and group revocations.
    """
    revoked = []
    ts = crl_contents.get("typeSpecific", [None, None])
    choice_name = ts[0] if isinstance(ts, (list, tuple)) else None
    if choice_name not in ("fullLinkedCrl", "deltaLinkedCrl",
                           "fullLinkedCrlWithAlg", "deltaLinkedCrlWithAlg"):
        return revoked

    tbs_crl = ts[1] if isinstance(ts, (list, tuple)) else ts
    i_rev = tbs_crl.get("iRev", 0)

    # Build a lookup of cert linkage values keyed by (i_cert, lv_hex)
    cert_lv_map = {}
    for cert in certs:
        lv = cert.get("linkage_value", b"")
        if isinstance(lv, str):
            lv = lv.encode("latin-1")
        key = (cert.get("i_cert", 0), lv.hex() if lv else "")
        cert_lv_map[key] = cert

    def _check_individual(seed1_bytes, seed2_bytes, i_rev_val):
        computed = compute_linkage_value(seed1_bytes, seed2_bytes, i_rev_val)
        key = (i_rev_val, computed.hex())
        if key in cert_lv_map:
            return cert_lv_map[key]
        return None

    def _bytes_of(val):
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        if isinstance(val, str):
            return val.encode("latin-1")
        return b""

    # Individual revocations
    individual = tbs_crl.get("individual") or []
    for jmax_group in individual:
        if isinstance(jmax_group, dict):
            jmax = jmax_group.get("jmax", 0)
            la_groups = jmax_group.get("contents", [])
        else:
            continue
        for la_group in la_groups:
            if not isinstance(la_group, dict):
                continue
            imax_groups = la_group.get("contents", [])
            for imax_group in imax_groups:
                if not isinstance(imax_group, dict):
                    continue
                imax = imax_group.get("iMax", 0)
                indiv_revocations = imax_group.get("contents", [])
                for j_idx, ir in enumerate(indiv_revocations):
                    if not isinstance(ir, dict):
                        continue
                    s1 = _bytes_of(ir.get("linkageSeed1", b""))
                    s2 = _bytes_of(ir.get("linkageSeed2", b""))
                    if len(s1) == 16 and len(s2) == 16:
                        hit = _check_individual(s1, s2, i_rev)
                        if hit:
                            revoked.append({**hit, "reason": "linkage-individual",
                                            "i_rev": i_rev, "j_idx": j_idx})

    # Group revocations
    groups = tbs_crl.get("groups") or []
    for group_entry in groups:
        if not isinstance(group_entry, dict):
            continue
        imax = group_entry.get("iMax", 0)
        s1 = _bytes_of(group_entry.get("linkageSeed1", b""))
        s2 = _bytes_of(group_entry.get("linkageSeed2", b""))
        if len(s1) == 16 and len(s2) == 16:
            hit = _check_individual(s1, s2, i_rev)
            if hit:
                revoked.append({**hit, "reason": "linkage-group", "i_rev": i_rev})

    return revoked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Check IEEE 1609.2 CRL for pseudonym cert revocation")
    ap.add_argument("--ra-url", default=None,
                    help="RA base URL. Auto-discovered from trustedcerts/ra cert if omitted "
                         "(IEEE 1609.2.1 §7.6.3.10).")
    ap.add_argument("--api-key", default=None, help="x-virtual-api-key header value")
    ap.add_argument("--certs-dir", required=True,
                    help="Pseudonym bundle directory (must contain download/ and trustedcerts/)")
    ap.add_argument("--craca-hex", default=None,
                    help="HashedId8 of CRACA cert (16 hex chars). "
                         "Auto-detected from trustedcerts/ if omitted.")
    ap.add_argument("--crl-series", type=int, default=None,
                    help="CRL series number. Auto-detected from cert if omitted.")
    ap.add_argument("--save-crl", default=None,
                    help="Save downloaded CRL bytes to this file.")
    ap.add_argument("--load-crl", default=None,
                    help="Load CRL from file instead of downloading (for offline use).")
    args = ap.parse_args()

    SEP = "─" * 70
    print(SEP)
    print("IEEE 1609.2 CRL revocation checker")
    print(SEP)

    # ---- Step 1: load pycrate ----
    print("\n[1] Loading pycrate schemas...")
    mod = _get_pycrate_mod()
    if mod is None:
        print("  pycrate unavailable — cert parsing and structured CRL display disabled.")
    else:
        print("  OK")

    # ---- Step 2: parse certs ----
    print(f"\n[2] Parsing pseudonym certs in {args.certs_dir}/download/ ...")
    certs = collect_certs(args.certs_dir)
    print(f"  Found {len(certs)} certificate(s)")
    if certs:
        sample = certs[0]
        print(f"  Sample: {sample['path']}")
        print(f"    type       : {sample.get('type', 'unknown')}")
        print(f"    i_cert     : {sample.get('i_cert', 'n/a')}  (0x{sample.get('i_cert',0):x})")
        print(f"    linkage_val: {sample.get('linkage_value', b'').hex()}")
        print(f"    hid10      : {sample.get('hid10', 'n/a')}")

    # ---- Step 2b: auto-discover RA URL from trustedcerts/ra ----
    ra_url = args.ra_url
    if ra_url is None:
        print(f"\n[2b] Auto-discovering RA URL from {args.certs_dir}/trustedcerts/ra ...")
        ra_url = ra_url_from_cert(args.certs_dir)
        if ra_url:
            print(f"  RA URL from certificate: {ra_url}")
        else:
            print("  Could not read RA cert. Supply --ra-url explicitly.")
            sys.exit(1)

    # ---- Step 3: determine cracaId / crlSeries ----
    craca_hex = args.craca_hex
    crl_series = args.crl_series

    if craca_hex is None or crl_series is None:
        print(f"\n[3] Identifying CRACA from {args.certs_dir}/trustedcerts/ ...")
        auto_craca_hex, _ = find_craca(args.certs_dir)
        if craca_hex is None:
            craca_hex = auto_craca_hex
        if crl_series is None and certs:
            crl_series = certs[0].get("crl_series", 1)
            print(f"  crlSeries from cert: {crl_series}")
    else:
        print(f"\n[3] Using supplied cracaId={craca_hex} crlSeries={crl_series}")

    if craca_hex is None:
        print("  ERROR: could not determine cracaId. Supply --craca-hex.")
        sys.exit(1)

    print(f"  cracaId (HashedId8) : {craca_hex}")
    print(f"  crlSeries           : {crl_series}")

    # ---- Step 4: get CRL bytes ----
    if args.load_crl:
        print(f"\n[4] Loading CRL from {args.load_crl} ...")
        crl_bytes = open(args.load_crl, "rb").read()
        print(f"  {len(crl_bytes)} bytes")
    else:
        print(f"\n[4] Downloading CRL from {ra_url} ...")
        crl_bytes = download_crl(ra_url, craca_hex, crl_series, args.api_key)
        if crl_bytes is None:
            print("  ERROR: CRL download failed. Check RA URL, api-key, cracaId, and crlSeries.")
            sys.exit(1)
        print(f"  Downloaded {len(crl_bytes)} bytes")

    if args.save_crl:
        open(args.save_crl, "wb").write(crl_bytes)
        print(f"  Saved to {args.save_crl}")

    # ---- Step 5: parse CRL ----
    print("\n[5] Parsing CRL ...")
    crl_val = parse_crl_pycrate(crl_bytes)
    if crl_val is None:
        print("  Could not parse CRL with pycrate.")
        print(f"  Raw (first 64 bytes): {crl_bytes[:64].hex()}")
        sys.exit(1)

    crl_contents = extract_crl_contents(crl_val)
    if crl_contents is None:
        print("  Could not extract CrlContents — showing raw SecuredCrl top level.")
        import json
        print(json.dumps(crl_val, indent=2, default=repr)[:2000])
        sys.exit(1)

    ts = crl_contents.get("typeSpecific", [None, None])
    crl_type = ts[0] if isinstance(ts, (list, tuple)) else "unknown"
    crl_serial = (ts[1] or {}).get("crlSerial", "n/a") if isinstance(ts, (list, tuple)) else "n/a"
    i_rev = (ts[1] or {}).get("iRev", "n/a") if isinstance(ts, (list, tuple)) else "n/a"

    print(f"  CRL type    : {crl_type}")
    print(f"  issueDate   : {crl_contents.get('issueDate')}")
    print(f"  nextCrl     : {crl_contents.get('nextCrl')}")
    if crl_type in ("fullHashCrl", "deltaHashCrl"):
        entries = (ts[1] or {}).get("entries", []) if isinstance(ts, (list, tuple)) else []
        print(f"  crlSerial   : {crl_serial}")
        print(f"  entries     : {len(entries)} revoked certificate(s)")
    elif crl_type in ("fullLinkedCrl", "deltaLinkedCrl",
                      "fullLinkedCrlWithAlg", "deltaLinkedCrlWithAlg"):
        tbs_crl = ts[1] if isinstance(ts, (list, tuple)) else {}
        individual = tbs_crl.get("individual") or []
        groups = tbs_crl.get("groups") or []
        grp_single = tbs_crl.get("groupsSingleSeed") or []
        print(f"  iRev        : {i_rev}")
        print(f"  individual  : {len(individual)} JMaxGroup(s)")
        print(f"  groups      : {len(groups)} GroupCrlEntry(s)")
        print(f"  groupsSingle: {len(grp_single)} GroupSingleSeedEntry(s)")

    # ---- Step 6: check revocation ----
    print("\n[6] Checking revocation ...")
    revoked = []
    if crl_type in ("fullHashCrl", "deltaHashCrl"):
        revoked = check_hash_based(crl_contents, certs)
    elif crl_type in ("fullLinkedCrl", "deltaLinkedCrl",
                      "fullLinkedCrlWithAlg", "deltaLinkedCrlWithAlg"):
        revoked = check_linkage_based(crl_contents, certs)

    print(SEP)
    if revoked:
        print(f"  REVOKED: {len(revoked)} certificate(s) found in CRL")
        for r in revoked:
            print(f"    {r['path']}  reason={r['reason']}  i_cert={r.get('i_cert','?')}")
    else:
        print(f"  NOT REVOKED: 0 of {len(certs)} pseudonym certificates appear in the CRL")
    print(SEP)


if __name__ == "__main__":
    main()
