#!/usr/bin/env python3
"""
check_crl.py — Download the IEEE 1609.2 CRL from the SCMS RA and check whether
pseudonym certificates are revoked.

Three modes:

  Mode 1 — check own device bundle:
    python3 check_crl.py --certs-dir certs/ISS/pseudonym/<id>

  Mode 2 — check signing cert from a received BSM (same SCMS provider):
    python3 check_crl.py --bsm <file.coer> --certs-dir certs/ISS/pseudonym/<id>

  Mode 3 — check BSM from a different SCMS provider (cross-provider):
    python3 check_crl.py --bsm <file.coer> \
        --ctl ctl/20250813-production_ctl   \
        --ra-url https://ra.otherprovider.com

Standards reference:
  IEEE 1609.2-2022    §7.3        CRL data structures
  IEEE 1609.2.1-2022  §6.3.5.10  Individual CRL download API
                      §6.3.5.8   Composite CRL download API
                      §7.3.11    MultiSignedCtl / CTL structure
"""

import argparse
import datetime
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
# Time helpers
# ---------------------------------------------------------------------------

_TAI_EPOCH = datetime.datetime(2004, 1, 1, tzinfo=datetime.timezone.utc)


def _tai32_fmt(tai_secs: int | None) -> str:
    """Format a Time32 (TAI seconds since 2004-01-01) as UTC + relative-to-now.

    Example outputs:
      2026-04-02 15:30 UTC  (7 days ago)
      2026-04-16 10:00 UTC  (in 7 days)
      2026-04-09 12:00 UTC  (now)
    """
    if tai_secs is None:
        return "n/a"
    dt = _TAI_EPOCH + datetime.timedelta(seconds=int(tai_secs))
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = dt - now
    total_secs = int(delta.total_seconds())
    abs_secs = abs(total_secs)

    if abs_secs < 60:
        rel = "now"
    elif abs_secs < 3600:
        mins = abs_secs // 60
        rel = f"in {mins}m" if total_secs > 0 else f"{mins}m ago"
    elif abs_secs < 86400:
        hours = abs_secs // 3600
        rel = f"in {hours}h" if total_secs > 0 else f"{hours}h ago"
    else:
        days = abs_secs // 86400
        rel = f"in {days}d" if total_secs > 0 else f"{days}d ago"

    return f"{dt.strftime('%Y-%m-%d %H:%M')} UTC  ({rel})"


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
# BSM certificate extraction
# ---------------------------------------------------------------------------

def extract_cert_from_bsm(bsm_bytes: bytes) -> bytes:
    """
    Extract the leaf signing certificate from an Ieee1609Dot2Data { signedData } BSM.
    Returns raw COER bytes of the Certificate (leaf / pseudonym cert).
    Raises ValueError if the signer uses a digest (no inline cert) or the
    structure is not signedData.
    """
    from asn1c_lib import decode_oer as _decode, encode_jer as _encode
    try:
        bsm = _decode("Ieee1609Dot2Data", bsm_bytes)
        signer = bsm["content"]["signedData"]["signer"]
    except Exception as e:
        raise ValueError(f"Cannot parse BSM as Ieee1609Dot2Data {{signedData}}: {e}")

    if "digest" in signer:
        raise ValueError(
            "BSM signer is a digest (HashedId8 only) — no inline certificate present.\n"
            "  Revocation check requires an inline certificate in the BSM."
        )
    certs = signer.get("certificate")
    if not certs:
        raise ValueError(f"Unexpected signer structure (keys: {list(signer)})")

    return _encode("Certificate", certs[0])


# ---------------------------------------------------------------------------
# CRACA identification
# ---------------------------------------------------------------------------

def ra_url_from_cert(certs_dir: str) -> str | None:
    """Return the RA URL from the RA certificate in the bundle directory.

    Delegates to asn1c_lib.ra_url_from_bundle().
    """
    from asn1c_lib import ra_url_from_bundle
    return ra_url_from_bundle(certs_dir)


def find_craca(certs_dir: str, cert_bytes: bytes = None) -> tuple[str, bytes] | tuple[None, None]:
    """
    Search trustedcerts/ for the certificate whose SHA-256[-3:] matches the
    cracaId (HashedId3) of cert_bytes, or of the first pseudonym certificate
    found in download/ if cert_bytes is not provided.
    Returns (craca_hashed_id8_hex, craca_cert_bytes).
    """
    if cert_bytes is None:
        # Find first pseudonym cert from download/
        download_dir = os.path.join(certs_dir, "download")
        for week in sorted(os.listdir(download_dir)):
            week_dir = os.path.join(download_dir, week)
            for f in sorted(os.listdir(week_dir)):
                if f.endswith(".cert"):
                    cert_bytes = open(os.path.join(week_dir, f), "rb").read()
                    break
            if cert_bytes:
                break
        if not cert_bytes:
            print("  No pseudonym cert found.")
            return None, None

    parsed = parse_cert(cert_bytes)
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
# CTL-based CRACA lookup
# ---------------------------------------------------------------------------

def _ctl_unsigned_cert_bytes(ctl_file_bytes: bytes) -> list[bytes]:
    """
    Parse a MultiSignedCtlSpdu (Ieee1609Dot2Data) and return the raw COER bytes
    of every Certificate in MultiSignedCtl.unsigned (SequenceOfCertificate).
    Returns an empty list on any parse failure.
    """
    mod = _get_pycrate_mod()
    if mod is None:
        return []
    try:
        # Outer Ieee1609Dot2Data
        D = mod.Ieee1609Dot2.Ieee1609Dot2Data
        D.from_oer(ctl_file_bytes)
        v = D.get_val()

        # Navigate to unsecuredData (same pattern as extract_crl_contents)
        content = v["content"]
        sd = content[1] if isinstance(content, (list, tuple)) else content.get("signedData")
        if isinstance(sd, (list, tuple)):
            sd = sd[1]
        inner = sd["tbsData"]["payload"]["data"]["content"]
        if isinstance(inner, (list, tuple)):
            _, unsecured = inner
        else:
            unsecured = inner.get("unsecuredData")

        if not isinstance(unsecured, (bytes, bytearray)):
            return []

        # CertManagementPdu → multiSignedCtl → MultiSignedCtl
        CMP = mod.Ieee1609Dot2Dot1CertManagement.CertManagementPdu
        CMP.from_oer(bytes(unsecured))
        cmp_val = CMP.get_val()

        if isinstance(cmp_val, (list, tuple)):
            cmp_choice, msc_val = cmp_val
        else:
            cmp_choice = next(iter(cmp_val))
            msc_val = cmp_val[cmp_choice]

        if cmp_choice != "multiSignedCtl":
            return []

        unsigned = msc_val.get("unsigned")
        if unsigned is None:
            return []

        # unsigned is SequenceOfCertificate — open type, likely arrives as raw bytes
        if isinstance(unsigned, (bytes, bytearray)):
            SeqCert = mod.Ieee1609Dot2.SequenceOfCertificate
            SeqCert.from_oer(bytes(unsigned))
            cert_vals = SeqCert.get_val()
        elif isinstance(unsigned, list):
            cert_vals = unsigned
        else:
            return []

        # Re-encode each cert value to raw COER bytes for hashing
        C = mod.Ieee1609Dot2.Certificate
        result = []
        for cv in (cert_vals or []):
            try:
                C.set_val(cv)
                result.append(bytes(C.to_oer()))
            except Exception:
                continue
        return result

    except Exception as e:
        print(f"  [ctl] Parse error: {e}")
        return []


def find_craca_in_ctl(ctl_path: str, craca_id3: bytes) -> tuple[str, bytes] | tuple[None, None]:
    """
    Scan the unsigned certificates in a MultiSignedCtlSpdu for a cert whose
    SHA-256[-3:] matches craca_id3.
    ctl_path may be a file or a directory; if a directory, the first
    *ctl*.oer file found is used.
    Returns (craca_hashed_id8_hex, craca_cert_bytes) or (None, None).
    """
    if os.path.isdir(ctl_path):
        oer_files = sorted(
            f for f in os.listdir(ctl_path)
            if f.endswith(".oer") and "ctl" in f.lower()
        )
        if not oer_files:
            oer_files = sorted(f for f in os.listdir(ctl_path) if f.endswith(".oer"))
        if not oer_files:
            print(f"  [ctl] No .oer file found in {ctl_path}")
            return None, None
        ctl_path = os.path.join(ctl_path, oer_files[0])

    print(f"  CTL file: {ctl_path}")
    try:
        ctl_bytes = open(ctl_path, "rb").read()
    except OSError as e:
        print(f"  [ctl] {e}")
        return None, None

    cert_bytes_list = _ctl_unsigned_cert_bytes(ctl_bytes)
    if not cert_bytes_list:
        print(f"  [ctl] No certificates extracted from CTL")
        return None, None

    print(f"  {len(cert_bytes_list)} unsigned certificate(s) in CTL")
    for cb in cert_bytes_list:
        digest = hashlib.sha256(cb).digest()
        if digest[-3:] == craca_id3:
            hid8 = digest[-8:].hex()
            print(f"  CRACA found in CTL  HashedId8={hid8}")
            return hid8, cb

    print(f"  [ctl] No cert matched cracaId {craca_id3.hex()}")
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


def _evolve_seed(seed: bytes, la_id: bytes, steps: int) -> bytes:
    """Forward-evolve a linkage seed by *steps* i-periods.

    IEEE 1609.2-2022 §5.1.3.4.6 (seedEvoFn1-sha256):
        input  = la_id (2 B) || ls (16 B) || 0^112 (14 B)   [32 bytes total]
        output = low-order 16 octets of SHA-256(input)
    """
    for _ in range(steps):
        sha_in = la_id + seed + b'\x00' * 14          # 2 + 16 + 14 = 32 bytes
        seed = hashlib.sha256(sha_in).digest()[-16:]   # low-order 16 bytes
    return seed


def _plv(ls: bytes, la_id: bytes, j: int) -> bytes:
    """Pre-linkage value — seed expansion function (lvGenFn1-aes128).

    IEEE 1609.2-2022 §5.1.3.4.8:
        data   = 0^80 (10 B) || la_id (2 B) || Uint32(j) (4 B)  [16 bytes]
        output = AES-128(key=ls, data=data) XOR data              [16 bytes]
    """
    data = b'\x00' * 10 + la_id + j.to_bytes(4, "big")   # 16 bytes
    enc = _aes_ecb(ls, data)
    return bytes(a ^ b for a, b in zip(enc, data))        # Davies-Meyer XOR


def compute_linkage_value(seed1: bytes, seed2: bytes,
                          la1_id: bytes, la2_id: bytes,
                          i_rev: int, i_cert: int, j: int) -> bytes:
    """
    IEEE 1609.2-2022 §5.1.3.4.2 — compute individual linkage value LV(i_cert, j).

    1. Evolve each CRL seed from iRev to i_cert  (§5.1.3.4.6).
    2. Compute pre-linkage values PLV1, PLV2      (§5.1.3.4.8).
    3. LV = low-order 9 bytes of (PLV1 ⊕ PLV2).

    Parameters
    ----------
    seed1, seed2 : 16-byte linkage seeds from the CRL (at iRev).
    la1_id, la2_id : 2-byte Linkage Authority Identifiers (from LAGroup).
    i_rev  : the CRL's iRev value.
    i_cert : the certificate's iCert value (must be >= i_rev).
    j      : certificate index within the i-period (0 … jMax-1).
    """
    if i_cert < i_rev:
        raise ValueError(f"i_cert ({i_cert}) < i_rev ({i_rev}): "
                         "cannot reverse-evolve a one-way hash chain")
    steps = i_cert - i_rev
    s1 = _evolve_seed(seed1, la1_id, steps)
    s2 = _evolve_seed(seed2, la2_id, steps)
    plv1 = _plv(s1, la1_id, j)
    plv2 = _plv(s2, la2_id, j)
    xored = bytes(a ^ b for a, b in zip(plv1, plv2))
    return xored[-9:]                                     # low-order 9 bytes


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

    # Collect the distinct i_cert values we need to check (only >= iRev)
    i_cert_values = sorted({c.get("i_cert", 0) for c in certs
                            if c.get("i_cert", 0) >= i_rev})

    def _check_individual(seed1_bytes, seed2_bytes, la1_id, la2_id,
                          i_rev_val, jmax_val):
        """Try every cert i_cert (>= iRev) × j (0…jMax-1) combination."""
        for ic in i_cert_values:
            for j in range(jmax_val):
                computed = compute_linkage_value(seed1_bytes, seed2_bytes,
                                                la1_id, la2_id,
                                                i_rev_val, ic, j)
                key = (ic, computed.hex())
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
            la1_id = _bytes_of(la_group.get("la1Id", b""))
            la2_id = _bytes_of(la_group.get("la2Id", b""))
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
                        hit = _check_individual(s1, s2, la1_id, la2_id,
                                               i_rev, jmax)
                        if hit:
                            revoked.append({**hit, "reason": "linkage-individual",
                                            "i_rev": i_rev, "j_idx": j_idx})

    # Group revocations
    groups = tbs_crl.get("groups") or []
    for group_entry in groups:
        if not isinstance(group_entry, dict):
            continue
        imax = group_entry.get("iMax", 0)
        la1_id = _bytes_of(group_entry.get("la1Id", b""))
        la2_id = _bytes_of(group_entry.get("la2Id", b""))
        s1 = _bytes_of(group_entry.get("linkageSeed1", b""))
        s2 = _bytes_of(group_entry.get("linkageSeed2", b""))
        if len(s1) == 16 and len(s2) == 16:
            # Group revocation: no jMax in GroupCrlEntry; use j=0 only.
            # (Full group-linkage checking against GroupLinkageValue is TODO.)
            hit = _check_individual(s1, s2, la1_id, la2_id, i_rev, 1)
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
    ap.add_argument("--certs-dir", default=None,
                    help="Pseudonym bundle directory. Required when --bsm is not used "
                         "(download/ contains the certs to check). When used with --bsm, "
                         "only trustedcerts/ is needed for RA URL and cracaId discovery; "
                         "omit entirely when --ctl + --ra-url cover both.")
    ap.add_argument("--bsm", default=None,
                    help="Check the signing certificate from this BSM file "
                         "(Ieee1609Dot2Data COER). The signer must use an inline "
                         "certificate (not a digest). Use with --certs-dir, or with "
                         "--ctl + --ra-url for cross-provider checking.")
    ap.add_argument("--craca-hex", default=None,
                    help="HashedId8 of CRACA cert (16 hex chars). "
                         "Auto-detected from trustedcerts/ if omitted.")
    ap.add_argument("--crl-series", type=int, default=None,
                    help="CRL series number. Auto-detected from cert if omitted.")
    ap.add_argument("--save-crl", default=None,
                    help="Save downloaded CRL bytes to this file.")
    ap.add_argument("--load-crl", default=None,
                    help="Load CRL from file instead of downloading (for offline use).")
    ap.add_argument("--ctl", default=None,
                    help="Path to a MultiSignedCtlSpdu file or directory (e.g. "
                         "ctl/20250813-production_ctl). Used as a fallback when "
                         "the CRACA cert is not found in --certs-dir/trustedcerts/ "
                         "(e.g. BSM from a different SCMS provider). "
                         "If a directory is given, the first *ctl*.oer file is used.")
    args = ap.parse_args()

    if not args.bsm and not args.certs_dir:
        ap.error("--certs-dir is required when --bsm is not used.")
    if args.bsm and not args.certs_dir and not args.ctl:
        ap.error("--bsm without --certs-dir requires --ctl for cracaId resolution "
                 "(and --ra-url for the CRL download endpoint).")

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

    # ---- Step 2: load cert(s) to check ----
    bsm_cert_bytes = None  # set when --bsm is used; drives find_craca and crlSeries

    if args.bsm:
        print(f"\n[2] Extracting signing cert from BSM {args.bsm} ...")
        try:
            bsm_raw = open(args.bsm, "rb").read()
            bsm_cert_bytes = extract_cert_from_bsm(bsm_raw)
        except (OSError, ValueError) as e:
            print(f"  ERROR: {e}")
            sys.exit(1)
        parsed = parse_cert(bsm_cert_bytes)
        if parsed is None:
            print("  ERROR: pycrate unavailable — cannot parse extracted certificate.")
            sys.exit(1)
        parsed["path"] = args.bsm
        parsed["raw"]  = bsm_cert_bytes
        parsed["hid10"] = hashed_id10(bsm_cert_bytes).hex()
        certs = [parsed]
        print(f"  type       : {parsed.get('type', 'unknown')}")
        print(f"  i_cert     : {parsed.get('i_cert', 'n/a')}  (0x{parsed.get('i_cert', 0):x})")
        print(f"  linkage_val: {parsed.get('linkage_value', b'').hex()}")
        print(f"  hid10      : {parsed.get('hid10', 'n/a')}")
    else:
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
        if args.certs_dir:
            print(f"\n[2b] Auto-discovering RA URL from {args.certs_dir} ...")
            ra_url = ra_url_from_cert(args.certs_dir)
            if ra_url:
                print(f"  RA URL from certificate: {ra_url}")
            else:
                print("  Could not read RA cert. Supply --ra-url explicitly.")
                sys.exit(1)
        else:
            print("  ERROR: no --ra-url supplied and no --certs-dir to discover it from.")
            print("  Supply --ra-url <RA base URL> for the provider that issued the BSM.")
            sys.exit(1)

    # ---- Step 3: determine cracaId / crlSeries ----
    craca_hex = args.craca_hex
    crl_series = args.crl_series

    if craca_hex is None or crl_series is None:
        if args.certs_dir:
            print(f"\n[3] Identifying CRACA from {args.certs_dir}/trustedcerts/ ...")
            auto_craca_hex, _ = find_craca(args.certs_dir, bsm_cert_bytes)
            if craca_hex is None:
                craca_hex = auto_craca_hex

        if craca_hex is None and args.ctl and certs:
            craca_id3 = certs[0].get("craca_id3", b"")
            if craca_id3:
                label = "[3b]" if args.certs_dir else "[3] "
                print(f"\n{label} Searching CTL for cracaId {craca_id3.hex()} ...")
                craca_hex, _ = find_craca_in_ctl(args.ctl, craca_id3)
                if craca_hex and args.ra_url is None:
                    print(f"  NOTE: CRACA resolved via CTL (cross-provider). "
                          f"RA URL is from your own trustedcerts/ — if the CRL "
                          f"download fails, supply --ra-url for the other provider's RA.")

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
    print(f"  issueDate   : {_tai32_fmt(crl_contents.get('issueDate'))}")
    print(f"  nextCrl     : {_tai32_fmt(crl_contents.get('nextCrl'))}  (i-period rollover; CRL may be reissued earlier on revocation)")
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
        index_within_i = tbs_crl.get("indexWithinI", "n/a")
        print(f"  iRev        : {i_rev}")
        print(f"  indexWithinI: {index_within_i}  (increments each time a new CRL is issued within this i-period)")
        print(f"  individual  : {len(individual)} JMaxGroup(s)")
        print(f"  groups      : {len(groups)} GroupCrlEntry(s)")
        print(f"  groupsSingle: {len(grp_single)} GroupSingleSeedEntry(s)")

        # Show computed linkage values for every individual entry so they can
        # be compared against cert linkage values when no match is found.
        def _lv_bytes(val):
            if isinstance(val, (bytes, bytearray)):
                return bytes(val)
            if isinstance(val, str):
                return val.encode("latin-1")
            if isinstance(val, (list, tuple)):
                return bytes(val)
            return b""

        # Show LA identifiers, iMax, and seed availability for each entry.
        def _id_hex(v):
            if isinstance(v, (bytes, bytearray)): return v.hex()
            if isinstance(v, str): return v.encode("latin-1").hex()
            return repr(v)

        total_seeds = 0
        entry_idx = 0
        for jmax_group in individual:
            if not isinstance(jmax_group, dict):
                continue
            jmax_disp = jmax_group.get("jmax", 0)
            for la_group in (jmax_group.get("contents") or []):
                if not isinstance(la_group, dict):
                    continue
                la1 = _id_hex(la_group.get("la1Id", b""))
                la2 = _id_hex(la_group.get("la2Id", b""))
                la1_bytes = _lv_bytes(la_group.get("la1Id", b""))
                la2_bytes = _lv_bytes(la_group.get("la2Id", b""))
                for imax_group in (la_group.get("contents") or []):
                    if not isinstance(imax_group, dict):
                        continue
                    imax = imax_group.get("iMax", "?")
                    seeds = imax_group.get("contents") or []
                    total_seeds += len(seeds)
                    print(f"    la1={la1}  la2={la2}  iMax={imax}  jMax={jmax_disp}  seeds={len(seeds)}")
                    for ir in seeds:
                        if not isinstance(ir, dict):
                            continue
                        s1 = _lv_bytes(ir.get("linkageSeed1", b""))
                        s2 = _lv_bytes(ir.get("linkageSeed2", b""))
                        if len(s1) == 16 and len(s2) == 16:
                            # Show LV at j=0 for display (all jMax values
                            # are checked during revocation in step 6)
                            lv = compute_linkage_value(s1, s2, la1_bytes, la2_bytes,
                                                       i_rev, i_rev, 0)
                            parts = [f"[{entry_idx:3d}] i={i_rev} j=0 lv={lv.hex()}"]
                            for ic in sorted({c.get("i_cert", 0) for c in certs
                                              if c.get("i_cert", 0) > i_rev}):
                                elv = compute_linkage_value(s1, s2, la1_bytes, la2_bytes,
                                                            i_rev, ic, 0)
                                parts.append(f"i={ic} lv={elv.hex()}")
                            print(f"      {'  | '.join(parts)}")
                            entry_idx += 1

        if individual and total_seeds == 0:
            print(f"  WARNING: CRL skeleton only — linkage seeds absent.")
            print(f"  The RA endpoint omits IndividualRevocation seed pairs.")
            print(f"  Per IEEE 1609.2.1-2022 §6.3.5.8/§6.3.5.10, the RA combines")
            print(f"  LA1+LA2 seeds before distributing a complete CRL to all parties.")
            print(f"  Revocation checking via this public endpoint is not possible.")

    # ---- Step 6: check revocation ----
    print("\n[6] Checking revocation ...")
    revoked = []
    if crl_type in ("fullHashCrl", "deltaHashCrl"):
        revoked = check_hash_based(crl_contents, certs)
    elif crl_type in ("fullLinkedCrl", "deltaLinkedCrl",
                      "fullLinkedCrlWithAlg", "deltaLinkedCrlWithAlg"):
        revoked = check_linkage_based(crl_contents, certs)

    noun = "certificate" if len(certs) == 1 else "pseudonym certificates"
    print(SEP)
    if revoked:
        print(f"  REVOKED: {len(revoked)} {noun} found in CRL")
        for r in revoked:
            print(f"    {r['path']}  reason={r['reason']}  i_cert={r.get('i_cert','?')}")
    else:
        print(f"  NOT REVOKED: 0 of {len(certs)} {noun} appear in the CRL")
    print(SEP)


if __name__ == "__main__":
    main()
