#!/usr/bin/env python3
"""
decode_mbr.py - Recursive OER/COER decoder for SaeJ3287Data.

Usage: python3 decode_mbr.py <file.coer>

Outputs a JSON object to stdout with recursively decoded fields.

Requires: lib/libasn1c.so  (run ./build_asn_lib.sh once to build it)
"""

import argparse
import json
import sys

from asn1c_lib import decode_oer, encode_jer

# AID constants (PSID)
AID_BSM = 32

# BSM tgtId constants
BSM_TGT_SECURITY = 2
BSM_TGT_LONGACC  = 5

# IdObsPdu constants
OBS_PDU_ETSI_GN      = 1
OBS_PDU_IEEE1609DOT2 = 2

# obsId names for BsmSecurity
BSM_SECURITY_OBS_NAMES = {
    1: "MessageIdIncWithHeaderInfo",
    2: "HeaderIncWithSecurityProfile",
    3: "HeaderPsidIncWithCertificate",
    4: "MessageIncWithSsp",
    5: "HeaderTimeOutsideCertificateValidity",
    6: "MessageLocationOutsideCertificateValidity",
    7: "HeaderLocationOutsideCertificateValidity",
}

# obsId names for BsmLongAcc
BSM_LONGACC_OBS_NAMES = {
    4: "ValueTooLarge",
}


# ── Enrichment helpers (recursive open-type decoding) ─────────────────────────

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert JER ANY hex string (uppercase, no spaces) to bytes."""
    return bytes.fromhex(hex_str.replace(' ', ''))


def decode_single_obs(tgt_id: int, hex_val: str) -> dict:
    """Decode one element from ObservationsByTarget-Bsm.observations (SEQUENCE OF ANY)."""
    raw = hex_to_bytes(hex_val)

    if tgt_id == BSM_TGT_SECURITY:
        pdu_name  = "MbSingleObservation-BsmSecurity"
        obs_names = BSM_SECURITY_OBS_NAMES
    elif tgt_id == BSM_TGT_LONGACC:
        pdu_name  = "MbSingleObservation-BsmLongAcc"
        obs_names = BSM_LONGACC_OBS_NAMES
    else:
        return {"_raw": hex_val, "_note": f"unknown tgtId={tgt_id}"}

    decoded = decode_oer(pdu_name, raw)
    obs_id  = decoded.get("obsId")
    if obs_id is not None:
        decoded["obsType"] = obs_names.get(obs_id, f"unknown-obsId-{obs_id}")
    return decoded


def enrich_obs_by_target(obs_by_tgt: dict) -> dict:
    """Recursively decode the observations SEQUENCE OF ANY."""
    tgt_id    = obs_by_tgt.get("tgtId")
    raw_obs   = obs_by_tgt.get("observations", [])
    decoded_obs = [
        decode_single_obs(tgt_id, item) if isinstance(item, str) else item
        for item in raw_obs
    ]
    return {**obs_by_tgt, "observations": decoded_obs}


def decode_v2x_pdu(pdu_type: int, hex_val: str):
    """Decode one element from V2xPduStream.v2xPdus (SEQUENCE OF ANY)."""
    if pdu_type == OBS_PDU_IEEE1609DOT2:
        return decode_oer("Ieee1609Dot2Data", hex_to_bytes(hex_val))
    # type=1 (ObsPduEtsiGn) and anything else: keep as hex
    return hex_val


def enrich_v2x_stream(stream: dict) -> dict:
    """Decode v2xPdus SEQUENCE OF ANY entries in a V2xPduStream."""
    pdu_type   = stream.get("type")
    raw_pdus   = stream.get("v2xPdus", [])
    decoded_pdus = [
        decode_v2x_pdu(pdu_type, item) if isinstance(item, str) else item
        for item in raw_pdus
    ]
    return {**stream, "v2xPdus": decoded_pdus}


def _enrich_asr_bsm_dict(asr: dict) -> dict:
    """Enrich an already-decoded AsrBsm dict (observations ANY → typed dicts)."""
    if "observations" in asr:
        asr = {**asr, "observations": [
            enrich_obs_by_target(o) for o in asr["observations"]
        ]}
    if "v2xPduEvidence" in asr:
        asr = {**asr, "v2xPduEvidence": [
            enrich_v2x_stream(s) for s in asr["v2xPduEvidence"]
        ]}
    return asr


def enrich_asr_bsm(content_hex: str) -> dict:
    """Decode AidSpecificReport.content hex as AsrBsm, then enrich recursively."""
    return _enrich_asr_bsm_dict(decode_oer("AsrBsm", hex_to_bytes(content_hex)))


def enrich_mbr(mbr: dict) -> dict:
    """Decode report.content based on the aid field."""
    report  = mbr.get("report", {})
    aid     = report.get("aid")
    content = report.get("content")

    if aid == AID_BSM:
        if isinstance(content, str):
            # Rare path: content still hex-encoded (e.g. bare SaeJ3287Mbr without IOS)
            report = {**report, "content": enrich_asr_bsm(content)}
        elif isinstance(content, dict):
            # Normal path: asn1c already decoded content via OPEN_TYPE dispatch;
            # inner SEQUENCE OF ANY fields still need enrichment.
            report = {**report, "content": _enrich_asr_bsm_dict(content)}

    return {**mbr, "report": report}


def _enrich_signed_1609(signed: dict) -> dict:
    """Decode unsecuredData inside a signed Ieee1609Dot2Data as SaeJ3287Mbr."""
    try:
        unsecured_hex = (
            signed.get("content", {})
                  .get("signedData", {})
                  .get("tbsData", {})
                  .get("payload", {})
                  .get("data", {})
                  .get("content", {})
                  .get("unsecuredData")
        )
        if not isinstance(unsecured_hex, str):
            return signed

        mbr = decode_oer("SaeJ3287Mbr", hex_to_bytes(unsecured_hex))
        enriched = enrich_mbr(mbr)

        # Rebuild the nested dicts immutably
        inner   = {**signed["content"]["signedData"]["tbsData"]["payload"]["data"]["content"],
                   "unsecuredData": enriched}
        data    = {**signed["content"]["signedData"]["tbsData"]["payload"]["data"],
                   "content": inner}
        payload = {**signed["content"]["signedData"]["tbsData"]["payload"], "data": data}
        tbs     = {**signed["content"]["signedData"]["tbsData"], "payload": payload}
        sd      = {**signed["content"]["signedData"], "tbsData": tbs}
        content = {**signed["content"], "signedData": sd}
        return  {**signed, "content": content}
    except Exception:
        return signed


def enrich_mbr_sec(mbr_sec: dict) -> dict:
    """Handle one SaeJ3287MbrSec CHOICE element."""
    if "plaintext" in mbr_sec:
        return {"plaintext": enrich_mbr(mbr_sec["plaintext"])}
    if "signed" in mbr_sec:
        return {"signed": _enrich_signed_1609(mbr_sec["signed"])}
    # sTE: pass through as-is (encrypted)
    return mbr_sec


def enrich_sae_j3287_data(data: dict) -> dict:
    """Top-level enrichment of a SaeJ3287Data object."""
    content = data.get("content")
    if content is not None:
        data = {**data, "content": enrich_mbr_sec(content)}
    return data


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recursive OER/COER decoder for SaeJ3287 messages"
    )
    parser.add_argument("file", help="Input .coer file")
    parser.add_argument(
        "--type",
        choices=["SaeJ3287Data", "SaeJ3287Mbr"],
        default="SaeJ3287Data",
        help="Top-level PDU type (default: SaeJ3287Data). "
             "Use SaeJ3287Mbr for raw MBR files without the SaeJ3287Data wrapper.",
    )
    args = parser.parse_args()

    with open(args.file, 'rb') as f:
        raw = f.read()

    pdu_type = args.type
    if not raw:
        print("ERROR: input file is empty", file=sys.stderr)
        sys.exit(1)
    if pdu_type == "SaeJ3287Data" and raw[0] != 0x01:
        # SaeJ3287Data starts with version=1 (0x01).
        # A bare SaeJ3287Mbr starts with Time64 (high byte 0x00 for current timestamps).
        print(
            "Warning: first byte is not 0x01; auto-switching to --type SaeJ3287Mbr",
            file=sys.stderr,
        )
        pdu_type = "SaeJ3287Mbr"

    if pdu_type == "SaeJ3287Mbr":
        top      = decode_oer("SaeJ3287Mbr", raw)
        enriched = enrich_mbr(top)
    else:
        top      = decode_oer("SaeJ3287Data", raw)
        enriched = enrich_sae_j3287_data(top)

    print(json.dumps({pdu_type: enriched}, indent=2))


if __name__ == "__main__":
    main()
