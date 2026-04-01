#!/usr/bin/env python3
"""
asn1c_lib.py - ctypes interface to lib/libasn1c.so (asn1c-generated codec).

Exports:
    decode_oer(pdu_name, data)  -> dict   Decode COER bytes to a JER dict.
    encode_jer(pdu_name, obj)   -> bytes  Encode a JER dict to COER bytes.

Requires: lib/libasn1c.so  (run ./build_asn_lib.sh on the Ubuntu host to build it)
"""

import ctypes
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_PATH   = os.path.join(SCRIPT_DIR, 'lib', 'libasn1c.so')

_lib = None


def _get_lib():
    global _lib
    if _lib is not None:
        return _lib
    if not os.path.exists(LIB_PATH):
        print(
            f"ERROR: {LIB_PATH} not found.\n"
            "Run ./build_asn_lib.sh to compile the decoder library.",
            file=sys.stderr,
        )
        sys.exit(1)
    lib = ctypes.CDLL(LIB_PATH)

    lib.decode_oer_to_jer.restype  = ctypes.c_int
    lib.decode_oer_to_jer.argtypes = [
        ctypes.c_char_p,                    # pdu_name
        ctypes.c_char_p,                    # data  (binary — length passed separately)
        ctypes.c_size_t,                    # data_len
        ctypes.POINTER(ctypes.c_char_p),    # json_out  (malloc'd; free with free_buffer)
        ctypes.c_char_p,                    # err_buf
        ctypes.c_size_t,                    # err_size
    ]

    lib.encode_jer_to_oer.restype  = ctypes.c_int
    lib.encode_jer_to_oer.argtypes = [
        ctypes.c_char_p,                    # pdu_name
        ctypes.c_char_p,                    # json_in  (NUL-terminated JER)
        ctypes.POINTER(ctypes.c_void_p),    # oer_out  (malloc'd; free with free_buffer)
        ctypes.POINTER(ctypes.c_size_t),    # oer_len
        ctypes.c_char_p,                    # err_buf
        ctypes.c_size_t,                    # err_size
    ]

    lib.free_buffer.restype  = None
    lib.free_buffer.argtypes = [ctypes.c_void_p]

    _lib = lib
    return _lib


def decode_oer(pdu_name: str, data: bytes) -> dict:
    """Decode raw OER/COER bytes as pdu_name, return parsed JER dict."""
    lib = _get_lib()

    c_name   = pdu_name.replace('-', '_').encode()
    err_buf  = ctypes.create_string_buffer(4096)
    json_out = ctypes.c_char_p(None)

    rc = lib.decode_oer_to_jer(
        c_name,
        data, len(data),
        ctypes.byref(json_out),
        err_buf, len(err_buf),
    )

    if rc != 0:
        hex_lines = []
        for i in range(0, len(data), 16):
            chunk    = data[i:i+16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f"  {i:04X}  {hex_part:<47}  {asc_part}")
        raise ValueError(
            f"Decode failed for {pdu_name}: {err_buf.value.decode()}\n"
            f"Input ({len(data)} bytes):\n" + '\n'.join(hex_lines)
        )

    try:
        result = json.loads(json_out.value.decode('utf-8'))
    finally:
        lib.free_buffer(json_out)

    return result


def encode_jer(pdu_name: str, obj: dict) -> bytes:
    """Encode a Python dict as the named PDU type, return COER bytes.

    pdu_name : ASN.1 type name (hyphens are replaced with underscores internally).
    obj      : Python dict matching the JER structure for the type.

    Raises ValueError on encode failure.
    """
    lib = _get_lib()

    c_name   = pdu_name.replace('-', '_').encode()
    json_str = json.dumps(obj, separators=(',', ':')).encode()
    err_buf  = ctypes.create_string_buffer(4096)
    oer_out  = ctypes.c_void_p(None)
    oer_len  = ctypes.c_size_t(0)

    rc = lib.encode_jer_to_oer(
        c_name,
        json_str,
        ctypes.byref(oer_out),
        ctypes.byref(oer_len),
        err_buf, len(err_buf),
    )

    if rc != 0:
        raise ValueError(
            f"Encode failed for {pdu_name}: {err_buf.value.decode()}\n"
            f"Input JSON: {json_str.decode()[:300]}"
        )

    try:
        result = bytes(ctypes.string_at(oer_out.value, oer_len.value))
    finally:
        lib.free_buffer(oer_out)

    return result
