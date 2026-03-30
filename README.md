# SAE J3287 Misbehavior Report (MBR) Toolkit

Tools for building and decoding Vehicle-to-Everything (V2X) Misbehavior Reports (MBRs) per SAE J3287 and ETSI TS 103 759. Given a Basic Safety Message (BSM) in COER format, the toolkit produces a standards-compliant `SaeJ3287Data` message (plaintext, signed, or signed+encrypted) and can decode any such message back to human-readable JSON.

## Requirements

| Tool | Purpose |
|------|---------|
| Python 3.8+ | `create_mbr.py`, `decode_mbr.py` |
| `cryptography` (pip) | ECDSA signing, AES-CCM encryption |
| `gcc` | Compile `lib/libdecode.so` |
| `lib/libdecode.so` | Required at runtime by both scripts |

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Build the shared library once before using either script:

```bash
./build_asn_lib.sh
```

## Usage

### Encode — `create_mbr.py`

Builds a `SaeJ3287Data` COER file from an input BSM. Always produces `out_plaintext.coer`; signed and encrypted variants require the corresponding key material.

```bash
python3 create_mbr.py \
    --bsm <file.coer>               # Input Ieee1609Dot2Data BSM (required)
    [--signing-key <key.pem>]       # ECDSA P-256 private key — enables out_signed.coer
    [--recipient-pub <hex>]         # Recipient P-256 public key (64–65 bytes hex) — enables out_ste.coer
    [--out-dir coer/]               # Output directory (default: coer/)
    [--psid 38]                     # PSID for headerInfo (default: 38 = MBR)
    [--cert-days 7]                 # Certificate validity in days (default: 7)
    [--lat 0]                       # observationLocation latitude (default: 0)
    [--lon 0]                       # observationLocation longitude (default: 0)
    [--elev 0]                      # observationLocation elevation (default: 0)
```

**Output files** (written to `--out-dir`):

| File | Type | Requires |
|------|------|---------|
| `out_plaintext.coer` | `SaeJ3287MbrSec.plaintext` | always |
| `out_signed.coer` | `SaeJ3287MbrSec.signed` | `--signing-key` |
| `out_ste.coer` | `SaeJ3287MbrSec.sTE` | `--signing-key` + `--recipient-pub` |

**Example:**

```bash
python3 create_mbr.py \
    --bsm coer/Ieee1609Dot2Data_bad_accel.coer \
    --out-dir coer/
```

### Decode — `decode_mbr.py`

Decodes a COER file to JSON on stdout, recursively expanding all open-type (`ANY`) fields.

```bash
python3 decode_mbr.py <file.coer> [--type {SaeJ3287Data|SaeJ3287Mbr}]
```

| Argument | Default | Notes |
|----------|---------|-------|
| `file` | — | Input `.coer` file (required) |
| `--type` | `SaeJ3287Data` | Use `SaeJ3287Mbr` for raw MBR files without the version wrapper; auto-detected if first byte ≠ `0x01` |

**Examples:**

```bash
python3 decode_mbr.py coer/out_plaintext.coer
python3 decode_mbr.py coer/jason_mbr.coer --type SaeJ3287Mbr
```

## Process Flow

```
┌──────────────────────────────────────────────────────┐
│  0. BUILD TOOL  (one-time)                           │
│                                                      │
│  git clone https://github.com/mouse07410/asn1c       │
│  cd asn1c && autoreconf -iv && ./configure           │
│  make && sudo make install                           │
│         │                                            │
│  asn1c binary available on PATH                      │
└──────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  1. SCHEMA TRANSLATION (one-time / on schema change) │
│                                                      │
│  J3287_ASN/*.asn   (parameterized ASN.1)             │
│         │                                            │
│  translate_asn1.py (idempotent)                      │
│         │                                            │
│  J3287_ASN_flat/*.asn  (non-parameterized)           │
└──────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  2. C CODE GENERATION (one-time / on schema change)  │
│                                                      │
│  compile_asn1.sh                                     │
│    → runs asn1c -fcompound-names on J3287_ASN_flat/  │
│    → post-processes IOC CLASS alias issues           │
│    → installs stubs/C-2ENT.{h,c}                    │
│         │                                            │
│  c_code/   (~380 generated .c/.h files)              │
└──────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  3. LIBRARY COMPILATION  ./build_asn_lib.sh          │
│                                                      │
│    → scans c_code/*.h for asn_TYPE_descriptor_t      │
│    → generates c_code/pdu_table.c (PDU dispatch)     │
│    → gcc -shared -fPIC c_code/*.c                    │
│         │                                            │
│  lib/libdecode.so                                    │
└──────────────────────────────────────────────────────┘
         │
         ├─────────────────────┐
         ▼                     ▼
┌─────────────────┐   ┌─────────────────────────────────┐
│  4. ENCODING    │   │  5. DECODING                    │
│  create_mbr.py  │   │  decode_mbr.py                  │
│                 │   │                                 │
│  BSM (.coer)    │   │  SaeJ3287Data or                │
│       │         │   │  SaeJ3287Mbr (.coer)            │
│  ① decode BSM   │   │       │                         │
│    (generationTime)│  │  ① libdecode.so: OER → JER    │
│  ② build MBR    │   │  ② enrich open types:           │
│    LongAcc obs  │   │    · AidSpecificReport.content  │
│  ③ wrap/sign/   │   │      → AsrBsm                   │
│    encrypt      │   │    · observations SEQUENCE OF   │
│       │         │   │      ANY → typed obs dicts      │
│  out_*.coer     │   │    · v2xPdus ANY →              │
└─────────────────┘   │      Ieee1609Dot2Data           │
                      │       │                         │
                      │  JSON (stdout)                  │
                      └─────────────────────────────────┘
```

## Repository Layout

```
ASN1/
├── J3287_ASN/              Parameterized ASN.1 source schemas
├── J3287_ASN_flat/         Flattened schemas (output of translate_asn1.py)
├── asn1c/                  ASN.1 compiler with custom OER/JER skeletons
├── c_code/                 Generated C code + handwritten shim (decode_shim.{h,c})
├── stubs/                  C-2ENT stub (ANY replacement for IOC CLASS open types)
├── lib/                    libdecode.so (compiled by build_asn_lib.sh)
├── coer/                   Sample COER files and decoded JSON outputs
├── create_mbr.py           MBR encoder
├── decode_mbr.py           MBR decoder
├── translate_asn1.py       Parameterized → flat ASN.1 translator
├── build_asn_lib.sh        Compile c_code/ → lib/libdecode.so
├── compile_asn1.sh         Run asn1c on J3287_ASN_flat/ → c_code/
└── requirements.txt        Python dependencies
```

## Key Standards

| Standard | Scope |
|----------|-------|
| SAE J3287 | Misbehavior report format (`SaeJ3287Data`, `SaeJ3287Mbr`) |
| ETSI TS 103 759 | Application-Specific Report structure, observation types |
| IEEE 1609.2 | V2X security: certificates, signatures, encryption (`Ieee1609Dot2Data`) |
| ETSI TS 103 097 | Certificate profile and management |

## Observation Types (hard-coded)

`create_mbr.py` currently generates a single observation:

| Field | Value | Meaning |
|-------|-------|---------|
| `tgtId` | `5` | `c-BsmTgt-LongAccCommon` |
| `obsId` | `4` | `LongAcc-ValueTooLarge` |
| `obs` | *(empty)* | NULL payload |

The BSM itself is included as evidence in `v2xPduEvidence` (`type=2`, `c-ObsPdu-ieee1609Dot2Data`).

