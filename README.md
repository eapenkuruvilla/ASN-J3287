# SAE J3287 Misbehavior Report (MBR) Toolkit

Tools for building and decoding Vehicle-to-Everything (V2X) Misbehavior Reports (MBRs) per SAE J3287 and ETSI TS 103 759. Given a Basic Safety Message (BSM) in COER format, the toolkit produces a standards-compliant `SaeJ3287Data` message (plaintext, signed, or signed+encrypted) and can decode any such message back to human-readable JSON.

## Requirements

| Tool | Purpose |
|------|---------|
| Python 3.8+ | `create_mbr.py`, `encode_mbr.py`, `decode_mbr.py`, `asn1c_lib.py`, `decode_j2735.py` |
| `cryptography` (pip) | ECDSA signing, AES-CCM encryption |
| `requests` (pip) | ISS API calls (sign, encrypt, validate, decrypt) and IP geolocation |
| `pycrate` (pip) | J2735 UPER decoding (`decode_j2735.py`) |
| `gcc` | Compile `lib/libasn1c.so` |
| `lib/libasn1c.so` | Required at runtime by `create_mbr.py` and `decode_mbr.py` |
| `asn/J2735ASN_202409/` | J2735 ASN.1 schema files (required by `decode_j2735.py`) |

Install Python dependencies:

```bash
pip install -r requirements.txt
```

See the [Process Flow](#process-flow) section for one-time setup steps (building `asn1c` and compiling `lib/libasn1c.so`).

## Usage

### Encode — `create_mbr.py`

Builds a `SaeJ3287Data` COER file from an input BSM. Always produces `out_plaintext.coer`; signed and encrypted variants require the corresponding key material.

```bash
python3 create_mbr.py \
    --bsm <file.coer>               # Input Ieee1609Dot2Data BSM (required)
    [--certs-dir <path>]            # SCMS bundle directory (RSU or pseudonym)
                                    #   RSU bundle: auto-selects valid rsu-*/downloadFiles/ cert
                                    #   Pseudonym bundle: auto-detected by download/ subdir;
                                    #     applies butterfly key expansion (sgn_expnsn.key)
                                    #   uses local ECQV key reconstruction for signing
    [--sign-api-key <token>]        # ISS virtual-device x-virtual-api-key token
                                    #   signs via ISS API — mutually exclusive with --certs-dir
    [--sign-api-url <url>]          # ISS DMS base URL for signing and API-based encryption (default: https://api.dm.preprod.v2x.isscms.com)
    [--recipient-cert <file>]       # Recipient MA cert file (COER) — enables out_ste.coer (certRecipInfo, preferred)
    [--recipient-pub <hex>]         # Recipient P-256 public key (64–65 bytes hex) — enables out_ste.coer (no cert → non-compliant P1/recipientId)
    [--encrypt-api-key <token>]     # ISS virtual-device token for API-based encryption (rekRecipInfo)
    [--encrypt-recipient-id <id>]   #   Device ID to encrypt to (required with --encrypt-api-key)
    [--out-dir coer/]               # Output directory (default: coer/)
    [--psid 38]                     # PSID for headerInfo (default: 38 = MBR)
    [--lat <int>]                   # observationLocation latitude in 1e-7 deg units (default: IP geolocation)
    [--lon <int>]                   # observationLocation longitude in 1e-7 deg units (default: IP geolocation)
    [--elev 0]                      # observationLocation elevation (default: 0)
```

**Output files** (written to `--out-dir`):

| File | Type | Requires |
|------|------|---------|
| `out_plaintext.coer` | `SaeJ3287Data { version=1, content: plaintext(SaeJ3287Mbr) }` | always |
| `out_signed.coer` | `SaeJ3287Data { version=1, content: signed(Ieee1609Dot2Data) }` | `--certs-dir` or `--sign-api-key` |
| `out_ste.coer` | `SaeJ3287Data { version=1, content: sTE(Ieee1609Dot2Data) }` | (`--certs-dir` or `--sign-api-key`) + (`--recipient-cert` or `--recipient-pub` or `--encrypt-api-key` + `--encrypt-recipient-id`) |

**Example — plaintext only:**

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --out-dir coer/
```

**Example — signed via ISS virtual device API:**

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --sign-api-key "<x-virtual-api-key token>" \
    --out-dir coer/
```

> **Note:** The ISS API adds `generationTime` and `expiryTime` to `headerInfo`, which violates the `SaeJ3287Mbr-Signed` absence constraints. The ISS validate API accepts this, but strict ASN.1 decoders (e.g. the ISS C# decoder) will reject it with "Absence constraint violated". Use local ECQV signing (`--certs-dir`) to produce a fully conformant `out_signed.coer`.

**Example — signed with local ECQV key reconstruction (ISS RSU bundle):**

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --certs-dir certs/ISS/application/e0c324c643aca860 \
    --out-dir coer/
```

The currently valid RSU certificate is selected automatically from `rsu-*/downloadFiles/`.

**Example — signed with local ECQV + butterfly expansion (ISS pseudonym/OBU bundle):**

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --certs-dir certs/ISS/pseudonym/9b09e9e5e5c99a9e \
    --out-dir coer/
```

**Example — signed with local ECQV key reconstruction (SaeSol RSU bundle):**

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --certs-dir certs/SaeSol/application/b831f0c528d4c4a3 \
    --out-dir coer/
```

**Example — signed with local ECQV + butterfly expansion (SaeSol pseudonym/OBU bundle):**

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --certs-dir certs/SaeSol/pseudonym/63efb57ac6280708 \
    --out-dir coer/
```

The bundle layout is detected automatically (`download/` subdir present → pseudonym). The currently valid pseudonym cert is selected; butterfly key expansion is applied using `sgn_expnsn.key`.

**Signing methods — confirmed status:**

| Method | Flag | Bundle / endpoint | ISS API validation |
|--------|------|-------------------|--------------------|
| ISS virtual device API | `--sign-api-key` | `api.dm.preprod.v2x.isscms.com` | ✅ `success` |
| Local ECQV — ISS RSU bundle | `--certs-dir certs/ISS/application/e0c324c643aca860` | `rsu-*/downloadFiles/` (raw scalar) | ✅ `success` |
| Local ECQV — ISS pseudonym bundle | `--certs-dir certs/ISS/pseudonym/9b09e9e5e5c99a9e` | `download/{i}/{i}_{j}.cert` + butterfly | ✅ `success` |
| Local ECQV — SaeSol RSU bundle | `--certs-dir certs/SaeSol/application/b831f0c528d4c4a3` | `rsu-*/downloadFiles/` (raw scalar) | ⬜ untested |
| Local ECQV — SaeSol pseudonym bundle | `--certs-dir certs/SaeSol/pseudonym/63efb57ac6280708` | `download/{i}/{i}_{j}.cert` + butterfly | ⬜ untested |

Certificates under `certs/ISS/` were downloaded from the ISS pre-production SCMS; certificates under `certs/SaeSol/` from the SaeSol SCMS. MBRs are generated by RSUs using application certificates stored under `certs/<Provider>/application/<OrgId>/<rsu-N>/`.

**RSU application certificate store layout**

| Path | Content |
|------|---------|
| `certchain/0` | Enrollment certificate |
| `certchain/1` | Issuer of cert 0 (Enrollment Certificate Authority) |
| `certchain/2` | Issuer of cert 1 (Intermediate Certificate Authority) |
| `certchain/s` | Private key reconstruction value for the enrollment signing key |
| `trustedcerts/` | Root of trust: `rca`, `pca`, `ica`, `eca`, `ra` |
| `enr_sign.prv` | Enrollment private signing key |
| `dwnl_sgn.priv` | Base signing key `sk_base` (raw 32-byte big-endian P-256 scalar). Used in ECQV reconstruction: `kU = sk_base` (RSU) or `kU = (sk_base + f_k(i,j)) mod n` (pseudonym with butterfly expansion). |
| `dwnl_enc.priv` | Base encryption key (raw 32-byte scalar; used for decrypting incoming messages). |
| `downloadFiles/<HashedId8>.cert` | Operational application certificate for the RSU (implicit / ECQV) |
| `downloadFiles/<HashedId8>.s` | Private key reconstruction value `r` (raw 32-byte big-endian scalar). Final signing key = `(r + e × kU) mod n` where `e = SHA-256(SHA-256(COER(TBS)) ∥ SHA-256(issuer_cert))` and `kU = sk_base` (from `dwnl_sgn.priv`). |

**Certificate structure**

The `<OrgId>` directory is the HashedId8 of the organisation/device enrollment certificate (`e0c324c643aca860` for ISS, `b831f0c528d4c4a3` for SaeSol). Each `rsu-N/` subdirectory holds credentials for one RSU.

Chain of trust (bottom → top):

```
downloadFiles/<HashedId8>.s     32-byte private key reconstruction value r (NOT the final key)
downloadFiles/<HashedId8>.cert  Authorization Ticket (AT / application cert, 80 bytes)
                                    signed by ↓
trustedcerts/pca                PCA (issues both RSU application and OBU pseudonym certs)
                                    signed by ↓
trustedcerts/ica                Intermediate Certificate Authority
                                    signed by ↓
trustedcerts/rca                Root CA (offline trust anchor)
```

For RSUs, `downloadFiles/<HashedId8>.cert` and `downloadFiles/<HashedId8>.s` are the operational signing credentials — the `certchain/` contents are a packaging artifact of the SCMS download format and are not used. RSUs do not rotate certificates (rotation applies to OBUs only).


**Implicit certificates:** The ISS SCMS issues **implicit certificates** (ECQV — Elliptic Curve Qu-Vanstone) for North American V2X per IEEE 1609.2. Unlike explicit certificates which carry a public key and CA signature as separate fields, an implicit cert superimposes them into a single reconstruction value — resulting in the compact 79–80 byte size seen here. The receiver reconstructs the sender's public key from the cert and implicitly verifies it in one step.

ECQV key reconstruction formula (IEEE 1609.2 §5.3.2 / SCMS profile):
```
tbs_coer = COER(cert.toBeSigned)
e        = SHA-256( SHA-256(tbs_coer) ∥ SHA-256(issuer_cert_coer) )  mod n
kU       = (sk_base + f_k(i, j))  mod n     ← butterfly expansion for pseudonym bundles
                                              (f_k is AES-ECB based KDF over sgn_expnsn.key)
dU       = (r + e × kU)  mod n              ← final signing scalar
```

**Butterfly Key Expansion** is used to batch-provision OBU pseudonym certificate pools from a single base key (`dwnl_sgn.priv` + `sgn_expnsn.key`). Each (i, j) pair corresponds to a leaf cert in `download/{i}/{i}_{j}.cert`. Not applicable to RSU application certs. See [All You Need to Know About V2X PKI Certificates](https://autocrypt.io/v2x-pki-certificates-butterfly-key-expansion-implicit-certificates/) for background.

`create_mbr.py` auto-detects pseudonym vs RSU bundles and applies butterfly expansion accordingly.

### Obtaining the MA Certificate from an RA (IEEE 1609.2.1 §6.3.5.13)

IEEE 1609.2.1-2022 §6.3.5.13 defines a standard REST endpoint for downloading the MA certificate:

```
GET https://{ra-host}/v3/ma-certificate?psid={hex-psid}
```

where `{hex-psid}` is the minimal-length hex encoding of the PSID for the application being reported (e.g. `20` for BSM, PSID 32 = 0x20).

**Example (ISS pre-production RA):**

```bash
curl "https://ra.preprod.v2x.isscms.com/v3/ma-certificate?psid=20" \
    -o certs/ma_keys/iss_ma_public_key.cert
```

The response body is the raw COER-encoded `Certificate` (binary, `application/octet-stream`).

**SaeSol RA (`ra.v2x-scms.saesoltech.io`) — deployment status:**

| Endpoint | Status |
|----------|--------|
| `GET /v3/ma-certificate?psid=<hex>` | **Available** — returns 202-byte COER `Certificate` |
| `GET /v3/ra-certificate` | Available — returns RA's own certificate |
| `GET /v3/certificate-management-info-status` | Available — returns CRL/CTL/MA status (no cert payload) |

The `ma-certificate` endpoint is now available. To refresh the cert:

```bash
curl https://ra.v2x-scms.saesoltech.io/v3/ma-certificate?psid=20 \
    -o certs/ma_keys/saesol_ma_public_key.cert
```

Unauthenticated access is permitted by both ISS pre-production and SaeSol (no auth header required). Standard authentication options defined in §6.3.5.13:

| Level | Option |
|-------|--------|
| Session | TLS 1.2/1.3 with X.509 client cert, or ISO/TS 21177 |
| Web API | OAuth 2.0 Bearer token (`Authorization: Bearer <token>`) |
| SCMS REST v3 | Enrollment certificate or X.509 |

Use `--recipient-cert` with local ECQV signing to produce a fully conformant signed+encrypted MBR:

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --certs-dir certs/ISS/application/e0c324c643aca860 \
    --recipient-cert certs/ma_keys/iss_ma_public_key.cert \
    --out-dir coer/
```

Or with the SaeSol MA cert:

```bash
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --certs-dir certs/ISS/application/e0c324c643aca860 \
    --recipient-cert certs/ma_keys/saesol_ma_public_key.cert \
    --out-dir coer/
```

> **Note:** `--sign-api-key` may be substituted for `--certs-dir` above, but the ISS API adds `generationTime`/`expiryTime` to `headerInfo` making the inner signed payload non-conformant with `SaeJ3287Mbr-Signed` absence constraints.

### Validate Signed MBR — `validate_mbr.py`

Validates a signed MBR against the ISS SCMS virtual device API
(`POST /virtual-device/validate`).  Accepts either a `SaeJ3287Data` file
(extracts the inner `Ieee1609Dot2Data` automatically) or a bare
`Ieee1609Dot2Data` file.

```bash
python3 validate_mbr.py [file] --api-key <token> [--url <base_url>] [--dump-response]
```

| Argument | Default | Notes |
|----------|---------|-------|
| `file` | `coer/out_signed.coer` | COER file to validate |
| `--api-key` | — | `x-virtual-api-key` token (required); virtual device must have PSID 38 in its enrollment |
| `--url` | `https://api.dm.preprod.v2x.isscms.com` | ISS DMS API base URL |
| `--dump-response` | off | Print the raw JSON response body from the ISS API (useful for troubleshooting signer type, cert fields, etc.) |

**Validation status values:**

| Status | Meaning |
|--------|---------|
| `valid` / `success` | Signature verified; certificate chain recognized by ISS SCMS |
| `failure` | Cryptographic verification failed — signature does not match cert |
| `not_signed` | Message not recognized as a signed `Ieee1609Dot2Data` |
| `unrecognized_issuer` | Signer cert chain not known to ISS SCMS |
| `unknown_cert` | Digest signer used but digest unknown to ISS |

On failure the script always prints the full API response and a decoded dump of the
`Ieee1609Dot2Data` that was sent. On success, use `--dump-response` to see the full
response body (including signer details, cert fields, and any ISS-decoded representation).

**Examples:**

```bash
python3 validate_mbr.py coer/out_signed.coer --api-key <token>
python3 validate_mbr.py coer/out_signed.coer --api-key <token> --dump-response
```

### Decrypt sTE MBR — `decrypt_mbr.py`

Decrypts a signed-then-encrypted MBR via the ISS SCMS virtual device API
(`POST /virtual-device/decrypt`).  Accepts either a `SaeJ3287Data` file
(extracts `content.sTE` automatically) or a bare `Ieee1609Dot2Data` file.

> **Recipient type constraint:** `POST /virtual-device/decrypt` requires `rekRecipInfo`
> recipients.  Messages encrypted to an MA certificate (`certRecipInfo`, produced by
> `--recipient-cert`) cannot be decrypted via this API — those require the MA's
> private key.  To produce a `rekRecipInfo`-encrypted file for round-trip testing,
> use `--encrypt-api-key` + `--encrypt-recipient-id` in `create_mbr.py`.

```bash
python3 decrypt_mbr.py [file] --api-key <token> [--url <base_url>]
```

| Argument | Default | Notes |
|----------|---------|-------|
| `file` | `coer/out_ste.coer` | COER file to decrypt |
| `--api-key` | — | `x-virtual-api-key` token (required); must be the device the message was encrypted to |
| `--url` | `https://api.dm.preprod.v2x.isscms.com` | ISS DMS API base URL |

**Round-trip test (create + decrypt):**

```bash
# 1. Create sTE encrypted to the virtual device's own key (rekRecipInfo)
python3 create_mbr.py \
    --bsm coer/bad_accel_iss_key.coer \
    --sign-api-key "<token>" \
    --encrypt-api-key "<token>" \
    --encrypt-recipient-id "<device-id>" \
    --out-dir coer/

# 2. Decrypt it back
python3 decrypt_mbr.py coer/out_ste.coer --api-key "<token>"
```

### Decode J2735 BSM — `decode_j2735.py`

Decodes a J2735 `MessageFrame` from a UPER hex string (e.g. the `unsecuredData` field in `decode_mbr.py` output) to JSON on stdout.

```bash
python3 decode_j2735.py <hex>
```

**Example** (hex copied from `decode_mbr.py` output):

```bash
python3 decode_j2735.py 001480A35FE73C47D19362A716192D96743CCBAB4D038388...
```

Note: J2735 schema compilation runs on every invocation and takes a few seconds.

### Decode MBR — `decode_mbr.py`

Decodes a COER file to JSON on stdout, recursively expanding all open-type (`ANY`) fields.

```bash
python3 decode_mbr.py <file.coer> [--type {SaeJ3287Data|SaeJ3287Mbr}]
```

| Argument | Default | Notes |
|----------|---------|-------|
| `file` | — | Input `.coer` file (required) |
| `--type` | `SaeJ3287Data` | Use `SaeJ3287Mbr` for raw MBR files without the version wrapper; auto-detected if first byte ≠ `0x01` |

**Recursive decoding** — the following fields are decoded automatically at all nesting levels:

| Field | Decoded as |
|-------|-----------|
| `AidSpecificReport.content` | `AsrBsm` |
| `AsrBsm.observations[].observations[]` | `MbSingleObservation-BsmLongAcc` / `MbSingleObservation-BsmSecurity` |
| `V2xPduStream.v2xPdus[]` | `Ieee1609Dot2Data` (when `type=2`) |
| `SaeJ3287MbrSec.signed` → `unsecuredData` | `SaeJ3287Mbr` (recursive) |

**Examples:**

```bash
python3 decode_mbr.py coer/out_plaintext.coer
python3 decode_mbr.py coer/out_signed.coer
```

## Process Flow

```
┌──────────────────────────────────────────────────────┐
│  0. BUILD TOOL  (one-time)                           │
│                                                      │
│  # Clone one level above this repo                   │
│  # This fork is actively maintained and supports     │
│  # newer features such as IOC (Information Object    │
│  # Classes) not available in the upstream original.  │
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
│  asn/J3287_ASN/*.asn   (parameterized ASN.1)         │
│         │                                            │
│  translate_asn1.py (idempotent)                      │
│         │                                            │
│  asn/J3287_ASN_flat/*.asn  (non-parameterized)       │
└──────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  2. C CODE GENERATION (one-time / on schema change)  │
│                                                      │
│  compile_asn1.sh                                     │
│    → runs asn1c -fcompound-names on asn/J3287_ASN_flat/ │
│    → post-processes IOC CLASS alias issues           │
│    → installs stubs/*.{h,c} into asn1c_code/             │
│         │                                            │
│  asn1c_code/   (~380 generated .c/.h files)              │
└──────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  3. LIBRARY COMPILATION  ./build_asn_lib.sh          │
│                                                      │
│    → scans asn1c_code/*.h for asn_TYPE_descriptor_t      │
│    → generates asn1c_code/pdu_table.c (PDU dispatch)     │
│    → gcc -shared -fPIC asn1c_code/*.c                    │
│         │                                            │
│  lib/libasn1c.so                                    │
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
│    (generationTime)│  │  ① libasn1c.so: OER → JER    │
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
├── asn/                    ASN.1 schema files
│   ├── J3287_ASN/          Parameterized ASN.1 source schemas
│   ├── J3287_ASN_flat/     Flattened schemas (output of translate_asn1.py)
│   ├── J2735ASN_202409/    J2735 schemas (used by decode_j2735.py)
│   └── ieee1609.2/         IEEE 1609.2 schemas
├── asn1c_code/                 Generated C code (populated by compile_asn1.sh)
├── stubs/                  Handwritten C files copied into asn1c_code/ by compile_asn1.sh:
│                             C-2ENT.{h,c}      — ANY replacement for IOC CLASS open types
│                             decode_shim.{h,c} — OER→JER decoder entry point for libasn1c.so
├── lib/                    libasn1c.so (compiled by build_asn_lib.sh)
├── certs/                  SCMS certificate store
│   ├── ISS/                ISS pre-production SCMS certificates
│   │   ├── application/    RSU application certificate bundles
│   │   │   └── e0c324c643aca860/   OrgId (HashedId8 of enrollment cert)
│   │   │       └── rsu-N/  One directory per RSU (rsu-0 … rsu-19)
│   │   │           ├── certchain/    SCMS packaging artifact (not used directly)
│   │   │           ├── trustedcerts/ Root of trust (rca, pca, ica, eca, ra)
│   │   │           ├── downloadFiles/ Operational signing cert and key
│   │   │           ├── enr_sign.prv  Enrollment signing key
│   │   │           ├── dwnl_sgn.priv Download signing key
│   │   │           └── dwnl_enc.priv Download encryption key
│   │   └── pseudonym/      OBU pseudonym certificate bundles
│   │       └── 9b09e9e5e5c99a9e/
│   │           ├── download/{i}/{i}_{j}.cert  Pseudonym leaf certs
│   │           ├── dwnl_sgn.priv  Base signing key
│   │           └── sgn_expnsn.key Butterfly expansion key
│   ├── SaeSol/             SaeSol SCMS certificates
│   │   ├── application/    RSU application certificate bundles
│   │   │   └── b831f0c528d4c4a3/   OrgId
│   │   │       └── rsu-N/  One directory per RSU (rsu-0, rsu-1)
│   │   │           ├── certchain/    SCMS packaging artifact (not used directly)
│   │   │           ├── trustedcerts/ Root of trust (rca, pca, ica, eca, ra)
│   │   │           ├── downloadFiles/ Operational signing cert and key
│   │   │           ├── enr_sign.prv  Enrollment signing key
│   │   │           ├── dwnl_sgn.priv Download signing key
│   │   │           └── dwnl_enc.priv Download encryption key
│   │   └── pseudonym/      OBU pseudonym certificate bundles
│   │       └── 63efb57ac6280708/
│   │           ├── download/{i}/{i}_{j}.cert  Pseudonym leaf certs
│   │           ├── dwnl_sgn.priv  Base signing key
│   │           └── sgn_expnsn.key Butterfly expansion key
│   └── ma_keys/            Misbehavior Authority certificates (recipient keys for encryption)
│       ├── iss_ma_public_key.cert   ISS pre-production MA certificate
│       └── saesol_ma_public_key.cert  SaeSol MA certificate (COER)
├── coer/                   Sample COER files and decoded JSON outputs
├── asn1c_lib.py            ctypes interface to lib/libasn1c.so (decode_oer / encode_jer)
├── encode_mbr.py           MBR/1609.2 message construction (build_mbr_from_bsm, build_signed_1609, build_encrypted_1609)
├── decode_mbr.py           MBR decoder — enrichment helpers + CLI
├── create_mbr.py           CLI entry point — cert selection, geolocation, main()
├── validate_mbr.py         Validate signed MBR via ISS SCMS virtual device API
├── decrypt_mbr.py          Decrypt sTE MBR via ISS SCMS virtual device API
├── decode_j2735.py         J2735 MessageFrame UPER decoder
├── translate_asn1.py       Parameterized → flat ASN.1 translator
├── build_asn_lib.sh        Compile asn1c_code/ → lib/libasn1c.so
├── compile_asn1.sh         Run asn1c on asn/J3287_ASN_flat/ → asn1c_code/
└── requirements.txt        Python dependencies
```

## IEEE 1609.2-2022 Conformance

Verified against IEEE Std 1609.2-2022. The local ECQV signing path (`--certs-dir`, `out_signed.coer`) is fully conformant. The ISS API signing path (`--sign-api-key`) adds `generationTime`/`expiryTime` to `headerInfo` and is not conformant with `SaeJ3287Mbr-Signed` absence constraints. The encrypted path (`out_ste.coer`) is conformant when `--recipient-cert` is used; using `--recipient-pub` alone produces non-compliant `recipientId` and KDF2 P1 values.

### Conformant

| Item | Standard ref |
|------|-------------|
| Signing hash: `SHA256(SHA256(tbsData) ‖ SHA256(cert))` | §5.3.1.2.2 |
| Data input = COER(ToBeSignedData) | §6.3.6 |
| PSID encoding for values < 128 (PSIDs 32 and 38) | §6.3.10 |
| Time32/Time64 TAI epoch + 37 leap-second offset | §6.3.11 |
| HashedId8 = `SHA256(cert)[-8:]` | §6.3.33 |
| EcdsaP256Signature: r as `x-only` (CHOICE index 0), s as 32-byte OCTET STRING | §6.3.38 |
| Compressed-point CHOICE indices 2 / 3 (`compressed-y-0` / `compressed-y-1`) | §6.3.23 |
| ECIES KDF2 output split: K\_enc = 16 B, K\_mac = 32 B (48 B total) | §5.3.5.1(c/d) |
| ECIES MAC = `HMAC-SHA256(K_mac, c)[0:16]` (non-DHAES: MAC over `c` only, not `V ‖ c`) | §5.3.5.1(e) |
| AES-128-CCM: tag = 16 B, nonce = 12 B, no AAD | §5.3.8 |
| SignedData field order (hashId, tbsData, signer, signature) | §6.3.4 |
| SignerIdentifier = `certificate` (CHOICE index 1) | §6.3.31 |
| RecipientInfo = `certRecipInfo` (CHOICE index 2) | §6.3.42 |

### Known Issues

| # | Issue | Severity | Affected output |
|---|-------|----------|----------------|
| 1 | **ECIES P1 / recipientId require cert bytes** — when `--recipient-pub` is used without `--recipient-cert`, KDF2 P1 = `b""` and recipientId = 8 zero bytes. Use `--recipient-cert <ma.cert>` to produce standard-compliant output. | Low (use `--recipient-cert`) | `out_ste.coer` |

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
