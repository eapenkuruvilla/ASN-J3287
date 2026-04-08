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
downloadFiles/<HashedId8>.cert  Authorization Ticket (AT / application cert)
                                    ISS: 80 bytes (implicit/ECQV)
                                    SaeSol: 107 bytes (explicit)
                                    signed by ↓
trustedcerts/pca                PCA (issues both RSU application and OBU pseudonym certs)
                                    signed by ↓
trustedcerts/ica                Intermediate Certificate Authority
                                    signed by ↓
trustedcerts/rca                Root CA (offline trust anchor)
```

For RSUs, `downloadFiles/<HashedId8>.cert` and `downloadFiles/<HashedId8>.s` are the operational signing credentials — the `certchain/` contents are a packaging artifact of the SCMS download format and are not used. RSUs do not rotate certificates (rotation applies to OBUs only).

**`downloadFiles/` naming convention:**

| Provider | Filename convention | Cert size |
|----------|---------------------|-----------|
| ISS | SCMS-assigned ID (not `SHA-256(cert)[-8:]`) | 80 bytes |
| SaeSol | `SHA-256(cert)[-8:]` (standard IEEE 1609.2 HashedId8) | 107 bytes |

**Identifying the certificate provider from a COER file**

A signed `Ieee1609Dot2Data` (BSM or MBR) can carry the signer's certificate in one of two ways:

| `SignerIdentifier` CHOICE | Content | Provider identifiable? |
|--------------------------|---------|------------------------|
| `certificate` | Full cert embedded — contains `issuer.sha256AndDigest` (PCA HashedId8) | Yes — scan raw bytes for known CA HashedId8 |
| `digest` | 8-byte `HashedId8` of the leaf cert only | **No** — two-step: digest → cached cert → PCA HashedId8 → provider |

`digest` is `SHA-256(leaf_pseudonym_cert)[-8:]`. It identifies a specific leaf cert, not a provider. Provider identity is one level up in the chain:

```
signer: digest  →  HashedId8 of OBU pseudonym cert
                        │  (requires cached full cert)
                        ↓
                   cert.issuer.sha256AndDigest  =  HashedId8 of PCA
                        │
                        ↓  (PCA HashedId8 lookup table below)
                   ISS or SaeSol
```

When a full-cert BSM is received the RSU should cache both the cert bytes and the derived provider against the leaf cert's HashedId8, so that subsequent `digest`-only BSMs from the same OBU resolve to a provider in one step.

When a `certificate` BSM is received, scan the raw COER bytes for the known PCA/ICA/RCA HashedId8 values:

| HashedId8 | Provider | CA role |
|-----------|----------|---------|
| `1631AFB5FC255D0F` | ISS | PCA |
| `7F0838125C75521B` | ISS | ICA |
| `93232614EE5E6F5B` | ISS | RCA |
| `D2EC3E78F493CF68` | SaeSol | PCA |
| `36F8FFD2C4DA2747` | SaeSol | ICA |
| `09F453B62DE0813A` | SaeSol | RCA |

`bad_accel_iss_key.coer` was confirmed ISS-signed: `1631AFB5FC255D0F` (ISS PCA) found at offset `0x0c1`.

**BSM cert hydration for MBR evidence**

The MA requires the full certificate of the misbehaving device in the MBR evidence to perform remediation (e.g. certificate revocation). If the misbehaving BSM carries only a `digest`, the RSU must substitute the full cert before embedding it as evidence:

1. When any BSM with `signer: certificate` is received, cache `HashedId8 → (cert_bytes, provider)`.
2. When building an MBR, if the evidence BSM has `signer: digest`, look up the HashedId8 in the cache and replace `digest` with `certificate`.
3. This substitution is **signature-preserving** — `SignerIdentifier` is outside the signed scope (`ToBeSignedData`) in IEEE 1609.2.
4. If the cache has no entry for the digest (misbehavior detected on the very first BSM from that OBU), embed the BSM as-is; the MA will need to retrieve the cert through other means.

> **Not yet implemented** — `create_mbr.py` currently embeds the BSM evidence as-is without cert hydration.

**Implicit certificates:** Both ISS and SaeSol issue **implicit certificates** (ECQV — Elliptic Curve Qu-Vanstone) per IEEE 1609.2. Unlike explicit certificates which carry a public key and CA signature as separate fields, an implicit cert superimposes them into a single reconstruction value. The receiver reconstructs the sender's public key from the cert and implicitly verifies it in one step.

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

**MA HashedId8 identifiers (`recipientId` in `certRecipInfo`)**

The `recipientId` field in an encrypted MBR is `SHA-256(ma_cert)[-8:]` — the HashedId8 of the MA certificate the message was encrypted to. An RA can extract this field from the raw COER without decrypting the payload and use it to route the MBR to the correct MA, including across SCMS providers.

| `recipientId` | MA |
|---------------|----|
| `A08430C61A34C7E8` | ISS pre-production MA |
| `CE248AFFB5F88ACD` | SaeSol MA |

**Cross-provider routing:** The signer's SCMS (identified by the CA HashedId8 in the cert chain — see [Identifying the certificate provider](#identifying-the-certificate-provider-from-a-coer-file)) and the MA's SCMS (identified by `recipientId`) can differ. An RA receiving an MBR-sTE should check `recipientId` against its known MA registry: if the `recipientId` matches a foreign MA, the RA forwards the MBR to that MA rather than its own.

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

### pycrate Schema Compatibility — `test_pycrate_schema.py`

Verifies that the `pycrate` library can compile and use all 29 schemas in `asn/J3287_ASN_flat/`, then attempts OER round-trip encode/decode on the key PDU types.

```bash
python3 test_pycrate_schema.py
```

**Result:** `pycrate` **CAN** handle the J3287_ASN_flat schema after the preprocessing workarounds described below.  All 9 target PDUs are found and both OER decode tests pass.

#### pycrate Compatibility Findings

The schemas use several advanced ASN.1 features that pycrate does not fully support.  `test_pycrate_schema.py` preprocesses every schema file before handing it to pycrate, applying the following transformations (all semantically safe for encoding/decoding purposes):

| # | Symptom | Root cause | Fix applied |
|---|---------|-----------|-------------|
| 1 | `AssertionError` in `_path_trunc(2)` | `(CONSTRAINED BY { ... })` blocks nested inside `WITH COMPONENTS` constraints crash pycrate's constraint parser | Strip every `(CONSTRAINED BY { … })` token; the bodies are purely documentary prose or commented-out structure descriptions |
| 2 | `AssertionError` in `_path_trunc(2)` | `(TypeName (SIZE (N)))` in a `WITH COMPONENTS` component constraint: pycrate creates an ObjProxy for the type and then tries `_parse_const_size` on it, failing a depth assertion | Strip the inner `(SIZE (N))` — reduce `(TypeName (SIZE (N)))` to `(TypeName)` |
| 3 | `AssertionError` in `_path_trunc(2)` | `fieldName (SIZE(N))` on a lowercase component inside `WITH COMPONENTS`: same ObjProxy/size path failure as above | Strip the `(SIZE(N))` suffix from lowercase field names in constraints |
| 4 | `invalid ident in WITH COMPONENTS constraint` | `(WITH COMPONENT (Type))` (singular, for `SEQUENCE OF` elements) leaves a residual `^(SIZE(N))` token after stripping that pycrate cannot parse | Strip the entire `(WITH COMPONENT (…))` token; also strip any dangling `(^(SIZE(N)))` intersection wrapper left behind |
| 5 | `missing mandatory components in WITH COMPONENTS` | Some schemas omit the `…,` partial indicator from `WITH COMPONENTS {` blocks that list only a subset of fields | Insert `…,` before the first component in any `WITH COMPONENTS {` block that lacks it |
| 6 | `invalid order of components in WITH COMPONENTS` | `EtsiTs103759Core.asn` `EtsiTs103759Mbr-STE`: the `recipients` field of `EncryptedData` is left as a bare field name after the `CONSTRAINED BY` is stripped, and appears after `ciphertext` (wrong order per the SEQUENCE definition) | Strip the bare `recipients` entry and the preceding comma |
| 7 | `undefined field reference for table constraint` | IOC component-relation constraints of the form `{TypeSet}{@.fieldName}` — pycrate cannot resolve the `@.fieldName` path reference | Strip the `{@.fieldName}` suffix from IOC table constraints |

> **Note on `strip_constrained_by` brace accounting:** Several `CONSTRAINED BY` bodies mix a comment line that opens a `{` (e.g. `-- encryption of … (WITH COMPONENTS {`) with real ASN.1 code that closes it.  The stripper tracks `comment_open_excess` — unmatched `{` inside comment lines — and consumes that many extra `})` after the closing brace to keep the outer structure balanced.  This handles the common pattern in `Ieee1609Dot2Dot1Protocol.asn` where all-comment bodies leave orphaned `})` in the file; for the one case in `EtsiTs103759Core.asn` where real code already balances the comment's `{`, the excess-consuming correctly shifts `recipients` to the right nesting depth (inside `encryptedData WITH COMPONENTS`), after which the ordering fix above removes it.

### asn1c vs pycrate — Which is cleaner?

**Short answer: asn1c is the cleaner production choice; pycrate is useful for Python-native introspection.**

| Criterion | asn1c (`libasn1c.so`) | pycrate |
|---|---|---|
| Schema ingestion | Compiles all 29 schemas **as-is** with no preprocessing | Requires 7 preprocessing transformations; some are fragile |
| ASN.1 feature support | Full: IOC, parameterized types, component-relation constraints, `WITH COMPONENT` (singular) | Partial: IOC table constraints silently stripped; `CONSTRAINED BY` bodies dropped |
| Encoding correctness | Validated against real V2X toolchain; COER/OER byte-accurate | OER round-trip passes for J3287 test PDUs, but stripped constraints mean some semantic checks are skipped |
| Runtime integration | C shared library (`libasn1c.so`) called via `ctypes`; requires a one-time native build | Pure Python; `pip install pycrate` is enough |
| Encode/decode speed | Fast (compiled C) | Slower (Python) |
| Schema introspection from Python | Not directly — requires parsing the generated C headers | Natural: `mod['TypeName']` returns a live object you can walk |
| Best fit | OER encoding/decoding, CI regression testing, production V2X pipelines | Rapid schema exploration, UPER decoding of J2735 BSMs, Python-only environments |

**Practical guidance:**

- Use **asn1c** (via `libasn1c.so` / `encode_mbr.py` / `decode_mbr.py`) as the production encode/decode path.  It handles the full schema without modification and produces byte-accurate COER output.
- Use **pycrate** (via `test_pycrate_schema.py`) as a development-time compatibility probe or when you need to inspect the schema object model from Python.  The preprocessing workarounds are contained in one file and do not affect the schemas on disk.
- `test_pycrate_schema.py` is **not** the production path — it is a schema regression test and exploration tool.

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
├── test_pycrate_schema.py  pycrate schema compatibility test (see pycrate findings)
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

## MA Encryption Key Selection — Cross-PKI Analysis

### The question

When encrypting an MBR (`SaeJ3287Mbr-STE`), **which MA's public key is used** when the misbehaving vehicle's pseudonym certificate was issued by a different SCMS than the reporting device's?

### What the standards say

**ETSI TS 103 759 V2.1.1, §8.2 (MA SSP):**
> *"The reporting ITS-S shall encrypt misbehaviour reports related to a specific ITS-AID **using the MA certificate which contains this specific ITS-AID in the MA SSP structure**."*

**IEEE 1609.2.1-2022, §7.6.2.12 (MaSsp):**
> *"The certificate containing this SSP is the MA Certificate to which an end entity should encrypt misbehavior reports related to the indicated PSIDs."*

**IEEE 1609.2.1-2022, §4.1.5 (Misbehavior authorities):**
> *"A reporting EE will obtain the certificates for the MAs responsible for the PSIDs for which the EE will generate misbehavior reports."*

> *"When the end entity sends the misbehavior reports to the RA, the cleartext metadata in the report contains information that **allows the RA to determine which MA to send the report to** and otherwise does not contain information about the payload of the report."*

**IEEE 1609.2.1-2022, §7.6.3.9 NOTE (MA certificate profile):**
> *"Although the MA certificate is issued by a specific CA, **the MA is authorized to receive misbehavior reports from and about end-entities whose certificates are issued by any CA within the system**. In other words, the issuance of the MA certificate by a specific CA does not imply that that CA has any particular control over the MA."*

### Answer

**The MA is selected by PSID (application type), not by which SCMS issued the misbehaving vehicle's certificate.**

The reporter:
1. Calls `GET /ma-certificate?psid=20` (hex for BSM PSID 32) on **its own RA**
2. Receives the MA certificate whose `MaSsp` lists that PSID
3. Encrypts the signed MBR to **that MA's `encryptionKey`**
4. Submits the ciphertext to **its own RA**, which routes it to the MA based on cleartext metadata in the report

IEEE 1609.2.1 §7.6.3.9 is explicit: an MA's authority is PSID-scoped, not SCMS-scoped. One MA is intended to handle reports about misbehaving vehicles regardless of which SCMS issued their certificates. The reporter's RA acts as the routing gateway.

### Gaps not addressed by the standards

| Gap | What the standard says | What it leaves out |
|---|---|---|
| **Multi-MA deployments** | "Different domains may have different MAs; different MAs may handle reports for different PSIDs" | Does not say which MA wins if two SCMSes each operate their own BSM MA |
| **Cross-SCMS RA routing** | "Cleartext metadata in the report allows the RA to determine which MA to send to" | Does not define what that metadata is or its format — left to application specs |
| **MA certificate discovery** | EE gets MA cert from its own RA via `psid` query | Does not specify how the RA knows which MA is authoritative for vehicles from a foreign SCMS |
| **Linkage data jurisdiction** | MA analyzes reports and may initiate revocation | Does not address the case where the receiving MA does not hold linkage data for the misbehaving vehicle's SCMS — cross-SCMS revocation coordination is out of scope for all three standards |

The US deployment includes multiple SCMS providers (e.g. ISS, SaeSol), so this gap is a real design issue in domestic deployments today, not only in international interoperability scenarios.

**Relevant standards reviewed:** SAE J3287 (January 2024 draft), ETSI TS 103 759 V2.1.1 (2023-01), IEEE 1609.2.1-2022.

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
