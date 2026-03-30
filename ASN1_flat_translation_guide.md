# ASN.1 Parameterized-to-Flat Translation Guide

This document captures the rules used to convert the parameterized ASN.1 modules in
`J3287_ASN/` into the non-parameterized (flat) equivalents in `J3287_ASN_flat/`.
The flat versions produce **identical OER encodings** to the originals.

---

## General Principles

1. **Parameterized template definitions are removed.** Replace the block with a comment
   noting the removal and listing the template signature.
2. **Parameterized instantiations are expanded inline** at the point of use, using
   the concrete argument types substituted for each formal parameter.
3. **IOC class definitions (`::= CLASS { ... }`) and IOS values are kept** — they
   serve as documentation and may be used by tooling even without parameterization.
4. **Open type fields (`&Val`, `&ExtContent`, etc.) map to `ANY`** — OER encodes
   open types and `ANY` identically (length-determinant followed by value bytes).
5. **`WITH COMPONENTS` constraints are preserved** in all expanded forms.
6. **`CONSTRAINED BY { ... }` with a comment** is used when the inner type of an
   opaque/encrypted blob cannot be expressed syntactically (e.g., the plaintext of
   an encrypted `Ieee1609Dot2Data`).
7. **Naming convention for generated intermediate types:** append a hyphenated suffix
   derived from the AID or context (e.g., `-Cam`, `-Bsm`).
8. **Imports are updated** to remove parameterized template names and add concrete
   types that the expanded forms reference directly.

---

## Pattern 1 — Remove a Parameterized Template Definition

**Source:**
```asn1
/**
 * @brief ...
 */
TemplateName {FORMAL-PARAM : ConstraintClass} ::= SEQUENCE {
  ...
}
```

**Flat:**
```asn1
-- NOTE: The parameterized template TemplateName {FORMAL-PARAM : ConstraintClass}
-- has been removed in this flat version. Its instantiation(s) are expanded inline
-- at the point of use.
```

**Applied to:**
- `Extension {EXT-TYPE : ExtensionTypes}` in `Ieee1609Dot2BaseTypes`
- `TemplateAsr`, `MbSingleObservation` in `EtsiTs103759BaseTypes`
- `EtsiTs103097Data-Unsecured/Signed/Encrypted/SignedAndEncrypted/...` in `EtsiTs103097Module`
- `ScmsPdu-Scoped`, `Ieee1609Dot2Data-Unsecured/Signed/Encrypted/...` in `Ieee1609Dot2Dot1Protocol`

---

## Pattern 2 — `Extension {{IOS}}`

Template signature: `Extension {EXT-TYPE : ExtensionTypes} ::= SEQUENCE { id ..., content ... }`

**Source:**
```asn1
SomeExtension ::= Extension{{SomeExtensionSet}}
```

**Flat:**
```asn1
-- Non-parameterized equivalent of Extension{{SomeExtensionSet}}.
SomeExtension ::= SEQUENCE {
  id      SomeExtensionId,   -- the ExtId subtype for this extension set
  content ANY
}
```

The `id` field type is the `ExtId` alias defined for this specific IOS
(e.g., `Ieee1609HeaderInfoExtensionId`, `EtsiTs103097HeaderInfoExtensionId`).

**Applied to:**
- `Ieee1609ContributedHeaderInfoExtension` in `Ieee1609Dot2`
- `EtsiOriginatingHeaderInfoExtension` in `EtsiTs103097ExtensionModule`

---

## Pattern 3 — `MbSingleObservation {{SetMbObsXxx}}`

Template signature: `MbSingleObservation {C-ASR-SINGLE-OBS : SetMbSingleObs} ::= SEQUENCE { obsId ..., obs ... }`

**Source:**
```asn1
-- used inline as element type inside ObservationsByTarget
```

**Flat (named intermediate type, one per IOS instance):**
```asn1
-- Non-parameterized equivalent of MbSingleObservation{{SetMbObsXxxYyy}}.
MbSingleObservation-XxxYyy ::= SEQUENCE {
  obsId  Uint8,
  obs    ANY
}
```

The suffix (`-XxxYyy`) is derived from the observation target name.

---

## Pattern 4 — `TemplateAsr {{ObsSet}, {EvSet}}`

Template signature:
```
TemplateAsr {C-ASR-OBS-BY-TGT: ObservationSet, C-ASR-EV: NonV2xPduEvidenceSet}
```

This is the most complex expansion. For each AID-specific ASR (suffix `-Xxx`):

**Step 1 — One `MbSingleObservation-XxxYyy` per observation type** (see Pattern 3).

**Step 2 — Intermediate container types:**
```asn1
ObservationsByTarget-Xxx ::= SEQUENCE {
  tgtId         Uint8,
  observations  SEQUENCE OF ANY
}

ObservationsByTargetSequence-Xxx ::= SEQUENCE (SIZE(1..MAX)) OF ObservationsByTarget-Xxx

NonV2xPduEvidenceItem-Xxx ::= SEQUENCE {
  id        Uint8,
  evidence  ANY
}

NonV2xPduEvidenceItemSequence-Xxx ::= SEQUENCE (SIZE(0..MAX)) OF NonV2xPduEvidenceItem-Xxx
```

**Step 3 — The expanded ASR type:**
```asn1
-- Non-parameterized equivalent of TemplateAsr{{SetMbObsTgtsXxx}, {SetMbEvXxx}}.
AsrXxx ::= SEQUENCE {
  observations       ObservationsByTargetSequence-Xxx,
  v2xPduEvidence     SEQUENCE (SIZE(1..MAX)) OF V2xPduStream,
  nonV2xPduEvidence  NonV2xPduEvidenceItemSequence-Xxx
}
```

**Step 4 — Update the IOS to use flat type names:**
```asn1
SetMbObsTgtsXxx C-ASR-OBS-BY-TGT ::= {
  {MbSingleObservation-XxxFoo BY c-XxxTgt-FooCommon} |
  {MbSingleObservation-XxxBar BY c-XxxTgt-BarCommon},
  ...
}
```

**Applied to:** `AsrCam` (`EtsiTs103759AsrCam`), `AsrBsm` (`SaeJ3287AsrBsm`)

---

## Pattern 5 — `Ieee1609Dot2Data-Unsecured {Tbu}`

**Source:**
```asn1
FooSpdu ::= Ieee1609Dot2Data-Unsecured {BarType}
```

**Flat:**
```asn1
-- Non-parameterized equivalent of Ieee1609Dot2Data-Unsecured{BarType}.
FooSpdu ::= Ieee1609Dot2Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    ...,
    unsecuredData (CONTAINING BarType)
  })
})
```

---

## Pattern 6 — `Ieee1609Dot2Data-Signed {Tbs, Psid}`

**Source:**
```asn1
FooSpdu ::= Ieee1609Dot2Data-Signed {BarType, somePsid}
```

**Flat:**
```asn1
-- Non-parameterized equivalent of Ieee1609Dot2Data-Signed{BarType, somePsid}.
FooSpdu ::= Ieee1609Dot2Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    ...,
    signedData (WITH COMPONENTS {
      ...,
      tbsData (WITH COMPONENTS {
        ...,
        payload (WITH COMPONENTS {
          ...,
          data (WITH COMPONENTS {
            ...,
            content (WITH COMPONENTS {
              unsecuredData (CONTAINING BarType)
            })
          })
        }),
        headerInfo (WITH COMPONENTS {
          ...,
          psid (somePsid),
          generationTime ABSENT,
          expiryTime ABSENT,
          generationLocation ABSENT,
          p2pcdLearningRequest ABSENT,
          missingCrlIdentifier ABSENT,
          encryptionKey ABSENT
        })
      }),
      signer (SignerSingleCert)
    })
  })
})
```

`SignerSingleCert` must be imported from `Ieee1609Dot2Dot1Protocol`.

---

## Pattern 7 — `Ieee1609Dot2Data-Encrypted {Tbe}`

**Source:**
```asn1
FooSpdu ::= Ieee1609Dot2Data-Encrypted {BarType}
```

**Flat:**
```asn1
-- Non-parameterized equivalent of Ieee1609Dot2Data-Encrypted{BarType}.
FooSpdu ::= Ieee1609Dot2Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    ...,
    encryptedData (CONSTRAINED BY {
      -- encryption of BarType
    })
  })
})
```

For structured inner types (e.g., `ScmsPdu-Scoped{...}`), expand the comment:
```asn1
    encryptedData (CONSTRAINED BY {
      -- encryption of ScmsPdu (WITH COMPONENTS {...,
      --   content (CONSTRAINED BY {-- InnerPduType ...})
      -- })
    })
```

---

## Pattern 8 — `Ieee1609Dot2Data-SignedEncrypted {Tbse, Psid}`

This equals `Ieee1609Dot2Data-Encrypted { Ieee1609Dot2Data-Signed {Tbse, Psid} }`.
The outer layer is an encrypted `Ieee1609Dot2Data`; its plaintext is a signed
`Ieee1609Dot2Data`. The outer structure uses Pattern 7 with the inner signed
structure described in the `CONSTRAINED BY` comment.

**Flat:**
```asn1
-- Non-parameterized equivalent of Ieee1609Dot2Data-SignedEncrypted{BarType, somePsid},
-- which is Ieee1609Dot2Data-Encrypted{Ieee1609Dot2Data-Signed{BarType, somePsid}}.
FooSpdu ::= Ieee1609Dot2Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    ...,
    encryptedData (CONSTRAINED BY {
      -- encryption of Ieee1609Dot2Data (WITH COMPONENTS {...,
      --   content (WITH COMPONENTS {...,
      --     signedData (WITH COMPONENTS {...,
      --       tbsData (WITH COMPONENTS {...,
      --         payload (WITH COMPONENTS {...,
      --           data (WITH COMPONENTS {...,
      --             content (WITH COMPONENTS {
      --               unsecuredData (CONTAINING BarType)
      --             })
      --           })
      --         }),
      --         headerInfo (WITH COMPONENTS {...,
      --           psid (somePsid),
      --           generationTime ABSENT,
      --           expiryTime ABSENT,
      --           generationLocation ABSENT,
      --           p2pcdLearningRequest ABSENT,
      --           missingCrlIdentifier ABSENT,
      --           encryptionKey ABSENT
      --         })
      --       }),
      --       signer (SignerSingleCert)
      --     })
      --   })
      -- })
    })
  })
})
```

---

## Pattern 9 — `Ieee1609Dot2Data-EncryptedSigned {Tbes, Psid}`

This equals `Ieee1609Dot2Data-Signed { Ieee1609Dot2Data-Encrypted {Tbes}, Psid }`.
The outer layer is a signed `Ieee1609Dot2Data`; its payload contains an encrypted
`Ieee1609Dot2Data`. Use Pattern 6 for the outer structure, but the `unsecuredData`
field `CONTAINING` clause holds the encrypted inner blob.

**Flat:**
```asn1
-- Non-parameterized equivalent of Ieee1609Dot2Data-EncryptedSigned{BarType, somePsid},
-- which is Ieee1609Dot2Data-Signed{Ieee1609Dot2Data-Encrypted{BarType}, somePsid}.
FooSpdu ::= Ieee1609Dot2Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    ...,
    signedData (WITH COMPONENTS {
      ...,
      tbsData (WITH COMPONENTS {
        ...,
        payload (WITH COMPONENTS {
          ...,
          data (WITH COMPONENTS {
            ...,
            content (WITH COMPONENTS {
              unsecuredData (CONTAINING Ieee1609Dot2Data (WITH COMPONENTS {
                ...,
                content (WITH COMPONENTS {
                  ...,
                  encryptedData (CONSTRAINED BY {
                    -- encryption of BarType
                  })
                })
              }))
            })
          })
        }),
        headerInfo (WITH COMPONENTS {
          ...,
          psid (somePsid),
          generationTime ABSENT,
          expiryTime ABSENT,
          generationLocation ABSENT,
          p2pcdLearningRequest ABSENT,
          missingCrlIdentifier ABSENT,
          encryptionKey ABSENT
        })
      }),
      signer (SignerSingleCert)
    })
  })
})
```

---

## Pattern 10 — `Ieee1609Dot2Data-SignedCertRequest {Tbscr, Signer}`

Similar to Pattern 6 (Signed), but the payload uses `certRequestData` instead of
`data`, and the `Signer` parameter is used directly (may be `SignerSingleCert` or
`SignerSelf` depending on the instantiation).

**Flat:**
```asn1
-- Non-parameterized equivalent of Ieee1609Dot2Data-SignedCertRequest{BarType, SignerFoo}.
FooSpdu ::= Ieee1609Dot2Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    ...,
    signedData (WITH COMPONENTS {
      ...,
      tbsData (WITH COMPONENTS {
        ...,
        payload (WITH COMPONENTS {
          ...,
          certRequestData (CONTAINING BarType)
        }),
        headerInfo (WITH COMPONENTS {
          ...,
          psid (ScmsPsid),
          generationTime ABSENT,
          expiryTime ABSENT,
          generationLocation ABSENT,
          p2pcdLearningRequest ABSENT,
          missingCrlIdentifier ABSENT,
          encryptionKey ABSENT
        })
      }),
      signer (SignerFoo)
    })
  })
})
```

---

## Pattern 11 — `Ieee1609Dot2Data-SignedEncryptedCertRequest {Tbstecr, Signer}`

This equals `Ieee1609Dot2Data-Encrypted { Ieee1609Dot2Data-SignedCertRequest {Tbstecr, Signer} }`.
Use Pattern 7 for the outer encrypted wrapper. The inner SignedCertRequest structure is
described in the `CONSTRAINED BY` comment.

---

## Pattern 12 — `Ieee1609Dot2Data-SignedX509AuthenticatedCertRequest {Tbscr, Signer}`

Same structure as Pattern 10 but uses `SignerSingleX509Cert` (or the supplied `Signer`
which is an X.509 signer form).

---

## Pattern 13 — `Ieee1609Dot2Data-SymmEncryptedSingleRecipient {Tbe}`

**Flat:**
```asn1
-- Non-parameterized equivalent of Ieee1609Dot2Data-SymmEncryptedSingleRecipient{BarType}.
FooField ::= Ieee1609Dot2Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    encryptedData (CONSTRAINED BY {
      --contains only one RecipientInfo, of form symmRecipinfo
      --symmetric encryption of-- BarType
    })
  })
})
```

---

## Pattern 14 — `ScmsPdu-Scoped {Pdu}`

**Source:**
```asn1
FooScoped ::= ScmsPdu-Scoped {BarInterfacePdu (WITH COMPONENTS { baz })}
```

**Flat:**
```asn1
-- Non-parameterized equivalent of ScmsPdu-Scoped{BarInterfacePdu (WITH COMPONENTS { baz })}.
FooScoped ::= ScmsPdu (WITH COMPONENTS {
  ...,
  content (CONSTRAINED BY {
    -- BarInterfacePdu (WITH COMPONENTS { baz })
  })
})
```

When `ScmsPdu-Scoped{...}` is nested inside another template (e.g., as the `Tbe`
argument to `Ieee1609Dot2Data-Encrypted`), the ScmsPdu expansion goes inside the
`CONSTRAINED BY` comment of the outer Pattern 7/8/11 expansion.

---

## Pattern 15 — `EtsiTs103097Data-Signed {ToBeSignedDataContent}`

**Flat:**
```asn1
-- Non-parameterized equivalent of EtsiTs103097Data-Signed{BarType}.
FooData ::= EtsiTs103097Data (WITH COMPONENTS {
  ...,
  content (WITH COMPONENTS {
    ...,
    signedData (WITH COMPONENTS {
      ...,
      tbsData (WITH COMPONENTS {
        ...,
        payload (WITH COMPONENTS {
          ...,
          data (WITH COMPONENTS {
            ...,
            content (WITH COMPONENTS {
              unsecuredData (CONTAINING BarType)
            })
          })
        })
      })
    })
  })
})
```

---

## Pattern 16 — `EtsiTs103097Data-SignedAndEncrypted-Unicast {ToBesignedAndEncryptedDataContent}`

This equals `EtsiTs103097Data-Encrypted-Unicast { EtsiTs103097Data-Signed {BarType} }`.
The outer layer is an encrypted unicast `EtsiTs103097Data`. Its plaintext is a signed
`EtsiTs103097Data`. Use a `CONSTRAINED BY` comment for the encrypted outer layer, with
the inner signed structure described inline.

---

## IOC / IOS Handling

| Element | Action |
|---------|--------|
| `CLASS { &field ... } WITH SYNTAX { ... }` | **Keep** — informational |
| `SomeSet ClassName ::= { {Val IDENTIFIED BY id} \| ... }` | **Keep**, but update any type references to use flat type names (e.g., `MbSingleObservation-XxxFoo` instead of `MbSingleObservation{{...}}`) |
| `SomeName ClassName ::= value` | **Keep** |

---

## Import Updates

When expanding a template instantiation, update the `IMPORTS` of the consuming module:

- **Remove** the parameterized template name (e.g., `Ieee1609Dot2Data-Signed`,
  `TemplateAsr`, `MbSingleObservation`, `Extension`).
- **Add** any concrete types that the expanded form references:
  - `SignerSingleCert` from `Ieee1609Dot2Dot1Protocol` (needed by all Signed expansions)
  - `Ieee1609Dot2Data` from `Ieee1609Dot2` (needed when the flat form wraps it with
    `WITH COMPONENTS`)
  - `V2xPduStream` from `EtsiTs103759BaseTypes` (needed by TemplateAsr expansions)

---

## File-by-File Change Summary

| File | Changes |
|------|---------|
| `Ieee1609Dot2BaseTypes.asn` | Removed `Extension {EXT-TYPE : ExtensionTypes}` template |
| `Ieee1609Dot2.asn` | Removed `Extension` import; expanded `Ieee1609ContributedHeaderInfoExtension` (Pattern 2) |
| `EtsiTs103097ExtensionModule.asn` | Removed `Extension` import and template; expanded `EtsiOriginatingHeaderInfoExtension` (Pattern 2) |
| `EtsiTs103097Module.asn` | Removed 6 `EtsiTs103097Data-*` template definitions; kept `EtsiTs103097Data-SignedExternalPayload` (non-parameterized subtype) |
| `EtsiTs103759BaseTypes.asn` | Removed `TemplateAsr` and `MbSingleObservation` templates; updated `V2xPduStream` fields to concrete types |
| `EtsiTs103759Core.asn` | Updated imports; expanded `EtsiTs103759Mbr-Signed` (Pattern 15) and `EtsiTs103759Mbr-STE` (Pattern 16); changed `AidSpecificReport.content` to `ANY` |
| `EtsiTs103759AsrCam.asn` | Fully expanded `AsrCam` (Pattern 4); added 10 intermediate types |
| `EtsiTs103759AsrDenm.asn` | No change — `AsrDenm ::= NULL` (no parameterization) |
| `EtsiTs103759AsrAppAgnostic.asn` | No change — `AsrAppAgnostic ::= NULL` (no parameterization) |
| `SaeJ3287AsrBsm.asn` | Fully expanded `AsrBsm` (Pattern 4); added 6 intermediate types |
| `SaeJ3287.asn` | Updated imports; expanded `SaeJ3287Mbr-Signed` (Pattern 6) and `SaeJ3287Mbr-STE` (Pattern 8) |
| `Ieee1609Dot2Dot1Protocol.asn` | Removed 10 parameterized templates; expanded 4 `ScmsPdu-*` subtypes (Pattern 14) and ~22 SPDU instantiations (Patterns 5–13) |
| `Ieee1609Dot2Dot1AcaRaInterface.asn` | Updated imports; expanded `EncryptedIndividualPLV.encPlv` inline (Pattern 13) |
| `Ieee1609Dot2Dot1Acpc.asn` | Updated imports; expanded `UnsecuredAprvBinaryTree` (Pattern 5), `SignedAprvBinaryTree` and `SignedIndividualAprv` (Pattern 6) |
| `Ieee1609Dot2Dot1CertManagement.asn` | Replaced IOC open type fields in `MultiSignedCtl` with `ANY` |
| All other `Ieee1609Dot2Dot1*Interface.asn` files | No change — no parameterized content |
| `Ieee1609Dot2Crl.asn`, `Ieee1609Dot2CrlBaseTypes.asn`, `Ieee1609Dot2CrlSsp.asn` | No change |
| `EtsiTs103759CommonObservations.asn` | No change |
