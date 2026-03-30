#!/usr/bin/env python3
"""
translate_asn1.py  –  ASN.1 Parameterized → Flat Translation

Reads parameterized ASN.1 source files from asn/J3287_ASN/ and writes
non-parameterized equivalents to asn/J3287_ASN_flat/.

The flat versions produce identical OER encodings: every parameterized
template instantiation is expanded to a concrete type definition, and
parameterized template definitions are removed from their modules.

Usage
-----
    python3 translate_asn1.py [--src asn/J3287_ASN] [--dst asn/J3287_ASN_flat]

The script is idempotent: re-running it overwrites the destination with a
fresh translation from the source.

Supported templates
-------------------
  Ieee1609Dot2Data-{Unsecured, Signed, Encrypted, SignedEncrypted,
    EncryptedSigned, SignedCertRequest, SignedEncryptedCertRequest,
    SignedX509AuthenticatedCertRequest, SymmEncryptedSingleRecipient}
  ScmsPdu-Scoped
  EtsiTs103097Data-{Unsecured, Signed, Encrypted, SignedAndEncrypted,
    Encrypted-Unicast, SignedAndEncrypted-Unicast}
  Extension  (EXT-TYPE parameterization)
  TemplateAsr  (includes MbSingleObservation, ObservationsByTarget, etc.)
"""

import re
import sys
import shutil
import argparse
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
#  Section 1 – Low-level parsing helpers
# ═══════════════════════════════════════════════════════════════════════════════

def matching_brace(text: str, idx: int) -> int:
    """Return index of the '}' matching the '{' at text[idx]."""
    depth = 0
    for i in range(idx, len(text)):
        if   text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"Unmatched '{{' at index {idx}: ...{text[idx:idx+60]!r}...")


def split_args(inner: str) -> list:
    """
    Split `inner` (text between outer braces) on top-level commas.
    Respects nesting: {}, (), [].
    """
    db = dp = dq = 0
    buf, result = [], []
    for ch in inner:
        if   ch == '{': db  += 1
        elif ch == '}': db  -= 1
        elif ch == '(': dp  += 1
        elif ch == ')': dp  -= 1
        elif ch == '[': dq  += 1
        elif ch == ']': dq  -= 1
        elif ch == ',' and db == 0 and dp == 0 and dq == 0:
            result.append(''.join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        result.append(''.join(buf).strip())
    return result


def find_instantiation(text: str, template: str, pos: int = 0):
    """
    Find the next `template { ... }` in text[pos:] that is NOT a definition.
    A definition has ::= immediately following the closing brace of the
    parameter list; an instantiation does not.

    Returns (match_start, args_text, end_pos) or None.
    """
    pat = re.compile(r'(?<![A-Za-z0-9-])' + re.escape(template) + r'\s*\{',
                     re.DOTALL)
    search_from = pos
    while True:
        m = pat.search(text, search_from)
        if not m:
            return None
        b_open  = m.end() - 1
        b_close = matching_brace(text, b_open)
        args    = text[b_open + 1: b_close].strip()
        end     = b_close + 1
        # Distinguish instantiation from definition: definitions have ::= next
        tail = text[end:].lstrip()
        if tail.startswith('::='):
            search_from = end   # skip – this is a definition
            continue
        return m.start(), args, end


def _scan_body_end(text: str, start: int) -> int:
    """
    Return the index just after the ASN.1 type body beginning at text[start].
    Works for both SEQUENCE { ... } and SEQUENCE (SIZE...) OF X {{ IOS }}.
    """
    db = dp = 0
    for i in range(start, len(text)):
        c = text[i]
        if   c == '{': db += 1
        elif c == '}': db -= 1
        elif c == '(': dp += 1
        elif c == ')': dp -= 1
        elif c == '\n' and db == 0 and dp == 0:
            return i + 1
    return len(text)


def remove_definition_block(text: str, template_name: str) -> str:
    """
    Remove the parameterized template definition (including its doc comment).
    Inserts a one-line note in its place.
    """
    pat = re.compile(r'(?<![A-Za-z0-9-])' + re.escape(template_name) + r'\s*\{',
                     re.DOTALL)
    search_from = 0
    while True:
        m = pat.search(text, search_from)
        if not m:
            return text   # not found – nothing to remove
        b_open  = m.end() - 1
        b_close = matching_brace(text, b_open)
        tail    = text[b_close + 1:].lstrip()
        if tail.startswith('::='):
            break         # this IS a definition
        search_from = b_close + 1

    t_start    = m.start()
    after_args = b_close + 1

    # Walk backwards to include any preceding /** ... */ doc comment
    block_start = t_start
    before = text[:t_start].rstrip()   # strip trailing whitespace including newlines
    if before.endswith('*/'):
        idx = before.rfind('/**')
        if idx != -1:
            # also consume leading whitespace / newline before the comment
            ws_start = idx
            while ws_start > 0 and text[ws_start - 1] in ' \t':
                ws_start -= 1
            if ws_start > 0 and text[ws_start - 1] == '\n':
                ws_start -= 1
            block_start = ws_start

    # Find the body (after ::=)
    assign_idx = text.index('::=', after_args) + 3
    while assign_idx < len(text) and text[assign_idx] in ' \t\n\r':
        assign_idx += 1
    block_end = _scan_body_end(text, assign_idx)

    note = (f"\n-- NOTE: Parameterized template '{template_name}' removed in flat"
            f" version.\n-- Its instantiations are expanded at the point of use.\n")
    return text[:block_start] + note + text[block_end:]


# ═══════════════════════════════════════════════════════════════════════════════
#  Section 2 – Template expansion functions
#
#  Each function returns a TYPE EXPRESSION (the right-hand side of ::=).
#  The calling code is responsible for producing the full type assignment.
# ═══════════════════════════════════════════════════════════════════════════════

# Populated at the end of this section; used by expand_arg()
_TEMPLATES: dict = {}


def expand_arg(arg: str) -> str:
    """If arg is a known template instantiation, expand it; else return as-is."""
    arg = arg.strip()
    for tname, expander in _TEMPLATES.items():
        if arg.startswith(tname):
            rest = arg[len(tname):].lstrip()
            if rest.startswith('{'):
                b_end = matching_brace(rest, 0)
                inner = rest[1:b_end]
                sub   = split_args(inner)
                return expander(*sub)
    return arg


def _commentize(expr: str, indent: str = '      ') -> str:
    """
    Convert a multi-line type expression to comment lines.
    Returns the whole block (no trailing newline).
    """
    lines = expr.split('\n')
    return '\n'.join(f'{indent}-- {line}' for line in lines)


# ── IEEE 1609.2 / 1609.2.1 templates ─────────────────────────────────────────

def exp_unsecured(tbu: str) -> str:
    tbu = expand_arg(tbu)
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        f"    unsecuredData (CONTAINING {tbu})\n"
        "  })\n"
        "})"
    )


def exp_signed(tbs: str, psid: str) -> str:
    tbs = expand_arg(tbs)
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    signedData (WITH COMPONENTS {\n"
        "      ...,\n"
        "      tbsData (WITH COMPONENTS {\n"
        "        ...,\n"
        "        payload (WITH COMPONENTS {\n"
        "          ...,\n"
        "          data (WITH COMPONENTS {\n"
        "            ...,\n"
        "            content (WITH COMPONENTS {\n"
        f"              unsecuredData (CONTAINING {tbs})\n"
        "            })\n"
        "          })\n"
        "        }),\n"
        "        headerInfo (WITH COMPONENTS {\n"
        "          ...,\n"
        f"          psid ({psid}),\n"
        "          generationTime ABSENT,\n"
        "          expiryTime ABSENT,\n"
        "          generationLocation ABSENT,\n"
        "          p2pcdLearningRequest ABSENT,\n"
        "          missingCrlIdentifier ABSENT,\n"
        "          encryptionKey ABSENT\n"
        "        })\n"
        "      }),\n"
        "      signer (SignerSingleCert)\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_encrypted(tbe: str) -> str:
    tbe_expanded = expand_arg(tbe)
    lines = tbe_expanded.split('\n')
    first_line   = f"      -- encryption of {lines[0]}"
    rest_lines   = '\n'.join(f'      -- {l}' for l in lines[1:])
    comment_body = first_line + ('\n' + rest_lines if rest_lines else '')
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    encryptedData (CONSTRAINED BY {\n"
        f"{comment_body}\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_signed_encrypted(tbse: str, psid: str) -> str:
    """SignedEncrypted = Encrypted( Signed(tbse, psid) )."""
    tbs = expand_arg(tbse)
    # Build the full inner Signed expression and commentize it
    inner = exp_signed(tbs if not tbs.startswith('Ieee1609Dot2Data') else tbse, psid)
    # To avoid double-expansion, re-build the comment manually
    tbs_str = tbs
    inner_expr = (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    signedData (WITH COMPONENTS {\n"
        "      ...,\n"
        "      tbsData (WITH COMPONENTS {\n"
        "        ...,\n"
        "        payload (WITH COMPONENTS {\n"
        "          ...,\n"
        "          data (WITH COMPONENTS {\n"
        "            ...,\n"
        "            content (WITH COMPONENTS {\n"
        f"              unsecuredData (CONTAINING {tbs_str})\n"
        "            })\n"
        "          })\n"
        "        }),\n"
        "        headerInfo (WITH COMPONENTS {\n"
        "          ...,\n"
        f"          psid ({psid}),\n"
        "          generationTime ABSENT, expiryTime ABSENT,\n"
        "          generationLocation ABSENT, p2pcdLearningRequest ABSENT,\n"
        "          missingCrlIdentifier ABSENT, encryptionKey ABSENT\n"
        "        })\n"
        "      }),\n"
        "      signer (SignerSingleCert)\n"
        "    })\n"
        "  })\n"
        "})"
    )
    lines = inner_expr.split('\n')
    first   = f"      -- encryption of {lines[0]}"
    rest    = '\n'.join(f"      -- {l}" for l in lines[1:])
    comment = first + ('\n' + rest if rest else '')
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    encryptedData (CONSTRAINED BY {\n"
        f"{comment}\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_encrypted_signed(tbes: str, psid: str) -> str:
    """EncryptedSigned = Signed( Encrypted(tbes), psid )."""
    tbes_expanded = expand_arg(tbes)
    lines = tbes_expanded.split('\n')
    first   = f"              -- encryption of {lines[0]}"
    rest    = '\n'.join(f"              -- {l}" for l in lines[1:])
    enc_comment = first + ('\n' + rest if rest else '')
    inner_enc = (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "                ...,\n"
        "                content (WITH COMPONENTS {\n"
        "                  ...,\n"
        f"                  encryptedData (CONSTRAINED BY {{\n"
        f"{enc_comment}\n"
        "                  })\n"
        "                })\n"
        "              })"
    )
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    signedData (WITH COMPONENTS {\n"
        "      ...,\n"
        "      tbsData (WITH COMPONENTS {\n"
        "        ...,\n"
        "        payload (WITH COMPONENTS {\n"
        "          ...,\n"
        "          data (WITH COMPONENTS {\n"
        "            ...,\n"
        "            content (WITH COMPONENTS {\n"
        f"              unsecuredData (CONTAINING {inner_enc})\n"
        "            })\n"
        "          })\n"
        "        }),\n"
        "        headerInfo (WITH COMPONENTS {\n"
        "          ...,\n"
        f"          psid ({psid}),\n"
        "          generationTime ABSENT,\n"
        "          expiryTime ABSENT,\n"
        "          generationLocation ABSENT,\n"
        "          p2pcdLearningRequest ABSENT,\n"
        "          missingCrlIdentifier ABSENT,\n"
        "          encryptionKey ABSENT\n"
        "        })\n"
        "      }),\n"
        "      signer (SignerSingleCert)\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_signed_cert_request(tbscr: str, signer: str) -> str:
    tbs = expand_arg(tbscr)
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    signedCertificateRequest (CONTAINING\n"
        "      SignedCertificateRequest (WITH COMPONENTS {\n"
        "        ...,\n"
        f"        tbsRequest ({tbs}),\n"
        f"        signer ({signer})\n"
        "      }))\n"
        "  })\n"
        "})"
    )


def exp_signed_encrypted_cert_request(tbstecr: str, signer: str) -> str:
    """SignedEncryptedCertRequest = Encrypted( SignedCertRequest(tbstecr, signer) )."""
    tbs = expand_arg(tbstecr)
    inner_expr = (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    signedCertificateRequest (CONTAINING SignedCertificateRequest (WITH COMPONENTS {\n"
        f"      ...,\n"
        f"      tbsRequest ({tbs}),\n"
        f"      signer ({signer})\n"
        "    }))\n"
        "  })\n"
        "})"
    )
    lines = inner_expr.split('\n')
    first   = f"      -- encryption of {lines[0]}"
    rest    = '\n'.join(f"      -- {l}" for l in lines[1:])
    comment = first + ('\n' + rest if rest else '')
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    encryptedData (CONSTRAINED BY {\n"
        f"{comment}\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_signed_x509_cert_request(tbscr: str, signer: str) -> str:
    tbs = expand_arg(tbscr)
    inner_expr = (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    ...,\n"
        "    signedX509CertificateRequest (CONTAINING SignedX509CertificateRequest (WITH COMPONENTS {\n"
        f"      ...,\n"
        f"      tbsRequest ({tbs}),\n"
        f"      signer ({signer})\n"
        "    }))\n"
        "  })\n"
        "})"
    )
    lines = inner_expr.split('\n')
    first   = f"      -- encryption of {lines[0]}"
    rest    = '\n'.join(f"      -- {l}" for l in lines[1:])
    comment = first + ('\n' + rest if rest else '')
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    encryptedData (CONSTRAINED BY {\n"
        f"{comment}\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_symm_encrypted(tbe: str) -> str:
    tbe = tbe.strip()
    return (
        "Ieee1609Dot2Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    encryptedData (CONSTRAINED BY {\n"
        "      --contains only one RecipientInfo, of form symmRecipinfo\n"
        f"      --symmetric encryption of-- {tbe}\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_scms_pdu_scoped(pdu: str) -> str:
    pdu = pdu.strip()
    pdu_comment = '\n'.join(f'    -- {line}' for line in pdu.splitlines())
    return (
        "ScmsPdu (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (CONSTRAINED BY {\n"
        f"{pdu_comment}\n"
        "  })\n"
        "})"
    )


# ── ETSI TS 103 097 templates ─────────────────────────────────────────────────

def exp_etsi_unsecured(tbu: str) -> str:
    tbu = expand_arg(tbu)
    return (
        "EtsiTs103097Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        f"    unsecuredData (CONTAINING {tbu})\n"
        "  })\n"
        "})"
    )


def exp_etsi_signed(tbs: str) -> str:
    tbs = expand_arg(tbs)
    return (
        "EtsiTs103097Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    signedData (WITH COMPONENTS {\n"
        "      ...,\n"
        "      tbsData (WITH COMPONENTS {\n"
        "        payload (WITH COMPONENTS {\n"
        "          data (WITH COMPONENTS {\n"
        "            ...,\n"
        "            content (WITH COMPONENTS {\n"
        f"              unsecuredData (CONTAINING {tbs})\n"
        "            })\n"
        "          }) PRESENT\n"
        "        })\n"
        "      })\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_etsi_encrypted(tbe: str) -> str:
    tbe = tbe.strip()
    return (
        "EtsiTs103097Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    encryptedData (WITH COMPONENTS {\n"
        "      ...,\n"
        "      ciphertext (WITH COMPONENTS {\n"
        "        ...,\n"
        "        aes128ccm (WITH COMPONENTS {\n"
        "          ...,\n"
        "          ccmCiphertext (CONSTRAINED BY {\n"
        f"            -- ccm encryption of -- {tbe}\n"
        "          })\n"
        "        })\n"
        "      })\n"
        "    })\n"
        "  })\n"
        "})"
    )


def exp_etsi_signed_and_encrypted(tbs: str) -> str:
    """EtsiTs103097Data-SignedAndEncrypted = Encrypted(Signed(tbs))."""
    tbs = tbs.strip()
    return exp_etsi_encrypted(f"EtsiTs103097Data-Signed{{{tbs}}}")


def exp_etsi_signed_and_encrypted_unicast(tbs: str) -> str:
    """EtsiTs103097Data-SignedAndEncrypted-Unicast = Encrypted(Signed(tbs)) + recipients(1)."""
    tbs = tbs.strip()
    return (
        "EtsiTs103097Data (WITH COMPONENTS {\n"
        "  ...,\n"
        "  content (WITH COMPONENTS {\n"
        "    encryptedData (WITH COMPONENTS {\n"
        "      ...,\n"
        "      ciphertext (WITH COMPONENTS {\n"
        "        ...,\n"
        "        aes128ccm (WITH COMPONENTS {\n"
        "          ...,\n"
        "          ccmCiphertext (CONSTRAINED BY {\n"
        f"            -- ccm encryption of EtsiTs103097Data-Signed{{{tbs}}}\n"
        "          })\n"
        "        })\n"
        "      }),\n"
        "      recipients (SIZE(1))\n"
        "    })\n"
        "  })\n"
        "})"
    )


# ── Register all templates ────────────────────────────────────────────────────

_TEMPLATES = {
    'Ieee1609Dot2Data-Unsecured':                          exp_unsecured,
    'Ieee1609Dot2Data-Signed':                             exp_signed,
    'Ieee1609Dot2Data-Encrypted':                          exp_encrypted,
    'Ieee1609Dot2Data-SignedEncrypted':                    exp_signed_encrypted,
    'Ieee1609Dot2Data-EncryptedSigned':                    exp_encrypted_signed,
    'Ieee1609Dot2Data-SignedCertRequest':                  exp_signed_cert_request,
    'Ieee1609Dot2Data-SignedEncryptedCertRequest':         exp_signed_encrypted_cert_request,
    'Ieee1609Dot2Data-SignedX509AuthenticatedCertRequest': exp_signed_x509_cert_request,
    'Ieee1609Dot2Data-SymmEncryptedSingleRecipient':       exp_symm_encrypted,
    'ScmsPdu-Scoped':                                      exp_scms_pdu_scoped,
    'EtsiTs103097Data-Unsecured':                          exp_etsi_unsecured,
    'EtsiTs103097Data-Signed':                             exp_etsi_signed,
    'EtsiTs103097Data-Encrypted':                          exp_etsi_encrypted,
    'EtsiTs103097Data-SignedAndEncrypted':                 exp_etsi_signed_and_encrypted,
    'EtsiTs103097Data-SignedAndEncrypted-Unicast':         exp_etsi_signed_and_encrypted_unicast,
}

# ── Extension{{IOS}} expansion ────────────────────────────────────────────────

# Maps IOS name → ID type name
_EXTENSION_ID_TYPES = {
    'Ieee1609HeaderInfoExtensions':      'Ieee1609HeaderInfoExtensionId',
    'EtsiTs103097HeaderInfoExtensions':  'EtsiTs103097HeaderInfoExtensionId',
}


def expand_extension_instantiation(text: str) -> str:
    """
    Find `TypeName ::= Extension{{IOS}}` patterns and replace each with an
    expanded SEQUENCE { id IdType, content ANY }.

    The note about the expansion is injected into the preceding /** */ docblock
    if one exists immediately before the definition (matching the hand-crafted
    flat file style).  Otherwise a standalone -- comment is prepended.
    """
    pat = re.compile(r'(\b[A-Z][A-Za-z0-9-]*\b)\s*::=\s*Extension\s*\{\{([^}]+)\}\}')

    result = []
    last_end = 0
    for m in pat.finditer(text):
        type_name = m.group(1)
        ios_name  = m.group(2).strip()
        id_type   = _EXTENSION_ID_TYPES.get(ios_name, 'ExtId')
        note_body = "Non-parameterized equivalent of Extension{{" + ios_name + "}}."
        expansion = (
            f"{type_name} ::= SEQUENCE {{\n"
            f"  id      {id_type},\n"
            f"  content ANY\n"
            f"}}"
        )

        before = text[last_end:m.start()]
        # Check if before ends with a /** */ docblock closer (last */ in `before`)
        close_idx = before.rfind('*/')
        if close_idx >= 0 and not before[close_idx+2:].strip():
            # Split: text up to (not including) */ | injected note | */ | gap | expansion
            gap = before[close_idx + 2:]   # whitespace (newlines) between */ and TypeName
            # Strip the leading space that precedes */ on that line
            pre = text[last_end : last_end + close_idx].rstrip(' \t')
            result.append(pre)
            result.append(" *\n * " + note_body + "\n */")
            result.append(gap + expansion)
        else:
            result.append(before)
            result.append("-- " + note_body + "\n" + expansion)
        last_end = m.end()

    result.append(text[last_end:])
    return ''.join(result)


# ═══════════════════════════════════════════════════════════════════════════════
#  Section 3 – Generic template instantiation expander
# ═══════════════════════════════════════════════════════════════════════════════

def expand_all_instantiations(text: str) -> str:
    """
    Find all `TypeName ::= TemplateName { args }` assignments and also inline
    field-type uses of the form `fieldName  TemplateName { args }` in text,
    and replace each with the expanded flat form.  Handles all templates in
    _TEMPLATES.  Processes longest template names first to avoid prefix matches.
    """
    for tname in sorted(_TEMPLATES, key=len, reverse=True):
        expander = _TEMPLATES[tname]

        # ── Pass 1: top-level assignments: TypeName ::= TemplateName { ... } ──
        assign_pat = re.compile(
            r'(\b[A-Z][A-Za-z0-9-]*\b)(\s*::=\s*)(?=' + re.escape(tname) + r'\s*\{)',
            re.DOTALL)
        while True:
            am = assign_pat.search(text)
            if not am:
                break
            type_name = am.group(1)
            result = find_instantiation(text, tname, am.end())
            if result is None:
                break
            _, args_text, end_pos = result
            args = split_args(args_text)
            try:
                expanded = expander(*args)
            except TypeError as e:
                print(f"  WARNING: wrong arg count for {tname}: {e}", file=sys.stderr)
                break
            replacement = f"{type_name} ::= {expanded}"
            text = text[:am.start()] + replacement + text[end_pos:]

        # ── Pass 2: inline field types: fieldName  TemplateName { ... } ──
        # (not preceded by ::= — those are template definitions or top-level)
        inline_pat = re.compile(
            r'(?<![=\n])(\s+)(?=' + re.escape(tname) + r'\s*\{)',
            re.DOTALL)
        while True:
            im = inline_pat.search(text)
            if not im:
                break
            # Verify it's not a definition (not preceded by ::=)
            before = text[:im.start()].rstrip()
            if before.endswith('::='):
                break  # shouldn't happen due to lookbehind, but be safe
            result = find_instantiation(text, tname, im.end())
            if result is None:
                break
            _, args_text, end_pos = result
            args = split_args(args_text)
            try:
                expanded = expander(*args)
            except TypeError as e:
                print(f"  WARNING: inline wrong arg count for {tname}: {e}", file=sys.stderr)
                break
            # Replace: keep the leading whitespace, replace template with expansion
            replacement = im.group(1) + expanded
            text = text[:im.start()] + replacement + text[end_pos:]

    return text


# ═══════════════════════════════════════════════════════════════════════════════
#  Section 4 – TemplateAsr expansion
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_obs_tgts_ios(text: str, ios_name: str) -> list:
    """
    Parse the IOS `ios_name C-ASR-OBS-BY-TGT ::= { {MbSingleObservation{{SetMbObsXxx}} BY tgtId} | ... }`
    and return a list of (single_obs_ios_name, tgt_id_value) tuples.
    """
    # Find ios_name ... ::= { ... }
    pat = re.compile(r'\b' + re.escape(ios_name) + r'\s+C-ASR-OBS-BY-TGT\s*::=\s*\{', re.DOTALL)
    m = pat.search(text)
    if not m:
        return []
    b_open  = m.end() - 1
    b_close = matching_brace(text, b_open)
    body    = text[b_open + 1: b_close]

    # Each entry: {MbSingleObservation{{SetMbObsXxx}} BY c-XxxTgt-YyyCommon}
    entry_pat = re.compile(
        r'\{MbSingleObservation\s*\{\{([^}]+)\}\}\s+BY\s+([\w-]+)\}',
        re.DOTALL)
    return [(m.group(1).strip(), m.group(2).strip())
            for m in entry_pat.finditer(body)]


def _suffix_from_ios_name(ios_name: str, prefix: str = 'SetMbObs') -> str:
    """Extract the type suffix from an IOS name, e.g. SetMbObsCamBeacon → CamBeacon."""
    if ios_name.startswith(prefix):
        return ios_name[len(prefix):]
    return ios_name


def handle_template_asr(text: str) -> str:
    """
    Find `AsrXxx ::= TemplateAsr {{ObsSet}, {EvSet}}` and:
      1. Generate MbSingleObservation-XxxFoo intermediate types.
      2. Generate ObservationsByTarget-Xxx, ObservationsByTargetSequence-Xxx,
         NonV2xPduEvidenceItem-Xxx, NonV2xPduEvidenceItemSequence-Xxx.
      3. Replace the AsrXxx ::= TemplateAsr assignment with the expanded form.
      4. Update the ObsTgts IOS to use flat type names.
    """
    # Find AsrXxx ::= TemplateAsr {{ ObsSet }, { EvSet }}
    asr_pat = re.compile(
        r'(\b(Asr[A-Za-z0-9]+)\b)\s*::=\s*TemplateAsr\s*\{', re.DOTALL)
    m = asr_pat.search(text)
    if not m:
        return text

    asr_name  = m.group(2)           # e.g. AsrCam
    # Derive module suffix: AsrCam → Cam, AsrBsm → Bsm
    suffix    = asr_name[3:]          # strip leading 'Asr'

    # Extract both args: {{ObsSet}, {EvSet}}
    b_open  = m.end() - 1
    b_close = matching_brace(text, b_open)
    args_text = text[b_open + 1: b_close].strip()
    args = split_args(args_text)      # ['{ObsSet}', '{EvSet}']
    obs_ios_name = args[0].strip('{}').strip()   # e.g. SetMbObsTgtsCam

    # Parse the ObsTgts IOS to get (single_obs_ios, tgt_id) pairs
    entries = _parse_obs_tgts_ios(text, obs_ios_name)

    # 1. Generate MbSingleObservation-XxxFoo types
    obs_types = []
    mb_type_blocks = []
    for (single_ios, tgt_id) in entries:
        type_suffix = _suffix_from_ios_name(single_ios)  # e.g. CamBeacon
        flat_name   = f"MbSingleObservation-{type_suffix}"
        obs_types.append((flat_name, single_ios, tgt_id))
        mb_type_blocks.append(
            "-- Non-parameterized equivalent of MbSingleObservation{{" + single_ios + "}}.\n" +
            f"{flat_name} ::= SEQUENCE {{\n"
            f"  obsId  Uint8,\n"
            f"  obs    ANY\n"
            f"}}"
        )

    # 2. Intermediate container types
    container_blocks = [
        f"ObservationsByTarget-{suffix} ::= SEQUENCE {{\n"
        f"  tgtId         Uint8,\n"
        f"  observations  SEQUENCE OF ANY\n"
        f"}}",

        f"ObservationsByTargetSequence-{suffix} ::= SEQUENCE (SIZE(1..MAX)) OF "
        f"ObservationsByTarget-{suffix}",

        f"NonV2xPduEvidenceItem-{suffix} ::= SEQUENCE {{\n"
        f"  id        Uint8,\n"
        f"  evidence  ANY\n"
        f"}}",

        f"NonV2xPduEvidenceItemSequence-{suffix} ::= "
        f"SEQUENCE (SIZE(0..MAX)) OF NonV2xPduEvidenceItem-{suffix}",
    ]

    # 3. Expanded AsrXxx type
    note = ("-- Non-parameterized equivalent of "
            f"TemplateAsr{{{{{obs_ios_name}}}}}, {{...}}}}.")
    expanded_asr = (
        f"{note}\n"
        f"{asr_name} ::= SEQUENCE {{\n"
        f"  observations       ObservationsByTargetSequence-{suffix},\n"
        f"  v2xPduEvidence     SEQUENCE (SIZE(1..MAX)) OF V2xPduStream,\n"
        f"  nonV2xPduEvidence  NonV2xPduEvidenceItemSequence-{suffix}\n"
        f"}}"
    )

    # Replace the original AsrXxx ::= TemplateAsr {…} assignment
    new_block = (
        '\n\n'.join(mb_type_blocks) + '\n\n' +
        '\n\n'.join(container_blocks) + '\n\n' +
        expanded_asr
    )
    text = text[:m.start()] + new_block + text[b_close + 1:]

    # 4. Update the ObsTgts IOS to use flat type names (replace MbSingleObservation{{…}})
    for (flat_name, single_ios, tgt_id) in obs_types:
        # Replace {MbSingleObservation{{SetMbObsXxx}} BY tgtId} with {flat_name BY tgtId}
        ios_pat = re.compile(
            r'\{MbSingleObservation\s*\{\{' + re.escape(single_ios) + r'\}\}\s+BY\s+'
            + re.escape(tgt_id) + r'\}',
            re.DOTALL)
        text = ios_pat.sub(f'{{{flat_name} BY {tgt_id}}}', text)

    return text


# ═══════════════════════════════════════════════════════════════════════════════
#  Section 5 – Import management
# ═══════════════════════════════════════════════════════════════════════════════

def remove_from_imports(text: str, *names: str) -> str:
    """Remove each name from the IMPORTS section of text."""
    for name in names:
        # Match: optional leading comma+whitespace, name, optional trailing comma
        # Try removing `name,` (name is not last in the list)
        text = re.sub(
            r'(?m)^[ \t]*' + re.escape(name) + r',[ \t]*\n', '', text)
        # Try removing `,\n  name` (name is last before FROM)
        text = re.sub(
            r',\s*\n([ \t]*)' + re.escape(name) + r'(\s*\n[ \t]*FROM)',
            r'\2', text)
        # Try removing lone `  name\n` (name is only item before FROM)
        text = re.sub(
            r'(?m)^[ \t]*' + re.escape(name) + r'[ \t]*\n', '', text)
    return text


def add_to_imports(text: str, module_hint: str, *names: str) -> str:
    """
    Add names to the FROM <module_hint> import block.
    module_hint is a prefix/substring of the module name that uniquely
    identifies the FROM clause (e.g. 'Ieee1609Dot2Dot1Protocol').
    Names are appended as the last item(s) before the FROM line.
    If the block currently has NO items (empty FROM block), the first name
    becomes the sole item.
    """
    for name in names:
        # Case 1: there are already items before FROM - append after the last one
        pat_append = re.compile(
            r'([ \t]+\S[^\n]*)\n([ \t]*FROM\s+' + re.escape(module_hint) + r')',
            re.DOTALL)
        def _append(m, n=name):
            last = m.group(1).rstrip()
            from_line = m.group(2)
            return f"{last},\n  {n}\n{from_line}"
        new_text, count = pat_append.subn(_append, text, count=1)
        if count:
            text = new_text
            continue
        # Case 2: empty block - just FROM on a new line, insert name before it
        pat_empty = re.compile(
            r'(\n)([ \t]*FROM\s+' + re.escape(module_hint) + r')',
            re.DOTALL)
        def _insert(m, n=name):
            return f"\n  {n}\n{m.group(2)}"
        text = pat_empty.sub(_insert, text, count=1)
    return text


# ═══════════════════════════════════════════════════════════════════════════════
#  Section 6 – Per-file transformation functions
# ═══════════════════════════════════════════════════════════════════════════════

def transform_ieee1609dot2basetypes(text: str) -> str:
    text = remove_definition_block(text, 'Extension')
    return text


def transform_ieee1609dot2(text: str) -> str:
    text = remove_from_imports(text, 'Extension')
    text = expand_extension_instantiation(text)
    return text


def transform_etsi_extension_module(text: str) -> str:
    text = remove_definition_block(text, 'Extension')
    text = expand_extension_instantiation(text)
    return text


def transform_etsi_103097_module(text: str) -> str:
    for tname in ['EtsiTs103097Data-Unsecured',
                  'EtsiTs103097Data-Signed',
                  'EtsiTs103097Data-Encrypted',
                  'EtsiTs103097Data-SignedAndEncrypted',
                  'EtsiTs103097Data-Encrypted-Unicast',
                  'EtsiTs103097Data-SignedAndEncrypted-Unicast']:
        text = remove_definition_block(text, tname)
    return text


def transform_etsi_103759_basetypes(text: str) -> str:
    for tname in ['TemplateAsr',
                  'ObservationsByTarget',
                  'ObservationsByTargetSequence',
                  'MbSingleObservation',
                  'NonV2xPduEvidenceItem',
                  'NonV2xPduEvidenceItemSequence']:
        text = remove_definition_block(text, tname)

    # V2xPduStream: replace IOC-typed fields with concrete types
    text = re.sub(
        r'C-OBS-PDU\.&id\s*\(\{SetObsPdu\}\)',
        'IdObsPdu', text)
    text = re.sub(
        r'SEQUENCE\s*\(SIZE\s*\(1\.\.255\)\)\s*OF\s*C-OBS-PDU\.&Val\s*'
        r'\(\{SetObsPdu\}\{@\.type\}\)',
        'SEQUENCE (SIZE (1..255)) OF ANY', text)
    return text


def transform_etsi_103759_core(text: str) -> str:
    # Expand EtsiTs103097Data-Signed and EtsiTs103097Data-SignedAndEncrypted-Unicast
    text = expand_all_instantiations(text)
    # Replace the template imports with the concrete base type they expand to
    text = remove_from_imports(text,
        'EtsiTs103097Data-Signed',
        'EtsiTs103097Data-SignedAndEncrypted-Unicast')
    text = add_to_imports(text, 'EtsiTs103097Module', 'EtsiTs103097Data')
    # AidSpecificReport.content: replace IOC open type with ANY
    text = re.sub(
        r'C-ASR\.&AidSpecificReport\s*\(\{[^}]+\}\{@\.[^}]+\}\)',
        'ANY', text)
    text = re.sub(
        r'C-ASR\.&AidSpecificReport\b[^,\n)]*',
        'ANY', text)
    return text


def transform_etsi_asr_file(text: str) -> str:
    """Handle any AsrXxx file (AsrCam, AsrBsm, ...)."""
    # Remove imports for parameterized templates that no longer exist
    text = remove_from_imports(text, 'MbSingleObservation', 'TemplateAsr')
    # The TemplateAsr expansion uses V2xPduStream directly
    text = add_to_imports(text, 'EtsiTs103759BaseTypes', 'V2xPduStream')
    # Expand TemplateAsr instantiation
    text = handle_template_asr(text)
    return text


def transform_sae_j3287(text: str) -> str:
    text = expand_all_instantiations(text)
    text = remove_from_imports(text,
        'Ieee1609Dot2Data-Signed',
        'Ieee1609Dot2Data-SignedEncrypted',
        'SequenceOfCertificate',
        'SignerIdentifier')
    # The expanded types use SignerSingleCert from Ieee1609Dot2Dot1Protocol
    text = add_to_imports(text, 'Ieee1609Dot2Dot1Protocol', 'SignerSingleCert')
    return text


def transform_ieee_dot1_protocol(text: str) -> str:
    for tname in ['ScmsPdu-Scoped',
                  'Ieee1609Dot2Data-Unsecured',
                  'Ieee1609Dot2Data-Signed',
                  'Ieee1609Dot2Data-Encrypted',
                  'Ieee1609Dot2Data-SignedCertRequest',
                  'Ieee1609Dot2Data-SignedX509AuthenticatedCertRequest',
                  'Ieee1609Dot2Data-SignedEncrypted',
                  'Ieee1609Dot2Data-EncryptedSigned',
                  'Ieee1609Dot2Data-SignedEncryptedCertRequest',
                  'Ieee1609Dot2Data-SymmEncryptedSingleRecipient']:
        text = remove_definition_block(text, tname)
    text = expand_all_instantiations(text)
    return text


def transform_ieee_dot1_aca_ra(text: str) -> str:
    # Expand Ieee1609Dot2Data-SymmEncryptedSingleRecipient inline in EncryptedIndividualPLV
    text = expand_all_instantiations(text)
    text = remove_from_imports(text, 'Ieee1609Dot2Data-SymmEncryptedSingleRecipient')
    # The SymmEncrypted expansion uses Ieee1609Dot2Data directly
    text = add_to_imports(text, 'Ieee1609Dot2Dot1Protocol', 'Ieee1609Dot2Data')
    return text


def transform_ieee_dot1_acpc(text: str) -> str:
    text = expand_all_instantiations(text)
    text = remove_from_imports(text,
        'Ieee1609Dot2Data-Unsecured',
        'Ieee1609Dot2Data-Signed')
    # Expansions use Ieee1609Dot2Data (from Ieee1609Dot2) and SignerSingleCert (from Protocol)
    # Add Ieee1609Dot2Data before the existing Ieee1609Dot2BaseTypes FROM block
    text = re.sub(
        r'(IMPORTS\b)',
        r'\1\n  Ieee1609Dot2Data'
        r'\nFROM Ieee1609Dot2 {iso(1) identified-organization(3) ieee(111)'
        r'\n  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)'
        r'\n  base(1) schema(1) major-version-2(2) minor-version-5(5)}'
        r'\nWITH SUCCESSORS\n',
        text, count=1)
    text = add_to_imports(text, 'Ieee1609Dot2Dot1Protocol', 'SignerSingleCert')
    return text


def transform_ieee_dot1_cert_management(text: str) -> str:
    # MultiSignedCtl: replace IOC open type fields with ANY
    text = re.sub(
        r'tbsCtl\s+[A-Z][A-Za-z0-9.&{}() \t\n]+(?=,\s*\n\s*unsigned)',
        'tbsCtl      ANY', text)
    text = re.sub(
        r'unsigned\s+[A-Z][A-Za-z0-9.&{}() \t\n]+(?=,\s*\n\s*signatures)',
        'unsigned    ANY', text)
    return text


# ═══════════════════════════════════════════════════════════════════════════════
#  Section 7 – File dispatch table and main driver
# ═══════════════════════════════════════════════════════════════════════════════

# Maps filename → transformation function (text → text).
# Files not listed here are copied unchanged.
FILE_TRANSFORMERS = {
    'Ieee1609Dot2BaseTypes.asn':            transform_ieee1609dot2basetypes,
    'Ieee1609Dot2.asn':                     transform_ieee1609dot2,
    'EtsiTs103097ExtensionModule.asn':      transform_etsi_extension_module,
    'EtsiTs103097Module.asn':              transform_etsi_103097_module,
    'EtsiTs103759BaseTypes.asn':           transform_etsi_103759_basetypes,
    'EtsiTs103759Core.asn':               transform_etsi_103759_core,
    'EtsiTs103759AsrCam.asn':             transform_etsi_asr_file,
    'SaeJ3287AsrBsm.asn':                 transform_etsi_asr_file,
    'SaeJ3287.asn':                        transform_sae_j3287,
    'Ieee1609Dot2Dot1Protocol.asn':        transform_ieee_dot1_protocol,
    'Ieee1609Dot2Dot1AcaRaInterface.asn':  transform_ieee_dot1_aca_ra,
    'Ieee1609Dot2Dot1Acpc.asn':           transform_ieee_dot1_acpc,
    'Ieee1609Dot2Dot1CertManagement.asn': transform_ieee_dot1_cert_management,
}


def process_file(src_path: Path, dst_path: Path) -> None:
    text = src_path.read_text(encoding='utf-8', errors='replace')
    transformer = FILE_TRANSFORMERS.get(src_path.name)
    if transformer:
        print(f"  Transforming  {src_path.name}")
        text = transformer(text)
    else:
        print(f"  Copying       {src_path.name}")
    dst_path.write_text(text, encoding='utf-8', errors='replace')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Translate parameterized ASN.1 modules to non-parameterized form.')
    parser.add_argument('--src', default='asn/J3287_ASN',
                        help='Source directory (default: asn/J3287_ASN)')
    parser.add_argument('--dst', default='asn/J3287_ASN_flat',
                        help='Destination directory (default: asn/J3287_ASN_flat)')
    args = parser.parse_args()

    src_dir = Path(args.src)
    dst_dir = Path(args.dst)

    if not src_dir.is_dir():
        sys.exit(f"ERROR: source directory not found: {src_dir}")

    dst_dir.mkdir(parents=True, exist_ok=True)

    asn_files = sorted(src_dir.glob('*.asn'))
    if not asn_files:
        sys.exit(f"ERROR: no .asn files found in {src_dir}")

    print(f"Source : {src_dir.resolve()}")
    print(f"Output : {dst_dir.resolve()}")
    print(f"Files  : {len(asn_files)}\n")

    for src_path in asn_files:
        dst_path = dst_dir / src_path.name
        try:
            process_file(src_path, dst_path)
        except Exception as exc:
            print(f"  ERROR processing {src_path.name}: {exc}", file=sys.stderr)
            raise

    print(f"\nDone. {len(asn_files)} files written to {dst_dir}/")


if __name__ == '__main__':
    main()
