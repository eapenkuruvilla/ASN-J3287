/*
 * Stub for IOC CLASS C-2ENT.
 *
 * C-2ENT is an Information Object Class (not a wire-encoded data type).
 * asn1c cannot generate a proper implementation for it; we represent it
 * as ANY (open type) so that aliases such as C-ASR-EV, C-ASR-OBS-BY-TGT,
 * C-ASR-SINGLE-OBS, and C-OBS-PDU compile correctly.
 */
#ifndef _C_2ENT_H_
#define _C_2ENT_H_

#include <asn_application.h>
#include <ANY.h>

#ifdef __cplusplus
extern "C" {
#endif

/* C-2ENT (IOC CLASS) — no wire encoding; represented as ANY */
typedef ANY_t C_2ENT_t;

extern asn_TYPE_descriptor_t asn_DEF_C_2ENT;
extern asn_TYPE_operation_t  asn_OP_C_2ENT;

asn_constr_check_f C_2ENT_constraint;

#ifdef __cplusplus
}
#endif

#endif /* _C_2ENT_H_ */
#include <asn_internal.h>
