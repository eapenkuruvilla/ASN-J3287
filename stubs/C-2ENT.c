/*
 * Stub for IOC CLASS C-2ENT.
 * Implemented as ANY (open type) since IOC classes have no wire encoding.
 */
#include "C-2ENT.h"
#include <asn_internal.h>

int
C_2ENT_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                  asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    return asn_generic_no_constraint(td, sptr, ctfailcb, app_key);
}

asn_TYPE_operation_t asn_OP_C_2ENT;  /* alias for asn_OP_ANY, set at startup */

asn_TYPE_descriptor_t asn_DEF_C_2ENT = {
    "C-2ENT",
    "C-2ENT",
    &asn_OP_ANY,
    0, 0, 0, 0,
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
        C_2ENT_constraint
    },
    0, 0,
    0
};
