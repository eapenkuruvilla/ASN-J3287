/*
 * decode_shim.c — unified OER→JER decoder for libdecode.so.
 *
 * Exports:
 *   decode_oer_to_jer()  – decode COER bytes as a named PDU, return JSON
 *   free_buffer()        – release memory returned by decode_oer_to_jer()
 *
 * The PDU dispatch table is in the auto-generated pdu_table.c.
 */

#include "decode_shim.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <jer_encoder.h>
#include <constr_TYPE.h>

/* ── Growing output buffer ──────────────────────────────────────────────── */

typedef struct {
    char   *data;
    size_t  used;
    size_t  capacity;
} growbuf_t;

static int growbuf_cb(const void *buf, size_t size, void *app_key)
{
    growbuf_t *gb = (growbuf_t *)app_key;
    if (gb->used + size + 1 > gb->capacity) {
        size_t new_cap = (gb->capacity + size) * 2;
        char *p = (char *)realloc(gb->data, new_cap);
        if (!p) return -1;
        gb->data = p;
        gb->capacity = new_cap;
    }
    memcpy(gb->data + gb->used, buf, size);
    gb->used += size;
    gb->data[gb->used] = '\0';
    return 0;
}

/* ── PDU lookup ─────────────────────────────────────────────────────────── */

static asn_TYPE_descriptor_t *find_pdu(const char *name)
{
    for (pdu_entry_t *e = pdu_table; e->name != NULL; e++) {
        if (strcmp(e->name, name) == 0)
            return e->td;
    }
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int decode_oer_to_jer(
    const char *pdu_name,
    const void *data, size_t data_len,
    char      **json_out,
    char       *err_buf, size_t err_size)
{
    *json_out = NULL;

    asn_TYPE_descriptor_t *td = find_pdu(pdu_name);
    if (!td) {
        snprintf(err_buf, err_size, "Unknown PDU type: '%s'", pdu_name);
        return -1;
    }

    /* Decode OER/COER */
    void *sptr = NULL;
    asn_dec_rval_t rval = asn_decode(
        NULL, ATS_BASIC_OER, td, &sptr, data, data_len);

    if (rval.code != RC_OK) {
        if (sptr) ASN_STRUCT_FREE(*td, sptr);
        snprintf(err_buf, err_size,
                 "Decode failed at byte %zu (asn1c code %d)",
                 rval.consumed, (int)rval.code);
        return -1;
    }

    /* Encode to JER */
    growbuf_t gb;
    gb.data     = (char *)malloc(4096);
    gb.used     = 0;
    gb.capacity = 4096;
    if (!gb.data) {
        ASN_STRUCT_FREE(*td, sptr);
        snprintf(err_buf, err_size, "Out of memory");
        return -1;
    }

    asn_enc_rval_t erval = jer_encode(td, sptr, JER_F_MINIFIED, growbuf_cb, &gb);
    ASN_STRUCT_FREE(*td, sptr);

    if (erval.encoded < 0) {
        free(gb.data);
        snprintf(err_buf, err_size, "JER encode failed (encoded=%zd)", erval.encoded);
        return -1;
    }

    *json_out = gb.data;
    return 0;
}

void free_buffer(void *ptr)
{
    free(ptr);
}

int encode_jer_to_oer(
    const char *pdu_name,
    const char *json_in,
    void      **oer_out,
    size_t     *oer_len,
    char       *err_buf, size_t err_size)
{
    *oer_out = NULL;
    *oer_len = 0;

    asn_TYPE_descriptor_t *td = find_pdu(pdu_name);
    if (!td) {
        snprintf(err_buf, err_size, "Unknown PDU type: '%s'", pdu_name);
        return -1;
    }

    /* Decode JER → in-memory ASN.1 structure */
    void *sptr = NULL;
    asn_dec_rval_t rval = asn_decode(
        NULL, ATS_JER, td, &sptr, json_in, strlen(json_in));

    if (rval.code != RC_OK) {
        if (sptr) ASN_STRUCT_FREE(*td, sptr);
        snprintf(err_buf, err_size,
                 "JER decode failed at byte %zu (code %d)",
                 rval.consumed, (int)rval.code);
        return -1;
    }

    /* Encode in-memory structure → COER bytes */
    asn_encode_to_new_buffer_result_t res =
        asn_encode_to_new_buffer(NULL, ATS_BASIC_OER, td, sptr);
    ASN_STRUCT_FREE(*td, sptr);

    if (!res.buffer) {
        snprintf(err_buf, err_size,
                 "OER encode failed (errno=%d)", errno);
        return -1;
    }

    *oer_out = res.buffer;
    *oer_len = (size_t)res.result.encoded;
    return 0;
}
