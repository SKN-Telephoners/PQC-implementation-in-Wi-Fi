

#ifndef PQC_PAKE_H
#define PQC_PAKE_H

#include "utils/common.h"

/* OUI used for PQC Vendor-Specific Action Frames */
#define PQC_OUI_0              0x00
#define PQC_OUI_1              0x90
#define PQC_OUI_2              0x4C

/* Vendor-specific Action type for PQC/PAKE */
#define PQC_OUI_TYPE_PAKE      0x10

/* PAKE subtypes */
#define PQC_PAKE_TYPE_1        0x01  /* PAKE-1 */
#define PQC_PAKE_TYPE_2        0x02  /* PAKE-2 */
#define PQC_PAKE_TYPE_3        0x03  /* PAKE-3 */
#define PQC_PAKE_TYPE_4        0x04  /* PAKE-4 */


struct pqc_pake1_fields {
    u8  pake_type;   /* PQC_PAKE_TYPE_1 */
    const u8 *c;     /* ML-KEM ciphertext */
    size_t c_len;
    const u8 *enc_id; /* AES-256(id) */
    size_t id_len;
};

/* Minimal logical representation of PAKE-2 payload */
struct pqc_pake2_fields {
    u8  pake_type;   /* PQC_PAKE_TYPE_2 */
    const u8 *enc_sid; /* AES-256(sid) */
    size_t sid_len;
    const u8 *dp;      /* fsid or H(fsid) */
    size_t dp_len;
};

/*
 * Serialize PAKE-1 into buffer:
 *  [pake_type][c_len(2B)][c][id_len(2B)][enc_id]
 * Returns total length on success, 0 on error (buffer too small).
 */
size_t pqc_build_pake1(u8 *buf, size_t buf_len,
               const struct pqc_pake1_fields *f);

/*
 * Parse PAKE-1 from buffer into fields struct.
 * Does not allocate memory, only sets pointers into buf.
 * Returns 0 on success, -1 on error.
 */
int pqc_parse_pake1(const u8 *buf, size_t len,
            struct pqc_pake1_fields *out);

/*
 * Serialize PAKE-2 into buffer:
 *  [pake_type][sid_len(2B)][enc_sid][dp_len(2B)][dp]
 */
size_t pqc_build_pake2(u8 *buf, size_t buf_len,
               const struct pqc_pake2_fields *f);

int pqc_parse_pake2(const u8 *buf, size_t len,
            struct pqc_pake2_fields *out);

#endif /* PQC_PAKE_H */
