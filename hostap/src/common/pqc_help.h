#ifndef PQC_HELP_H
#define PQC_HELP_H

#include "../utils/common.h"

#define PQC_R_LEN 32
#define PQC_SID_LEN 16


/* OUI used for PQC Vendor-Specific Action Frames */
#define PQC_OUI_0              0x00
#define PQC_OUI_1              0x90
#define PQC_OUI_2              0x4C

/* Vendor-specific Action type for PQC/PAKE */
#define PQC_OUI_TYPE_PAKE      0x10

/* PAKE subtypes */
#define PQC_PAKE_TYPE_1        0x01  /* PAKE-1: STA -> AP */
#define PQC_PAKE_TYPE_2        0x02  /* PAKE-2: AP -> STA */
#define PQC_PAKE_TYPE_3        0x03  /* already used in PAKE-3 */
#define PQC_PAKE_TYPE_4        0x04  /* reserved for PAKE-4 */

const char* get_oqs_kem_alg(u8 pqc_choice);
const char* get_oqs_dsa_alg(u8 pqc_choice);
int pqc_2f_inverse(const u8 *K, size_t K_len, const u8 *s, size_t s_len, const u8 *T, size_t T_len, u8 *r, u8 *M);
int pqc_2f_network(const u8 *K, size_t K_len, const u8 *r, size_t r_len, const u8 *M, size_t M_len, u8 *s, u8 *T);

#endif // PQC_HELP_H