#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpabuf.h"  
#include "crypto/sha256.h"     
#include "pqc_help.h"
#include <oqs/oqs.h>

/**
 * get_oqs_kem_alg - Maps the PQC KEM bitmask to liboqs algorithm string
 */
const char* get_oqs_kem_alg(u8 pqc_choice) {
    if (pqc_choice & 0x80) return OQS_KEM_alg_ml_kem_512;
    if (pqc_choice & 0x40) return OQS_KEM_alg_ml_kem_768;
    if (pqc_choice & 0x20) return OQS_KEM_alg_ml_kem_1024;
    return NULL;
}

/**
 * get_oqs_dsa_alg - Maps the PQC DSA bitmask to liboqs algorithm string
 */
const char* get_oqs_dsa_alg(u8 pqc_choice) {
    if (pqc_choice & 0x08) return OQS_SIG_alg_ml_dsa_44;
    if (pqc_choice & 0x04) return OQS_SIG_alg_ml_dsa_65;
    if (pqc_choice & 0x02) return OQS_SIG_alg_ml_dsa_87;
    return NULL;
}

/**
 * pqc_2f_network - Implements the Double Feistel Network (2F)
 * T = M (dot) H1(K, r)
 * s = r (XOR) H2(K, T)
 */
int pqc_2f_network(const u8 *K, size_t K_len,
                          const u8 *r, size_t r_len,
                          const u8 *M, size_t M_len,
                          u8 *s, u8 *T) {
    u8 R_val[32]; /* Result of H1 (HMAC-SHA256) */
    u8 t_val[32]; /* Result of H2 (HMAC-SHA256) */
    size_t i;

    /* 1. H1(K, r) -> R */
    if (hmac_sha256(K, K_len, r, r_len, R_val) < 0)
        return -1;

    /* 2. T = M (dot) R */
    /* Operational logic: Modular addition byte-by-byte (modulo 256) */
    for (i = 0; i < M_len; i++) {
        T[i] = (u8)((M[i] + R_val[i % sizeof(R_val)]) & 0xFF);
    }

    /* 3. H2(K, T) -> t */
    if (hmac_sha256(K, K_len, T, M_len, t_val) < 0)
        return -1;

    /* 4. s = r XOR t */
    for (i = 0; i < r_len; i++) {
        s[i] = r[i] ^ t_val[i % sizeof(t_val)];
    }

    return 0;
}

/**
 * pqc_2f_inverse - Implements the Double Feistel Network (2F)
 */
int pqc_2f_inverse(const u8 *K, size_t K_len, 
                          const u8 *s, size_t s_len, 
                          const u8 *T, size_t T_len, 
                          u8 *r, u8 *M) {
    u8 R_val[32];
    u8 t_val[32];
    size_t i;

    /* 1. 't' -> t = H2(K, T) */
    if (hmac_sha256(K, K_len, T, T_len, t_val) < 0) return -1;

    /* 2. 'r' -> r = s XOR t */
    for (i = 0; i < s_len; i++) {
        r[i] = s[i] ^ t_val[i % sizeof(t_val)];
    }

    /* 3. 'R' -> R = H1(K, r) */
    if (hmac_sha256(K, K_len, r, s_len, R_val) < 0) return -1;

    /* 4. 'M' (Z) -> M = T (minus mod 256) R */
    for (i = 0; i < T_len; i++) {
        M[i] = (u8)((T[i] - R_val[i % sizeof(R_val)]) & 0xFF);
    }

    return 0;
}