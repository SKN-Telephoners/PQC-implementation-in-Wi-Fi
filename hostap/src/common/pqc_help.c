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

int pqc_pbkdf2_sha256(const char *passphrase, const u8 *salt, size_t salt_len,
                     int iterations, u8 *buf, size_t buflen)
{
    u8 counter[4];
    u8 u[32], t[32];
    u8 *pos = buf;
    size_t left = buflen;
    unsigned int i, j, block = 1;

    while (left > 0) {
        size_t clen = left > 32 ? 32 : left;

        WPA_PUT_BE32(counter, block);
        /* T_i = U_1 = hmac_sha256(salt || block_counter) */
        struct wpabuf *salt_buf = wpabuf_alloc(salt_len + 4);
        if (!salt_buf) return -1;
        wpabuf_put_data(salt_buf, salt, salt_len);
        wpabuf_put_data(salt_buf, counter, 4);

        hmac_sha256((u8 *)passphrase, 32, wpabuf_head(salt_buf), wpabuf_len(salt_buf), u);
        wpabuf_free(salt_buf);

        os_memcpy(t, u, 32);

        for (i = 1; i < (unsigned int)iterations; i++) {
            hmac_sha256((u8 *)passphrase, 32, u, 32, u);
            for (j = 0; j < 32; j++)
                t[j] ^= u[j];
        }

        os_memcpy(pos, t, clen);
        pos += clen;
        left -= clen;
        block++;
    }
    return 0;
}

int pqc_derive_pasn_ptk(const u8 *pmk, const u8 *sta_mac, const u8 *ap_mac,
                       const u8 *shared_secret, size_t shared_secret_len,
                       u8 *out_ptk)
{
    const char *label = "PASN key deriviation";
    size_t label_len = os_strlen(label);
    u8 *salt;
    size_t salt_len;
    int ret;

    /* Salt structure: label || MAC_STA || MAC_AP || shared_secret */
    salt_len = label_len + ETH_ALEN + ETH_ALEN + shared_secret_len;
    salt = os_malloc(salt_len);
    if (!salt) return -1;

    os_memcpy(salt, label, label_len);
    os_memcpy(salt + label_len, sta_mac, ETH_ALEN);
    os_memcpy(salt + label_len + ETH_ALEN, ap_mac, ETH_ALEN);
    os_memcpy(salt + label_len + (2 * ETH_ALEN), shared_secret, shared_secret_len);

    /* Use our local standalone PBKDF2 */
    ret = pqc_pbkdf2_sha256((const char *)pmk, salt, salt_len, 4096, out_ptk, 32);

    os_free(salt);
    return ret;
}