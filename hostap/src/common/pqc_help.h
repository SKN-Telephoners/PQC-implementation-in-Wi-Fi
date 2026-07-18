#ifndef PQC_HELP_H
#define PQC_HELP_H

#include "../utils/common.h"
#include "../common/ieee802_11_defs.h"

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

/* Vendor-specific Action type for PQC/PASN */
#define PQC_OUI_TYPE_PASN      0x11

/* PASN subtypes */
#define PQC_PASN_TYPE_1        0x01  /* PASN-1: STA -> AP (ML-KEM pub key) */
#define PQC_PASN_TYPE_2        0x02  /* PASN-2: AP -> STA (ciphertext + MIC1) */
#define PQC_PASN_TYPE_2_SIG    0x03  /* PASN-2-SIG: AP -> STA (ML-DSA signature fragments) */
#define PQC_PASN_TYPE_3        0x04  /* PASN-3: STA -> AP (MIC2) */
#define PQC_PASN_TYPE_4        0x05  /* PASN-4: AP -> STA ({GTK} + {IGTK} + MIC3) */

/* other useful */
#define MIC_LEN                32
#define PTK_LEN                48
#define KEK_LEN                16
#define KCK_LEN                16
#define TK_LEN                 16
#define PMK_LEN                32
#define ID_LEN                 16
#define TAG_LEN                32
#define AES_KEY_LEN            32
#define TIMES_AES_WRAP         4

/* Fragmentation definitions */
#define PQC_FRAG_HDR_LEN 8 /* 4 bytes total_len + 4 bytes offset */
#define PQC_FRAG_MAX_SIZE 800

const char* get_oqs_kem_alg(u8 pqc_choice);
const char*  get_oqs_dsa_alg(u8 pqc_choice);
int get_oqs_kem_pub_len(u8 pqc_choice);

int pqc_pbkdf2_sha256(const char *passphrase, const u8 *salt, size_t salt_len,
                     int iterations, u8 *buf, size_t buflen);

int pqc_derive_pasn_ptk(const u8 *pmk, const u8 *sta_mac, const u8 *ap_mac,
                       const u8 *shared_secret, size_t shared_secret_len,
                       u8 *out_ptk);

int pqc_2f_inverse(const u8 *K, size_t K_len, const u8 *s, size_t s_len, const u8 *T, size_t T_len, u8 *r, u8 *M);
int pqc_2f_network(const u8 *K, size_t K_len, const u8 *r, size_t r_len, const u8 *M, size_t M_len, u8 *s, u8 *T);

/* Function pointer definition for agnostic transmission */
typedef int (*pqc_tx_action_cb)(void *ctx, const u8 *dst_mac, const u8 *data, size_t data_len);

/* Shared Fragmentation Functions */
int pqc_send_fragmented_action_frame(void *ctx, pqc_tx_action_cb tx_cb, 
                                     const u8 *dst_mac, u8 oui_type, u8 subtype, 
                                     const u8 *payload, size_t payload_len);

struct wpabuf * pqc_reassemble_fragment(struct wpabuf **sm_buf, 
                                        u32 total_len, u32 offset,
                                        const u8 *frag_payload, size_t frag_len);


#endif // PQC_HELP_H