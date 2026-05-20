#ifndef PQC_AP_SM_H
#define PQC_AP_SM_H

#include "../utils/common.h"
#include "../src/common/pqc_help.h"

/*
* main struct used in PQC implementation (AP)
*/
struct hostapd_pqc_sm {
    struct hostapd_data *hapd;
    struct sta_info *sta;    /* pointer to client */

    u8 pqc_choice;
    int pqc_enabled; // if PQC is used

    u8 K_aes[32]; // derived after PAKE-1
    u8 sid[16]; // random
    u8 pwd[128];    /* from AP config */
    size_t pwd_len;
    
    u8 *fsid;   /* computed during construction of PAKE-2 */
    size_t fsid_len;

    /* Parameters from PAKE-3 (STA) */
    u8 s[PQC_R_LEN];
    u8 *T;
    size_t T_len;

    /* PQC keys */
    u8 *dsa_pub_key;
    size_t dsa_pub_key_len;
    u8 *dsa_secret_key;
    size_t dsa_secret_key_len;
    u8 *kem_pub_key;
    size_t kem_pub_key_len;
    u8 *kem_secret_key;
    size_t kem_secret_key_len;

    u8 *sta_first_kem_public_key;  /* psk (Z) */
    size_t sta_first_kem_pub_len;

    u8 *shared_secret_K;       /* K - derived after encapsulation */
    size_t shared_secret_K_len;

    u8 *ciphertext_2;          /* c - generated during encapsulation */
    size_t ciphertext_2_len;

    // PASN
    u8 *ap_mldsa_public_key;   /* ML-DSA public key (AP) generated during PAKE */
    size_t ap_mldsa_public_len;
    u8 *ap_mldsa_secret_key;   /* ML-DSA secret key (AP) generated during PAKE */
    size_t ap_mldsa_secret_len;
    u8 *sta_mldsa_public_key;  /* ML-DSA public key (STA) received in PASN-1 */
    size_t sta_mldsa_public_len;

    /* PASN-2 derived materials */
    u8 *pasn_ciphertext;       /* ML-KEM ciphertext (AP generated) */
    size_t pasn_ciphertext_len;
    u8 *pasn_shared_secret;    /* PQC shared secret from ML-KEM encapsulation */
    size_t pasn_shared_secret_len;
    u8 *pasn_dsa_signature;    /* ML-DSA signature over ciphertext */
    size_t pasn_dsa_signature_len;

    u8 pasn_ptk[32];           /* PTK - Pairwise Transient Key */
    u8 pasn_kek[16];           /* Key Encryption Key */
    u8 pasn_kck[16];           /* Key Confirmation Key */
    u8 pasn_tk[16];            /* Temporal Key */
    u8 pasn_mic1[32];          /* MIC1 for PASN-2 */
};

struct hostapd_pqc_sm * pqc_ap_sm_init(struct hostapd_data *hapd, struct sta_info *sta);
void pqc_ap_sm_deinit(struct hostapd_pqc_sm *sm);
int pqc_ap_sm_derive_pmk(struct hostapd_pqc_sm *sm, u8 *pmk_out);

#endif /* PQC_AP_SM_H */