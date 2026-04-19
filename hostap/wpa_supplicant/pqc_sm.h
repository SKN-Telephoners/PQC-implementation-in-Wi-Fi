#ifndef PQC_PAKE_H
#define PQC_PAKE_H

#include "../utils/common.h"

#define PQC_R_LEN 32
#define PQC_SID_LEN 16


/*
* main struct used in PQC implementation
*/
struct wpa_pqc_sm {
    struct wpa_supplicant *wpa_s; // main context

    // config and negotiation
    u8 pqc_choice; // algorithm
    int pqc_enabled; // if PQC is used

    // PAKE
    /* PLACEHOLDER - these values should be populated from previous steps */
    u8 K_aes[32]; // derived before PAKE-1
    u8 id[16]; // random
    u8 pwd[64]; // Wi-Fi password
    size_t pwd_len; // TODO: it needs to be read from config file 

    u8 *fsid; // counted before sending PAKE-3
    size_t fsid_len; 
    u8 *kem_secret_key; // needed for PAKE-4, generated before sending PAKE-3
    size_t kem_secret_key_len;

    // DSA
    u8 *dsa_public_key;     
    u8 *dsa_secret_key;
    size_t dsa_keys_len;
}; 

struct wpa_pqc_sm * pqc_sm_init(struct wpa_supplicant *wpa_s, u8 negotiated_choice);
void pqc_sm_deinit(struct wpa_pqc_sm *sm);
int pqc_sm_rx_pake2(struct wpa_pqc_sm *sm, const u8 *enc_sid, size_t enc_sid_len);

#endif 