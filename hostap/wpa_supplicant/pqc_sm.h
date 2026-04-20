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
    u8 pwd[128]; // Wi-Fi password
    size_t pwd_len; // TODO: it needs to be read from config file 

    u8 *fsid; // counted before sending PAKE-3
    size_t fsid_len; 
    /* ML-KEM */
    u8 *ap_kem_public_key;  // pk: public key from AP (from Probe Response)
    size_t ap_kem_pub_len;
    u8 *kem_secret_key; // ssk: secret key (STA) needed for PAKE-4, generated before sending PAKE-3
    size_t kem_secret_key_len;
    u8 *sta_kem_public_key; // psk: public key STA (send in PAKE-3 as Z)
    size_t sta_kem_pub_len;
    u8 *sta_second_secret_key; // seck: secret key (STA) generated after association response
    size_t sta_second_secret_len; 
    u8 *sta_second_pub_key; //pubk: public key (STA) generated after association response
    size_t sta_second_pub_len;

    // ML-DSA
    u8 *dsa_public_key;     
    size_t dsa_keys_len;
}; 
struct wpa_pqc_sm * pqc_sm_init(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);
void pqc_sm_deinit(struct wpa_pqc_sm *sm);
int pqc_sm_rx_pake2(struct wpa_pqc_sm *sm, const u8 *enc_sid, size_t enc_sid_len);

#endif 