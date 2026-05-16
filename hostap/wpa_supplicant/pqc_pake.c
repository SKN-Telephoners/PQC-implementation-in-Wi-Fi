#include "includes.h"
#include "common.h"
#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "utils/os.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "bss.h"
#include "sme.h"
#include <oqs/oqs.h>
#include "rsn_supp/wpa.h"
#include "../src/common/pqc_help.h"
#include "pqc_sm.h"

int wpas_pqc_send_pake3(struct wpa_pqc_sm *sm, const u8 *s, size_t s_len, const u8 *T, size_t T_len);

/* building and sending PAKE1 */
int wpas_pqc_send_pake1(struct wpa_pqc_sm *sm, const u8 *c, size_t c_len, const u8 *enc_id, size_t enc_id_len) {
    struct wpabuf *buf = NULL;
    int ret = -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Rozpoczecie budowy ramki PAKE-1");

    /* Length: Cat (1) + Action (1) + OUI (3) + Type (1) + Subtype (1) + c_len (2) + c + id_len (2) + enc_id */
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + 2 + c_len + 2 + enc_id_len;
    buf = wpabuf_alloc(frame_len);
    if (!buf) return -1;

    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);          // Cat: 4
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);     // Action: 9
    
    wpabuf_put_u8(buf, PQC_OUI_0);                   // OUI 0
    wpabuf_put_u8(buf, PQC_OUI_1);                   // OUI 1
    wpabuf_put_u8(buf, PQC_OUI_2);                   // OUI 2
    
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PAKE);           // PQC Type
    wpabuf_put_u8(buf, PQC_PAKE_TYPE_1);             // Subtype: PAKE-1

    /* Payload */
    wpabuf_put_be16(buf, c_len);
    wpabuf_put_data(buf, c, c_len);
    
    wpabuf_put_be16(buf, enc_id_len);
    wpabuf_put_data(buf, enc_id, enc_id_len);

    unsigned int freq = sm->wpa_s->current_bss ? sm->wpa_s->current_bss->freq : 2412;
    const u8 *target_bssid = sm->wpa_s->pending_bssid;
    
    static const u8 zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
    if (os_memcmp(target_bssid, zero_mac, ETH_ALEN) == 0 && sm->wpa_s->current_bss) {
        target_bssid = sm->wpa_s->current_bss->bssid;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: Sending Public Action frame (PAKE-1) to: " MACSTR, MAC2STR(target_bssid));

    ret = wpa_drv_send_action(sm->wpa_s, freq, 0, target_bssid, 
                              sm->wpa_s->own_addr, target_bssid, 
                              wpabuf_head(buf), wpabuf_len(buf), 0);

    wpabuf_free(buf);
    return ret;
}

/* after receiving PAKE-2 */
int pqc_sm_rx_pake2(struct wpa_pqc_sm *sm, 
                    const u8 *payload, size_t payload_len) {
    u8 sid[PQC_SID_LEN]; 
    u8 r[PQC_R_LEN]; 
    u8 s[PQC_R_LEN];
    u8 *T = NULL;
    int ret = -1;
    OQS_KEM *kem = NULL;

    wpa_printf(MSG_DEBUG, "PQC_LOG: State Machine processing PAKE-2");
    
    if (payload_len <= PQC_SID_LEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PAKE-2 payload too short");
        return -1;
    }

    const u8 *enc_sid = payload;
    const u8 *dpk = payload + PQC_SID_LEN;
    size_t dpk_len = payload_len - PQC_SID_LEN;

    /* save ML-DSA key from AP (dpk) for later verification in PASN */
    if (sm->dsa_public_key) {
        os_free(sm->dsa_public_key);
    }
    sm->dsa_public_key = os_malloc(dpk_len);
    if (!sm->dsa_public_key) return -1;
    
    os_memcpy(sm->dsa_public_key, dpk, dpk_len);
    sm->dsa_keys_len = dpk_len; 

    wpa_printf(MSG_DEBUG, "PQC_LOG: Saved AP ML-DSA public key (len=%zu)", dpk_len);
    
    /* Decrypt {sid} using AES-256 with K_aes */
    /* PLACEHOLDER: K_aes derived earlier */
    void *aes_ctx = aes_decrypt_init(sm->K_aes, 32);
    if (!aes_ctx) return -1;
    aes_decrypt(aes_ctx, enc_sid, sid);
    aes_decrypt_deinit(aes_ctx);

    /* fsid = sid || id || MAC_AP || MAC_STA */
    sm->fsid_len = PQC_SID_LEN + sizeof(sm->id) + (2 * ETH_ALEN);
    sm->fsid = os_malloc(sm->fsid_len);
    if (!sm->fsid) return -1;

    u8 *pos = sm->fsid;
    os_memcpy(pos, sid, PQC_SID_LEN);                
    pos += PQC_SID_LEN;
    os_memcpy(pos, sm->id, sizeof(sm->id));          
    pos += sizeof(sm->id);
    os_memcpy(pos, sm->wpa_s->bssid, ETH_ALEN);      
    pos += ETH_ALEN; /* MAC AP */
    os_memcpy(pos, sm->wpa_s->own_addr, ETH_ALEN);   /* MAC STA */

    /* ML-KEM.KeyGen() = (ps_e, ss_e) */
    const char *alg_name = get_oqs_kem_alg(sm->pqc_choice);
    if (!alg_name) goto cleanup;

    kem = OQS_KEM_new(alg_name);
    if (!kem) goto cleanup;

    uint8_t *ps_e = os_malloc(kem->length_public_key);
    uint8_t *ss_e = os_malloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, ps_e, ss_e) != OQS_SUCCESS) {
        os_free(ps_e);
        OQS_MEM_secure_free(ss_e, kem->length_secret_key);
        goto cleanup;
    }

    /* Save KEM secret key for the next step (PAKE-4 decapsulation) */
    sm->kem_secret_key = ss_e;
    sm->kem_secret_key_len = kem->length_secret_key;

    /* 4. r <- random */
    if (os_get_random(r, PQC_R_LEN) < 0) {
        os_free(ps_e);
        goto cleanup;
    }

    /* 5. (s, T) = 2F(pwd, r, Z) */
    T = os_malloc(kem->length_public_key);
    if (!T) { 
        os_free(ps_e); 
        goto cleanup; 
    }

    sm->T = T;
    sm->T_len = kem->length_public_key;

    if (pqc_2f_network(sm->pwd, sm->pwd_len, r, PQC_R_LEN, ps_e, kem->length_public_key, s, T) < 0) {
        os_free(ps_e); 
        os_free(T); 
        goto cleanup;
    }

    os_memcpy(sm->s, s, PQC_R_LEN);

    /* 6. Send PAKE-3(s, T) */
    wpa_printf(MSG_INFO, "PQC_LOG: PAKE-3 data ready (s_len=%d, T_len=%zu)", PQC_R_LEN, kem->length_public_key);
    
    if (wpas_pqc_send_pake3(sm, s, PQC_R_LEN, T, kem->length_public_key) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Failed to send PAKE-3 frame");
        ret = -1;
    } else {
        ret = 0;
    }

    os_free(ps_e);
    os_free(T);

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (ret != 0 && sm->fsid) { 
        os_free(sm->fsid); 
        sm->fsid = NULL; 
    }
    return ret;
}

/**
 * wpas_pqc_send_pake3 - Building and sending Vendor specific action frame
 */
int wpas_pqc_send_pake3(struct wpa_pqc_sm *sm, 
                                const u8 *s, size_t s_len, 
                                const u8 *T, size_t T_len) {
    struct wpabuf *buf;
    int ret;

    /* Getting channel frequency */
    unsigned int freq = sm->wpa_s->current_bss ? sm->wpa_s->current_bss->freq : 2412;
    
    /* Frame structure: 
     * Category (1B) + Action (1B) + OUI (3B) + OUI_TYPE (1B) + Subtype/ID (1B) + Payload (s + T)
     */
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + s_len + T_len;
    buf = wpabuf_alloc(frame_len);
    if (!buf) 
        return -1;

    /* Action Frame header */
    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);          // Cat: 4
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);     // Action: 9
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PAKE); // (Zależnie czy na AP używasz tego dodatkowego bajtu typu)
    wpabuf_put_u8(buf, PQC_PAKE_TYPE_3);     // Subtype: 0x03 = PAKE-3 

    /* Payload PQC */
    wpabuf_put_data(buf, s, s_len);
    wpabuf_put_data(buf, T, T_len);

    wpa_printf(MSG_DEBUG, "PQC: Sending PAKE-3 Action Frame to " MACSTR " on freq %d",
               MAC2STR(sm->wpa_s->bssid), freq);

    /* * Sending frame
    * Parameters: wpa_s, freq, wait, dst_mac, src_mac, bssid, data, data_len, no_cck
    */
    const u8 *target_bssid = sm->wpa_s->pending_bssid;
    
    static const u8 zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
    if (os_memcmp(target_bssid, zero_mac, ETH_ALEN) == 0 && sm->wpa_s->current_bss) {
        target_bssid = sm->wpa_s->current_bss->bssid;
    }


    ret = wpa_drv_send_action(sm->wpa_s, freq, 0,
                    target_bssid, 
                    sm->wpa_s->own_addr, 
                    target_bssid,
                    wpabuf_head(buf), wpabuf_len(buf), 0);

    wpabuf_free(buf);
    return ret;
}

/* after receiving PAKE-4 */

int pqc_sm_rx_pake4(struct wpa_pqc_sm *sm, 
                    const u8 *payload, size_t payload_len) {
    int ret = -1;
    OQS_KEM *kem = NULL;
    const char *tag_prefix = "tag verification";
    const char *key_prefix = "key derivation";
    u8 Htag[32]; 
    u8 PMK[32];

    wpa_printf(MSG_DEBUG, "PQC_LOG: State Machine processing PAKE-4");

    const char *alg_name = get_oqs_kem_alg(sm->pqc_choice);
    if(!alg_name) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in mapping PQC algorithm");
        return -1;
    }
    kem = OQS_KEM_new(alg_name);
    if (!kem) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in initializing QOS KEM");
        return -1;
    } 
    
    if (payload_len <= kem->length_ciphertext) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PAKE-4 payload too short");
        goto cleanup;
    }

    const u8 *c2 = payload;
    size_t c2_len = kem->length_ciphertext;
    const u8 *tag = payload + c2_len;
    size_t tag_len = payload_len - c2_len;
    if (tag_len < 32) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PAKE-4 tag too short");
        goto cleanup;
    }

    /* save ciphertext2 from AP (c2) for later use*/
    if (sm->ap_ciphertext_2) {
        os_free(sm->ap_ciphertext_2);
    }
    sm->ap_ciphertext_2 = os_malloc(c2_len);
    if (!sm->ap_ciphertext_2) goto cleanup;
    
    os_memcpy(sm->ap_ciphertext_2, c2, c2_len);
    sm->ap_ciphertext_2_len = c2_len; 

    wpa_printf(MSG_DEBUG, "PQC_LOG: Saved ciphertext 2 from AP (len=%zu)", c2_len);

    /* KEM decapsulation */
    sm->shared_secret_K_len = kem->length_shared_secret;
    sm->shared_secret_K = os_malloc(sm->shared_secret_K_len);
    if (!sm->shared_secret_K) goto cleanup;

    if(OQS_KEM_decaps(kem, sm->shared_secret_K, c2, sm->kem_secret_key) != OQS_SUCCESS){
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in KEM decapsulation");
        goto cleanup;
    }

    /* tag verification */
    size_t Htag_len = os_strlen(tag_prefix) + sm->fsid_len + sm->pwd_len + sm->sta_kem_pub_len + PQC_R_LEN + sm->T_len + c2_len + sm->shared_secret_K_len;
    struct wpabuf *Htag_data = wpabuf_alloc(Htag_len);
    if (!Htag_data) goto cleanup;

    // concatenation
    wpabuf_put_data(Htag_data, tag_prefix, os_strlen(tag_prefix));
    if (sm->fsid)
        wpabuf_put_data(Htag_data, sm->fsid, sm->fsid_len);
    wpabuf_put_data(Htag_data, sm->pwd, sm->pwd_len);
    wpabuf_put_data(Htag_data, sm->sta_kem_public_key, sm->sta_kem_pub_len);
    wpabuf_put_data(Htag_data, sm->s, PQC_R_LEN);
    wpabuf_put_data(Htag_data, sm->T, sm->T_len);
    wpabuf_put_data(Htag_data, sm->ap_ciphertext_2, sm->ap_ciphertext_2_len);
    wpabuf_put_data(Htag_data, sm->shared_secret_K, sm->shared_secret_K_len);

    // HMAC-SHA256
    hmac_sha256(sm->shared_secret_K, sm->shared_secret_K_len, wpabuf_head(Htag_data), wpabuf_len(Htag_data), Htag);
    wpabuf_free(Htag_data);
    //checking correctness of tag and PMK construction
    if(!sm->wpa_s->wpa){
        wpa_printf(MSG_ERROR, "PQC_LOG: WPA state machine not initialized yet");
        goto cleanup;
    }
    size_t Hkey_len = sm->fsid_len + sm->pwd_len + sm->sta_kem_pub_len + PQC_R_LEN + sm->T_len + c2_len;
    struct wpabuf *Hkey_data = wpabuf_alloc(Hkey_len);
    if (!Hkey_data) goto cleanup;

    if (sm->fsid)
        wpabuf_put_data(Hkey_data, sm->fsid, sm->fsid_len);
    wpabuf_put_data(Hkey_data, sm->pwd, sm->pwd_len);
    wpabuf_put_data(Hkey_data, sm->sta_kem_public_key, sm->sta_kem_pub_len);
    wpabuf_put_data(Hkey_data, sm->s, PQC_R_LEN);
    wpabuf_put_data(Hkey_data, sm->T, sm->T_len);
    wpabuf_put_data(Hkey_data, sm->ap_ciphertext_2, sm->ap_ciphertext_2_len);

    // PMK 
    
    if (os_memcmp_const(Htag, tag, 32) != 0){
        wpa_printf(MSG_WARNING, "PQC_LOG: Tag verification failed. Setting random PMK.");
        os_get_random(PMK, sizeof(PMK));
    } else {
        wpa_printf(MSG_DEBUG, "PQC_LOG: Tag verification success.");
        hmac_sha256_kdf(sm->shared_secret_K, sm->shared_secret_K_len, key_prefix, wpabuf_head(Hkey_data), wpabuf_len(Hkey_data), PMK, sizeof(PMK));
    }
    wpabuf_free(Hkey_data);

    wpa_sm_set_pmk(sm->wpa_s->wpa, PMK, sizeof(PMK), NULL, sm->wpa_s->bssid);

    wpa_printf(MSG_INFO, "PQC_LOG: PAKE phase complete. Triggering Association...");

    wpa_supplicant_set_state(sm->wpa_s, WPA_ASSOCIATING);
    if (sm->wpa_s->current_bss && sm->wpa_s->current_ssid) {
        sme_associate(sm->wpa_s, sm->wpa_s->current_ssid->mode, 
                      sm->wpa_s->current_bss->bssid, 
                      sm->wpa_s->current_ssid->auth_alg);
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: cannot start association");
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (ret != 0 && sm->fsid) { 
        os_free(sm->fsid); 
        sm->fsid = NULL; 
    }
    return ret;
}

