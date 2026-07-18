#include "utils/includes.h"
#include "utils/common.h"
#include "utils/os.h"
#include "utils/wpabuf.h"      
#include "utils/wpa_debug.h"  
#include "crypto/sha256.h" 
#include "hostapd.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "pqc_ap_sm.h"
#include "../common/pqc_help.h"
#include <oqs/oqs.h>

/* STATE LIFECYCLE */

struct hostapd_pqc_sm * pqc_ap_sm_init(struct hostapd_data *hapd, struct sta_info *sta) {
    struct hostapd_pqc_sm *sm;

    if (!hapd || !sta || !hapd->conf->pqc_enabled) return NULL;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Initializing State Machine for STA " MACSTR, MAC2STR(sta->addr));
    
    sm = os_zalloc(sizeof(*sm));
    if (!sm) return NULL;

    sm->hapd = hapd;
    sm->sta = sta;
    sm->pqc_choice = sta->pqc_choice; /* save after receiving probe request */

    /* copy pwd from AP config */
    if (hapd->conf->ssid.wpa_passphrase) {
        sm->pwd_len = os_strlen(hapd->conf->ssid.wpa_passphrase);
        os_memcpy(sm->pwd, hapd->conf->ssid.wpa_passphrase, sm->pwd_len);
    } else {
        wpa_printf(MSG_WARNING, "PQC_LOG: Warning - wpa_passphrase not found in AP config!");
    }

    /* saving earlier generated keys from sta_info struct to state machine */
    
    // ML-KEM - delete from sta_info struct after copying TODO
    if (sta->ml_kem_512_pub && sta->ml_kem_secr) {
        sm->kem_pub_key_len = sta->ml_kem_512_pub_len;
        sm->kem_pub_key = os_malloc(sm->kem_pub_key_len);
        
        sm->kem_secret_key_len = sta->ml_kem_secr_len;
        sm->kem_secret_key = os_malloc(sm->kem_secret_key_len);
        
        if (sm->kem_pub_key && sm->kem_secret_key) {
            os_memcpy(sm->kem_pub_key, sta->ml_kem_512_pub, sm->kem_pub_key_len);
            os_memcpy(sm->kem_secret_key, sta->ml_kem_secr, sm->kem_secret_key_len);
            wpa_printf(MSG_DEBUG, "PQC_LOG: KEM keys successfully imported from sta_info");
        } else {
            wpa_printf(MSG_ERROR, "PQC_LOG: Failed to allocate memory for KEM keys in SM");
            pqc_ap_sm_deinit(sm);
            return NULL;
        }
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: Missing KEM keys in sta_info during SM init");
    }

    return sm;
}

void pqc_ap_sm_deinit(struct hostapd_pqc_sm *sm) {
    if (!sm) return;
    wpa_printf(MSG_DEBUG, "PQC_AP: Deinitializing State Machine");

    if (sm->fsid) os_free(sm->fsid);
    if (sm->T) os_free(sm->T);
    if (sm->sta_first_kem_public_key) os_free(sm->sta_first_kem_public_key);
    if (sm->ciphertext_2) os_free(sm->ciphertext_2);
    if (sm->kem_pub_key) os_free(sm->kem_pub_key);
    if (sm->dsa_pub_key) os_free(sm->dsa_pub_key);
    
    /* liboqs safe delete */
    if (sm->kem_secret_key) {
        OQS_MEM_secure_free(sm->kem_secret_key, sm->kem_secret_key_len);
    }
    
    if (sm->dsa_secret_key) {
        OQS_MEM_secure_free(sm->dsa_secret_key, sm->dsa_secret_key_len);
    }

    if (sm->shared_secret_K) {
        OQS_MEM_secure_free(sm->shared_secret_K, sm->shared_secret_K_len);
    }

    forced_memzero(sm->pwd, sizeof(sm->pwd));
    os_free(sm);

}

/* PMK derivation based on SM data*/
int pqc_ap_sm_derive_pmk(struct hostapd_pqc_sm *sm, u8 *pmk_out) {
    const char *key_prefix = "key derivation";

    /* when shared secret is None */
    if (!sm || !sm->shared_secret_K) {
        wpa_printf(MSG_ERROR, "PQC_LOG: No shared_secret_K for PMK derivation");
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: Generating PMK (assoc verification)");

    /* buffer and allocation */
    size_t Hkey_len = sm->fsid_len + sm->pwd_len + sm->sta_first_kem_pub_len + PQC_R_LEN + sm->T_len + sm->ciphertext_2_len;
    struct wpabuf *Hkey_data = wpabuf_alloc(Hkey_len);
    if (!Hkey_data) return -1;

    /* concatenation */
    if (sm->fsid) wpabuf_put_data(Hkey_data, sm->fsid, sm->fsid_len);
    wpabuf_put_data(Hkey_data, sm->pwd, sm->pwd_len);
    wpabuf_put_data(Hkey_data, sm->sta_first_kem_public_key, sm->sta_first_kem_pub_len);
    wpabuf_put_data(Hkey_data, sm->s, PQC_R_LEN);
    wpabuf_put_data(Hkey_data, sm->T, sm->T_len);
    wpabuf_put_data(Hkey_data, sm->ciphertext_2, sm->ciphertext_2_len);

    /* Generating PMK - 32 bytes*/
    hmac_sha256_kdf(sm->shared_secret_K, sm->shared_secret_K_len, 
                    key_prefix, wpabuf_head(Hkey_data), wpabuf_len(Hkey_data), 
                    pmk_out, PMK_LEN);

    wpabuf_free(Hkey_data);
    return 0;
}