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
#include <oqs/oqs.h>

/**
 * get_oqs_kem_alg - Maps the PQC bitmask to liboqs algorithm string
 */
static const char* get_oqs_kem_alg(u8 pqc_choice) {
    if (pqc_choice & 0x80) return OQS_KEM_alg_ml_kem_512;
    if (pqc_choice & 0x40) return OQS_KEM_alg_ml_kem_768;
    if (pqc_choice & 0x20) return OQS_KEM_alg_ml_kem_1024;
    return NULL;
}

/**
 * pqc_2f_inverse - Implements the Double Feistel Network (2F)
 */
static int pqc_2f_inverse(const u8 *K, size_t K_len, 
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

/* send PAKE-4 */
static int hostapd_pqc_send_pake4(struct hostapd_pqc_sm *sm, 
                                  const u8 *c, size_t c_len, 
                                  const u8 *tag, size_t tag_len) {
    struct wpabuf *buf;
    int ret;
    
    /*Frame structure: 
     * Category (1B) + OUI (3B) + Subtype/ID (1B) + Payload (c2 + tag)
     */
    size_t frame_len = 1 + 3 + 1 + c_len + tag_len;
    buf = wpabuf_alloc(frame_len);
    if (!buf) 
        return -1;

    /* Action Frame header */
    wpabuf_put_u8(buf, WLAN_ACTION_VENDOR_SPECIFIC); // 127
    wpabuf_put_be24(buf, 0x00904C); // test OUI = 00:90:4C
    wpabuf_put_u8(buf, 0x04);       // Subtype: 0x04 = PAKE-4

    /* Payload PQC */
    wpabuf_put_data(buf, c, c_len);
    wpabuf_put_data(buf, tag, tag_len);

    wpa_printf(MSG_DEBUG, "PQC_LOG: Sending PAKE-3 Action Frame");

    /* * Sending frame
    * Parameters: wpa_s, freq, wait, dst_mac, src_mac, bssid, data, data_len, no_cck
    */
    ret = hostapd_drv_send_action(sm->hapd, sm->hapd->iface->freq, 0, 
                                  sm->sta->addr, 
                                  wpabuf_head(buf), wpabuf_len(buf));
    wpabuf_free(buf);
    return ret;
}

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

    /* copy pws from AP config */
    if (hapd->conf->ssid.wpa_passphrase) {
        sm->pwd_len = os_strlen(hapd->conf->ssid.wpa_passphrase);
        os_memcpy(sm->pwd, hapd->conf->ssid.wpa_passphrase, sm->pwd_len);
    }

    OQS_init();
    return sm;
}

void pqc_ap_sm_deinit(struct hostapd_pqc_sm *sm) {
    if (!sm) return;
    wpa_printf(MSG_DEBUG, "PQC_AP: Deinitializing State Machine");

    if (sm->fsid) os_free(sm->fsid);
    if (sm->T) os_free(sm->T);
    if (sm->sta_first_kem_public_key) os_free(sm->sta_first_kem_public_key);
    if (sm->ciphertext_2) os_free(sm->ciphertext_2);
    
    /* liboqs safe delete */
    if (sm->shared_secret_K) {
        OQS_MEM_secure_free(sm->shared_secret_K, sm->shared_secret_K_len);
    }

    forced_memzero(sm->pwd, sizeof(sm->pwd));
    os_free(sm);
    
    OQS_destroy();
}

/* after receiving PAKE-3 */

int pqc_ap_sm_rx_pake3(struct hostapd_pqc_sm *sm, 
                       const u8 *s, size_t s_len, 
                       const u8 *T, size_t T_len) {
    u8 r[PQC_R_LEN];
    u8 tag[32]; 
    const char *tag_prefix = "tag verification";
    int ret = -1;
    OQS_KEM *kem = NULL;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Processing PAKE-3");

    /* saving s i T in state (needed for tag) */
    os_memcpy(sm->s, s, s_len);
    sm->T = os_malloc(T_len);
    if (!sm->T) return -1;
    os_memcpy(sm->T, T, T_len);
    sm->T_len = T_len;

    /* inverse Feistel network */
    sm->sta_first_kem_pub_len = T_len;
    sm->sta_first_kem_public_key = os_malloc(sm->sta_first_kem_pub_len);
    if (!sm->sta_first_kem_public_key) goto cleanup;

    if (pqc_2f_inverse(sm->pwd, sm->pwd_len, s, s_len, T, T_len, r, sm->sta_first_kem_public_key) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Feistel inverse failed");
        goto cleanup;
    }

    /*(ML-KEM.encaps(psk) = c, K) */
    const char *alg_name = get_oqs_kem_alg(sm->pqc_choice);
    if (!alg_name) goto cleanup;

    kem = OQS_KEM_new(alg_name);
    if (!kem) goto cleanup;

    sm->ciphertext_2_len = kem->length_ciphertext;
    sm->ciphertext_2 = os_malloc(sm->ciphertext_2_len);
    
    sm->shared_secret_K_len = kem->length_shared_secret;
    sm->shared_secret_K = os_malloc(sm->shared_secret_K_len);

    if (OQS_KEM_encaps(kem, sm->ciphertext_2, sm->shared_secret_K, sm->sta_first_kem_public_key) != OQS_SUCCESS) {
        goto cleanup;
    }

    /* Tag generation
     * HMAC-SHA256("tag verification" || fsid || pwd || psk || s || T || c || K) 
     */
    size_t data_len = os_strlen(tag_prefix) + sm->fsid_len + sm->pwd_len + sm->sta_first_kem_pub_len + s_len + T_len + sm->ciphertext_2_len + sm->shared_secret_K_len;
    struct wpabuf *tag_data = wpabuf_alloc(data_len);
    if (!tag_data) goto cleanup;

    //concatenation
    wpabuf_put_data(tag_data, tag_prefix, os_strlen(tag_prefix));
    if (sm->fsid) 
        wpabuf_put_data(tag_data, sm->fsid, sm->fsid_len);
    wpabuf_put_data(tag_data, sm->pwd, sm->pwd_len);
    wpabuf_put_data(tag_data, sm->sta_first_kem_public_key, sm->sta_first_kem_pub_len);
    wpabuf_put_data(tag_data, s, s_len);
    wpabuf_put_data(tag_data, T, T_len);
    wpabuf_put_data(tag_data, sm->ciphertext_2, sm->ciphertext_2_len);
    wpabuf_put_data(tag_data, sm->shared_secret_K, sm->shared_secret_K_len); 

    // HMAC
    hmac_sha256(sm->shared_secret_K, sm->shared_secret_K_len, wpabuf_head(tag_data), wpabuf_len(tag_data), tag);
    wpabuf_free(tag_data);

    /* sending PAKE-4(c, tag) */
    if (hostapd_pqc_send_pake4(sm, sm->ciphertext_2, sm->ciphertext_2_len, tag, sizeof(tag)) < 0) {
        wpa_printf(MSG_ERROR, "PQC_AP: Failed to send PAKE-4");
        goto cleanup;
    }

    ret = 0; /* success */

cleanup:
    if (kem) OQS_KEM_free(kem);
    return ret;
}