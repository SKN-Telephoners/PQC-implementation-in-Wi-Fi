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

static const char* get_oqs_dsa_alg(u8 pqc_choice) {
    if (pqc_choice & 0x08) return OQS_SIG_alg_ml_dsa_44;
    if (pqc_choice & 0x04) return OQS_SIG_alg_ml_dsa_65;
    if (pqc_choice & 0x02) return OQS_SIG_alg_ml_dsa_87;
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

/* building and sending PAKE-2 */
static int hostapd_pqc_send_pake2(struct hostapd_data *hapd, struct sta_info *sta, 
                                  const u8 *enc_sid, size_t enc_sid_len, 
                                  const u8 *dpk, size_t dpk_len) {
    struct wpabuf *buf = NULL;
    int ret = -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Started building PAKE-2 frame");

    /* Length: Cat(1) + Action(1) + OUI(3) + Type(1) + Subtype(1) + sid_len(2) + enc_sid + dpk_len(2) + dpk */
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + 2 + enc_sid_len + 2 + dpk_len;
    buf = wpabuf_alloc(frame_len);
    if (!buf) return -1;

    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);          // Cat: 4
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);     // Action: 9
    
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);
    
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PAKE);
    wpabuf_put_u8(buf, PQC_PAKE_TYPE_2);

    /* Payload PAKE-2: length(2B) + {sid} + length(2B) + dpk */
    wpabuf_put_be16(buf, enc_sid_len);
    wpabuf_put_data(buf, enc_sid, enc_sid_len);
    
    wpabuf_put_be16(buf, dpk_len);
    wpabuf_put_data(buf, dpk, dpk_len);

    wpa_printf(MSG_INFO, "PQC_LOG: Sending public action frame (PAKE-2) to: " MACSTR, MAC2STR(sta->addr));

    ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0,
                                  sta->addr,          // dst
                                  wpabuf_head(buf), wpabuf_len(buf));

    wpabuf_free(buf);
    return ret;
}

/* Funkcja wywoływana po otrzymaniu ramki PAKE-1 z `handle_action`. */
int pqc_ap_sm_rx_pake1(struct hostapd_pqc_sm *sm, struct hostapd_data *hapd, struct sta_info *sta, const u8 *payload, size_t len) {
    
    OQS_KEM *kem = NULL;
    OQS_SIG *sig = NULL;
    u8 id[16];
    int ret = -1;

    if (!sm || len < 4) return -1;

    /* --- parsing PAKE-1 --- */
    const u8 *pos = payload;
    u16 c_len = WPA_GET_BE16(pos); pos += 2;
    if (len < 4 + c_len) return -1;
    const u8 *c = pos; pos += c_len;
    
    u16 id_len = WPA_GET_BE16(pos); pos += 2;
    if (len < 4 + c_len + id_len || id_len != PQC_SID_LEN) return -1;
    const u8 *enc_id = pos;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Parsing of PAKE-1 ended (c_len: %d, id_len: %d)", c_len, id_len);

    /* KEM Decapsulation: (Kses) = ML-KEM-decaps(c, sk) */
    kem = OQS_KEM_new(get_oqs_kem_alg(sm->pqc_choice)); 
    if (!kem) return -1;
    
    if (OQS_KEM_decaps(kem, sm->K_aes, c, sm->kem_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in KEM decapsulation");
        goto cleanup;
    }
    

    /* Decryption of STA id */
    void *aes_ctx = aes_decrypt_init(sm->K_aes, 32);
    if (!aes_ctx) goto cleanup;
    aes_decrypt(aes_ctx, enc_id, id);
    aes_decrypt_deinit(aes_ctx);

    /* Generating and encrypting sid */
    u8 sid[PQC_SID_LEN];
    u8 enc_sid[PQC_SID_LEN];
    if (os_get_random(sid, sizeof(sid)) < 0) goto cleanup;
    
    os_memcpy(sm->sid, sid, sizeof(sid));

    aes_ctx = aes_encrypt_init(sm->K_aes, 32);
    if (!aes_ctx) goto cleanup;
    aes_encrypt(aes_ctx, sid, enc_sid);
    aes_encrypt_deinit(aes_ctx);

    /* fsid = sid || id || MAC_AP || MAC_STA */
    sm->fsid_len = sizeof(sid) + sizeof(id) + (2 * ETH_ALEN);
    sm->fsid = os_malloc(sm->fsid_len);
    if (!sm->fsid) goto cleanup;
    
    u8 *fsid_pos = sm->fsid;
    os_memcpy(fsid_pos, sid, sizeof(sid)); fsid_pos += sizeof(sid);
    os_memcpy(fsid_pos, id, sizeof(id)); fsid_pos += sizeof(id);
    os_memcpy(fsid_pos, hapd->own_addr, ETH_ALEN); fsid_pos += ETH_ALEN;
    os_memcpy(fsid_pos, sta->addr, ETH_ALEN);

    /* Generation of ML-DSA key pair */
    sig = OQS_SIG_new(get_oqs_dsa_alg(sm->pqc_choice)); 
    if (!sig) goto cleanup;
    
    sm->dsa_pub_key_len = sig->length_public_key;
    sm->dsa_secret_key_len = sig->length_secret_key;
    sm->dsa_pub_key = os_malloc(sig->length_public_key);
    sm->dsa_secret_key = os_malloc(sig->length_secret_key); 
    
    if (!sm->dsa_pub_key || !sm->dsa_secret_key) goto cleanup;

    if (OQS_SIG_keypair(sig, sm->dsa_pub_key, sm->dsa_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in ML-DSA key pair generation on AP");
        goto cleanup;
    }

    /* sending PAKE-2 function call */
    ret = hostapd_pqc_send_pake2(hapd, sta, enc_sid, sizeof(enc_sid), sm->dsa_pub_key, sm->dsa_pub_key_len);

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return ret;
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

    /* copy pwd from AP config */
    if (hapd->conf->ssid.wpa_passphrase) {
        sm->pwd_len = os_strlen(hapd->conf->ssid.wpa_passphrase);
        os_memcpy(sm->pwd, hapd->conf->ssid.wpa_passphrase, sm->pwd_len);
    } else {
        wpa_printf(MSG_WARNING, "PQC_LOG: Warning - wpa_passphrase not found in AP config!");
    }

    /* saving earlier generated keys from sta_info struct to state machine */
    
    // ML-KEM
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
    
    if (sm->dsa_secret_key) { // Uwaga na literowke 'sexret' z definicji struktury
        OQS_MEM_secure_free(sm->dsa_secret_key, sm->dsa_secret_key_len);
    }

    if (sm->shared_secret_K) {
        OQS_MEM_secure_free(sm->shared_secret_K, sm->shared_secret_K_len);
    }

    forced_memzero(sm->pwd, sizeof(sm->pwd));
    os_free(sm);

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
                    pmk_out, 32);

    wpabuf_free(Hkey_data);
    return 0;
}