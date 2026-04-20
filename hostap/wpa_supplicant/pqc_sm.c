#include "includes.h"
#include "common.h"
#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "utils/os.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "bss.h"
#include "pqc_sm.h"
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
 * pqc_2f_network - Implements the Double Feistel Network (2F)
 * T = M (dot) H1(K, r)
 * s = r (XOR) H2(K, T)
 */
static int pqc_2f_network(const u8 *K, size_t K_len,
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
 * wpas_pqc_send_pake3 - Building and sending Vendor specific action frame
 */
/* Wysłanie ramki Action (jak poprzednio) */
static int wpas_pqc_send_pake3(struct wpa_pqc_sm *sm, 
                                const u8 *s, size_t s_len, 
                                const u8 *T, size_t T_len) {
    struct wpabuf *buf;
    int ret;

    /* Getting channel frequency */
    unsigned int freq = sm->wpa_s->current_bss ? sm->wpa_s->current_bss->freq : 2412;
    
    /*Frame structure: 
     * Category (1B) + OUI (3B) + Subtype/ID (1B) + Payload (s + T)
     */
    size_t frame_len = 1 + 3 + 1 + s_len + T_len;
    buf = wpabuf_alloc(frame_len);
    if (!buf) 
        return -1;

    /* Action Frame header */
    wpabuf_put_u8(buf, WLAN_ACTION_VENDOR_SPECIFIC); // 127
    wpabuf_put_be24(buf, 0x00904C); // test OUI = 00:90:4C
    wpabuf_put_u8(buf, 0x03);       // Subtype: 0x03 = PAKE-3 

    /* Payload PQC */
    wpabuf_put_data(buf, s, s_len);
    wpabuf_put_data(buf, T, T_len);

    wpa_printf(MSG_DEBUG, "PQC: Sending PAKE-3 Action Frame to " MACSTR " on freq %d",
               MAC2STR(sm->wpa_s->bssid), freq);

    /* * Sending frame
    * Parameters: wpa_s, freq, wait, dst_mac, src_mac, bssid, data, data_len, no_cck
    */
    ret = wpa_drv_send_action(sm->wpa_s, freq, 0, 
                              sm->wpa_s->bssid, sm->wpa_s->own_addr, sm->wpa_s->bssid, 
                              wpabuf_head(buf), wpabuf_len(buf), 0);
    wpabuf_free(buf);
    return ret;
}

/* STATE LIFECYCLE */

struct wpa_pqc_sm * pqc_sm_init(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid) {
    struct wpa_pqc_sm *sm;

    if(!ssid || !ssid->pqc_enabled) return NULL;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Initializing State Machine (choice mask: 0x%02x)", ssid->pqc_choice);
    
    sm = os_zalloc(sizeof(*sm));
    if (!sm) return NULL;

    sm->wpa_s = wpa_s;
    sm->pqc_choice = ssid->pqc_choice;
    sm->pqc_enabled = 1;

    // AP's pub KEM key (probe response)
    sm->ap_kem_pub_len = 800; 
    sm->ap_kem_public_key = os_malloc(sm->ap_kem_pub_len);

    if (sm->ap_kem_public_key) {
        os_memcpy(sm->ap_kem_public_key, wpa_s->pqc_kem_buffer, sm->ap_kem_pub_len);
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP KEM Public Key imported from wpa_s buffer");
    }

    if(ssid->passphrase){
        sm->pwd_len = os_strlen(ssid->passphrase);
        os_memcpy(sm->pwd, ssid->passphrase, sm->pwd_len);
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: Missing password in STA network config");
    }

    /* initialize liboqs */
    OQS_init();

    return sm;
}

void pqc_sm_deinit(struct wpa_pqc_sm *sm) {
    if (!sm) return;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Deinitializing State Machine");

    if (sm->fsid) os_free(sm->fsid);
    
    if (sm->ap_kem_public_key) os_free(sm->ap_kem_public_key);
    if (sm->sta_kem_public_key) os_free(sm->sta_kem_public_key);
    if (sm->sta_second_pub_key) os_free(sm->sta_second_pub_key);
    if (sm->dsa_public_key) os_free(sm->dsa_public_key);

    /* liboqs safe delete */
    if (sm->kem_secret_key) {
        OQS_MEM_secure_free(sm->kem_secret_key, sm->kem_secret_key_len);
    }
    if (sm->sta_second_secret_key) {
        OQS_MEM_secure_free(sm->sta_second_secret_key, sm->sta_second_secret_len);
    }

    forced_memzero(sm->pwd, sizeof(sm->pwd));
    forced_memzero(sm->K_aes, sizeof(sm->K_aes));

    os_free(sm);

    OQS_destroy();
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

    /* 6. (s, T) = 2F(pwd, r, Z) */
    T = os_malloc(kem->length_public_key);
    if (!T) { 
        os_free(ps_e); 
        goto cleanup; }

    if (pqc_2f_network(sm->pwd, sm->pwd_len, r, PQC_R_LEN, ps_e, kem->length_public_key, s, T) < 0) {
        os_free(ps_e); 
        os_free(T); 
        goto cleanup;
    }

    /* 7. Send PAKE-3(s, T) */
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