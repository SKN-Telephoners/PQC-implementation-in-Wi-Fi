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
#include "pqc_ap_sm.h"
#include "crypto/aes.h"

static int hostapd_pqc_send_pake2(struct hostapd_pqc_sm *sm, const u8 *broadcast_mac);
static int hostapd_pqc_send_pake4(struct hostapd_pqc_sm *sm, const u8 *c, size_t c_len, const u8 *tag, size_t tag_len);
static int ap_tx_action_wrapper(void *ctx, const u8 *dst_mac, const u8 *data, size_t data_len) {
    struct hostapd_pqc_sm *sm = ctx;
    /* Send via AP driver interface on the current frequency */
    return hostapd_drv_send_action(sm->hapd, sm->hapd->iface->freq, 0, dst_mac, data, data_len);
}

/* called after receiving PAKE-1 . */
int pqc_ap_sm_rx_pake1(struct hostapd_pqc_sm *sm, struct hostapd_data *hapd, struct sta_info *sta, const u8 *payload, size_t len) {
    
    OQS_KEM *kem = NULL;
    OQS_SIG *sig = NULL;
    u8 id[ID_LEN];
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

    /* KEM Decapsulation: dynamically loaded based on negotiated choice */
    kem = OQS_KEM_new(get_oqs_kem_alg(sm->pqc_choice)); 
    if (!kem) return -1;
    
    /* Assuming sm->kem_secret_key was populated from sta->kem_secr during initialization */
    if (OQS_KEM_decaps(kem, sm->K_aes, c, sm->kem_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in KEM decapsulation");
        goto cleanup;
    }
    wpa_hexdump(MSG_DEBUG, "PQC_DBG AP: K_aes[0:8]", sm->K_aes, 8);

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

    wpa_hexdump(MSG_DEBUG, "PQC_DBG AP: sid plaintext", sid, sizeof(sid));
    wpa_hexdump(MSG_DEBUG, "PQC_DBG AP: enc_sid sent", enc_sid, sizeof(enc_sid));

    /* Store enc_sid in state machine for the sender function */
    os_memcpy(sm->enc_sid, enc_sid, sizeof(enc_sid));
    sm->enc_sid_len = sizeof(enc_sid);

    /* fsid = sid || id || MAC_AP || MAC_STA */
    sm->fsid_len = sizeof(sid) + sizeof(id) + (2 * ETH_ALEN);
    sm->fsid = os_malloc(sm->fsid_len);
    if (!sm->fsid) goto cleanup;
    
    u8 *fsid_pos = sm->fsid;
    os_memcpy(fsid_pos, sid, sizeof(sid)); fsid_pos += sizeof(sid);
    os_memcpy(fsid_pos, id, sizeof(id)); fsid_pos += sizeof(id);
    os_memcpy(fsid_pos, hapd->own_addr, ETH_ALEN); fsid_pos += ETH_ALEN;
    os_memcpy(fsid_pos, sta->addr, ETH_ALEN);

    /* Generation of ML-DSA key pair (Dynamically sized) */
    sig = OQS_SIG_new(get_oqs_dsa_alg(sm->pqc_choice)); 
    if (!sig) goto cleanup;
    
    sm->dsa_pub_key_len = sig->length_public_key;
    sm->dsa_secret_key_len = sig->length_secret_key;
    sm->dsa_pub_key = os_malloc(sm->dsa_pub_key_len);
    sm->dsa_secret_key = os_malloc(sm->dsa_secret_key_len); 
    
    if (!sm->dsa_pub_key || !sm->dsa_secret_key) goto cleanup;

    if (OQS_SIG_keypair(sig, sm->dsa_pub_key, sm->dsa_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in ML-DSA key pair generation on AP");
        goto cleanup;
    }

    /* Broadcast MAC used for the Hardware Filter workaround */
    u8 broadcast_mac[ETH_ALEN];
    os_memset(broadcast_mac, 0xff, ETH_ALEN);

    ret = hostapd_pqc_send_pake2(sm, broadcast_mac);

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return ret;
}

/* building and sending PAKE-2 */
int hostapd_pqc_send_pake2(struct hostapd_pqc_sm *sm, const u8 *broadcast_mac) 
{
    /*
     * Length of enc_sid (2 bytes) + enc_sid + length of dsa_pub_key (2B) + dsa_pub_key
    */
     
    size_t payload_len = 2 + sm->enc_sid_len + 2 + sm->dsa_pub_key_len;

    struct wpabuf *payload = wpabuf_alloc(payload_len);
    if (!payload) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Failed to allocate PAKE-2 payload");
        return -1;
    }

    /* Pack the payload */
    wpabuf_put_be16(payload, (u16)sm->enc_sid_len);
    wpabuf_put_data(payload, sm->enc_sid, sm->enc_sid_len);
    wpabuf_put_be16(payload, (u16)sm->dsa_pub_key_len);
    wpabuf_put_data(payload, sm->dsa_pub_key, sm->dsa_pub_key_len);

    wpa_printf(MSG_DEBUG, "PQC_LOG: Sending PAKE-2 (Total Payload: %zu bytes)", payload_len);
    
    /* MTU slicing and headers */
    int ret = pqc_send_fragmented_action_frame(sm, ap_tx_action_wrapper, broadcast_mac, 
                                               PQC_OUI_TYPE_PAKE, PQC_PAKE_TYPE_2, 
                                               wpabuf_head(payload), wpabuf_len(payload));
    
    wpabuf_free(payload);
    return ret;
}


/* after receiving PAKE-3 */
int pqc_ap_sm_rx_pake3(struct hostapd_pqc_sm *sm, 
                       const u8 *s, size_t s_len, 
                       const u8 *T, size_t T_len) {
    u8 r[PQC_R_LEN];
    u8 tag[TAG_LEN]; 
    const char *tag_prefix = "tag verification";
    int ret = -1;
    OQS_KEM *kem = NULL;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Processing PAKE-3");

    /* saving s i T in state (needed for tag) */
    os_memcpy(sm->s, s, s_len);

    /* Prevent memory leak on retransmissions */
    os_free(sm->T);
    sm->T_len = T_len;
    sm->T = os_malloc(T_len);
    if (!sm->T) return -1;
    os_memcpy(sm->T, T, T_len);
    
    /* inverse Feistel network */
    sm->sta_first_kem_pub_len = T_len;

    if (sm->sta_first_kem_public_key) os_free(sm->sta_first_kem_public_key);
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

    os_free(sm->ciphertext_2);
    os_free(sm->shared_secret_K);

    sm->ciphertext_2_len = kem->length_ciphertext;
    sm->ciphertext_2 = os_malloc(sm->ciphertext_2_len);
    
    sm->shared_secret_K_len = kem->length_shared_secret;
    sm->shared_secret_K = os_malloc(sm->shared_secret_K_len);

    if (OQS_KEM_encaps(kem, sm->ciphertext_2, sm->shared_secret_K, sm->sta_first_kem_public_key) != OQS_SUCCESS) {
        goto cleanup;
    }

    wpa_hexdump(MSG_DEBUG, "PQC_DBG AP: fsid[0:16]", sm->fsid, sm->fsid ? (sm->fsid_len < 16 ? sm->fsid_len : 16) : 0);
    wpa_hexdump(MSG_DEBUG, "PQC_DBG AP: psk[0:8]", sm->sta_first_kem_public_key, 8);
    wpa_hexdump(MSG_DEBUG, "PQC_DBG AP: K[0:8]", sm->shared_secret_K, sm->shared_secret_K_len < 8 ? sm->shared_secret_K_len : 8);

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

    wpa_hexdump(MSG_DEBUG, "PQC_DBG AP: tag", tag, sizeof(tag));

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

/* send PAKE-4 */
static int hostapd_pqc_send_pake4(struct hostapd_pqc_sm *sm, 
                                  const u8 *c, size_t c_len, 
                                  const u8 *tag, size_t tag_len) {
    struct wpabuf *payload;
    int ret;
    const u8 bcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    /*Frame structure: 
     Payload (c2 + tag)
     */
    size_t payload_len = c_len + tag_len;
    payload = wpabuf_alloc(payload_len);
    if (!payload) 
        return -1;

    /* Payload PQC */
    wpabuf_put_data(payload, c, c_len);
    wpabuf_put_data(payload, tag, tag_len);

    wpa_printf(MSG_DEBUG, "PQC_LOG: Sending PAKE-4 to BROADCAST(Payload: %zu bytes)", payload_len);

    /* * Sending frame
    */
    ret = pqc_send_fragmented_action_frame(sm, ap_tx_action_wrapper, bcast_mac, 
                                           PQC_OUI_TYPE_PAKE, PQC_PAKE_TYPE_4, 
                                           wpabuf_head(payload), wpabuf_len(payload));
    wpabuf_free(payload);
    return ret;
}
