#include "includes.h"
#include "common.h"
#include "utils/common.h"
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
#include "pqc_pasn.h"
#include "../src/crypto/aes_wrap.h"
#include "../src/drivers/driver.h"

static int sta_tx_action_wrapper(void *ctx, const u8 *dst_mac, const u8 *data, size_t data_len) {
    struct wpa_pqc_sm *sm = ctx;
    /* Uses assoc_freq and handles BSSID routing */
    return wpa_drv_send_action(sm->wpa_s, sm->wpa_s->assoc_freq, 0, dst_mac, 
                               sm->wpa_s->own_addr, sm->wpa_s->bssid, 
                               data, data_len, 0);
}

/**
 * wpas_pqc_send_pasn1 - Build and send PASN-1 frame with ML-DSA public key
 *
 * Frame structure:
 * - Category (1B): WLAN_ACTION_PUBLIC
 * - Action (1B): WLAN_PA_VENDOR_SPECIFIC
 * - OUI (3B): PQC_OUI
 * - Type (1B): PQC_OUI_TYPE_PASN
 * - Subtype (1B): PQC_PASN_TYPE_1
 * - Payload:
 *   - ML-DSA public key length (2B)
 *   - ML-DSA public key (variable)
 *   - STA MAC address (6B)
 *
 * @sm: PQC state machine
 * Returns: 0 on success, -1 on failure
 */

int wpas_pqc_send_pasn1(struct wpa_pqc_sm *sm) {
    int ret = -1;

    // Use the ML-KEM key generated during association/pqc_sm_assoc_success
    if (!sm || !sm->sta_second_pub_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Missing ML-KEM public key");
        return -1;
    }

    // Payload: ML-KEM Key Len (2) + ML-KEM Key (Var) + MAC (6)
    size_t payload_len = 2 + sm->sta_second_pub_len + ETH_ALEN;
    struct wpabuf *payload = wpabuf_alloc(payload_len);
    if (!payload) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to allocate PASN-1 payload");
        return -1;
    }

    /* ML-KEM public key */
    wpabuf_put_be16(payload, (u16)sm->sta_second_pub_len);
    wpabuf_put_data(payload, sm->sta_second_pub_key, sm->sta_second_pub_len);

    /* Payload: STA MAC address for verification on AP side */
    wpabuf_put_data(payload, sm->wpa_s->own_addr, ETH_ALEN);

    /* Get target BSSID */
    const u8 *target_bssid = sm->wpa_s->pending_bssid;
    static const u8 zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};

    if (os_memcmp(target_bssid, zero_mac, ETH_ALEN) == 0 && sm->wpa_s->current_bss) {
        target_bssid = sm->wpa_s->current_bss->bssid;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: [PQC_STAGE_5_END] PASN - Sending PASN-1 frame to: " MACSTR
           " (ML-KEM pub key len: %zu bytes)",
           MAC2STR(target_bssid), sm->sta_second_pub_len);

    /* Send action frame */
    ret = pqc_send_fragmented_action_frame(sm, sta_tx_action_wrapper, target_bssid, 
                                           PQC_OUI_TYPE_PASN, PQC_PASN_TYPE_1, 
                                           wpabuf_head(payload), wpabuf_len(payload));

    if (ret == 0) {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-1 frame sent successfully");
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to send PASN-1 frame");
    }

    wpabuf_free(payload);
    return ret;
}

/* pqc_sm_rx_pasn2 - Save ciphertext and MIC1 from PASN-2 frame.
 * Crypto verification is deferred until all PASN-2-SIG fragments arrive.
 *
 * Frame payload: ct_len(2) + ciphertext + MIC1(32)
 */
int pqc_sm_rx_pasn2(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len) {
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Processing PASN-2 frame from AP");

    if (!sm || !payload || payload_len < 4 + MIC_LEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid PASN-2 frame (too short)");
        return -1;
    }

    const u8 *pos = payload;
    u16 ciphertext_len = WPA_GET_BE16(pos);
    pos += 2;

    if (payload_len < (size_t)(2 + ciphertext_len + MIC_LEN)) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2 truncated");
        return -1;
    }

    const u8 *ciphertext = pos;
    const u8 *mic1 = pos + ciphertext_len;

    /* Save ciphertext */
    if (sm->pasn_ciphertext) os_free(sm->pasn_ciphertext);
    sm->pasn_ciphertext = os_malloc(ciphertext_len);
    if (!sm->pasn_ciphertext)
        return -1;
    
    os_memcpy(sm->pasn_ciphertext, ciphertext, ciphertext_len);
    sm->pasn_ciphertext_len = ciphertext_len;

    /* Save MIC1 for later verification */
    os_memcpy(sm->pasn_mic1, mic1, MIC_LEN);

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-2 saved (ct=%u bytes, MIC1 saved). Waiting for PASN-2-SIG... ",
               ciphertext_len);
    return 0;
}

/* pqc_sm_rx_pasn2_sig - perform full crypto verification.
 * Frame payload: total_sig_len(2) + ML-DSA signature(variable)
 */
int pqc_sm_rx_pasn2_sig(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len) {
    OQS_SIG *sig = NULL;
    OQS_KEM *kem = NULL;
    int ret = -1;

    if (!sm || !payload || payload_len == 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid PASN-2-SIG frame");
        return -1;
    }

    const u8 *signature = payload;
    u16 sig_len = payload_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-2-SIG received (%u bytes). Verifying... ", sig_len);

    if (!sm->dsa_public_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN -AP ML-DSA public key missing (should have been saved from PAKE-2)");
        return -1;
    }
    if (!sm->pasn_ciphertext) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Ciphertext missing (PASN-2 not received first)");
        return -1;
    }

    const char *dsa_alg = get_oqs_dsa_alg(sm->pqc_choice);
    const char *kem_alg = get_oqs_kem_alg(sm->pqc_choice);
    if (!dsa_alg || !kem_alg) return -1;

    sig = OQS_SIG_new(dsa_alg);
    kem = OQS_KEM_new(kem_alg);
    if (!sig || !kem) goto cleanup;

    /* crypto 
    * ML-DSA: verify signature over ciphertext using AP's key from PAKE-2 
    */
    if (OQS_SIG_verify(sig, sm->pasn_ciphertext, sm->pasn_ciphertext_len,
                       signature, sig_len, sm->dsa_public_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - ML-DSA signature verification failed");
        goto cleanup;
    }
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - ML-DSA signature verification successful");

    /* ML-KEM decapsulation */
    sm->pasn_shared_secret_len = kem->length_shared_secret;
    if (sm->pasn_shared_secret) OQS_MEM_secure_free(sm->pasn_shared_secret, sm->pasn_shared_secret_len);
    
    sm->pasn_shared_secret = os_malloc(sm->pasn_shared_secret_len);
    if (!sm->pasn_shared_secret) goto cleanup;

    if (OQS_KEM_decaps(kem, sm->pasn_shared_secret, sm->pasn_ciphertext, sm->sta_second_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - ML-KEM decapsulation failed");
        goto cleanup;
    }
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - ML-KEM decapsulation successful (shared secret len: %zu)",
               sm->pasn_shared_secret_len);

    /* PTK derivation */
    wpa_hexdump(MSG_ERROR, "PQC_DEBUG_STA: PMK", sm->pmk, PMK_LEN);
    if (pqc_derive_pasn_ptk(sm->pmk, sm->wpa_s->own_addr, sm->wpa_s->bssid,
                            sm->pasn_shared_secret, sm->pasn_shared_secret_len,
                            sm->pasn_ptk) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PTK derivation failed");
        goto cleanup;
    }

    // cut PTK into subkeys: KEK, KCK, TK
    os_memcpy(sm->pasn_kek, sm->pasn_ptk, KEK_LEN);
    os_memcpy(sm->pasn_kck, sm->pasn_ptk + KEK_LEN, KCK_LEN);
    os_memcpy(sm->pasn_tk, sm->pasn_ptk + KEK_LEN + KCK_LEN, TK_LEN);
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PTK derived successfully");

    /* MIC1 verification: HMAC-SHA256(KCK, ciphertext || signature) */
    struct wpabuf *mic1_input = wpabuf_alloc(sm->pasn_ciphertext_len + sig_len);
    if (!mic1_input) goto cleanup;

    wpabuf_put_data(mic1_input, sm->pasn_ciphertext, sm->pasn_ciphertext_len);
    wpabuf_put_data(mic1_input, signature, sig_len);

    u8 mic1_calculated[MIC_LEN];
    hmac_sha256(sm->pasn_kck, KCK_LEN, wpabuf_head(mic1_input), wpabuf_len(mic1_input), mic1_calculated);
    wpabuf_free(mic1_input);

    if (os_memcmp_const(mic1_calculated, sm->pasn_mic1, MIC_LEN) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - MIC1 verification failed");
        goto cleanup;
    }

    /* MIC2 generation */
    hmac_sha256(sm->pasn_kck, KCK_LEN, sm->pasn_ptk, PTK_LEN, sm->pasn_mic2);
    wpa_printf(MSG_INFO, "PQC_LOG: PASN - generated MIC2 and saved in state machine");

    /* Send PASN-3*/
    wpa_printf(MSG_DEBUG, "PQC_LOG: Sending PASN-3 frame with MIC2 [PQC_STAGE_6_END]");
    if (wpas_pqc_send_pasn3(sm) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Failed to send PASN-3 frame");
        goto cleanup;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: PASN-3 frame sent successfully. Waiting for group keys...");
    ret = 0;

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return ret;
}


/**
 * wpas_pqc_send_pasn3 - Build and send PASN-3 frame with MIC2
 *
 * Frame structure:
 * - Category (1B): WLAN_ACTION_PUBLIC
 * - Action (1B): WLAN_PA_VENDOR_SPECIFIC
 * - OUI (3B): PQC_OUI
 * - Type (1B): PQC_OUI_TYPE_PASN
 * - Subtype (1B): PQC_PASN_TYPE_1
 * - Payload:
 *   - MIC2 - 32 bytes 
 *
 * @sm: PQC state machine
 * Returns: 0 on success, -1 on failure
 */

int wpas_pqc_send_pasn3(struct wpa_pqc_sm *sm) {
    int ret = -1;
    // Using the MIC2 derived earlier (during PASN-2 parsing)
    if (!sm || !sm->wpa_s) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - State machine not initialized");
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Assembling PAKE-3 frame");
    // Payload: MIC2 (32)
    size_t payload_len = MIC_LEN;
    struct wpabuf *payload = wpabuf_alloc(payload_len);
    if (!payload) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to allocate PASN-3 payload");
        return -1;
    }

    /* Payload: MIC2 */
    wpabuf_put_data(payload, sm->pasn_mic2, MIC_LEN);

    /* Get target BSSID */
    const u8 *target_bssid = sm->wpa_s->pending_bssid;
    static const u8 zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};

    if (os_memcmp(target_bssid, zero_mac, ETH_ALEN) == 0 && sm->wpa_s->current_bss) {
        target_bssid = sm->wpa_s->current_bss->bssid;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: [PQC_TX_PAKE3_END] PASN - Sending PASN-3 frame to: " MACSTR, MAC2STR(target_bssid));

    /* Send action frame */
    ret = pqc_send_fragmented_action_frame(sm, sta_tx_action_wrapper, target_bssid, 
                                           PQC_OUI_TYPE_PASN, PQC_PASN_TYPE_3, 
                                           wpabuf_head(payload), wpabuf_len(payload));

    if (ret == 0) {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-3 frame sent successfully");
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to send PASN-3 frame");
    }

    wpabuf_free(payload);
    return ret;
}

/* Parsing of PASN-4 */
int pqc_sm_rx_pasn4(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len) {
    /* Group keys: GTK (16B) + IGTK (16B) = 32B. 
     * AES Key Wrap adds an 8-byte overhead. */
    const size_t UNWRAPPED_KEYS_LEN = 32; 
    const size_t WRAPPED_KEYS_LEN = UNWRAPPED_KEYS_LEN + 8;
     
    if (!sm || !sm->wpa_s || !payload) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid state machine or payload");
        return -1;
    }

    if (payload_len < WRAPPED_KEYS_LEN + MIC_LEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid PASN-4 frame (too short)");
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Processing PASN-4 frame from AP");

    /* Parsing of payload: Encrypted keys (40B) + MIC3 (32B) */
    size_t enc_keys_len = payload_len - MIC_LEN;
    const u8 *enc_keys = payload;
    const u8 *mic3 = payload + enc_keys_len;

    /* MIC 3 verify */
    u8 mic3_calculated[MIC_LEN];
    hmac_sha256(sm->pasn_kck, KCK_LEN, enc_keys, enc_keys_len, mic3_calculated);

    if (os_memcmp_const(mic3_calculated, mic3, MIC_LEN) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - MIC3 verification failed. Disconnecting.");
        return -1;
    }
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - MIC3 verified successfully");

    /* Unwrapping of GTK and IGTK */
    u8 group_keys[UNWRAPPED_KEYS_LEN]; // 16B GTK + 16B IGTK

    if (aes_unwrap(sm->pasn_kek, KEK_LEN, TIMES_AES_WRAP, enc_keys, group_keys) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to decrypt group keys (AES Unwrap error)");
        return -1;
    }

    const u8 *gtk = group_keys;
    const u8 *igtk = group_keys + 16;
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Group keys decrypted successfully");

    /* instalation of keys in hardware */
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_STA: TK", sm->pasn_tk, TK_LEN);
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_STA: KEK", sm->pasn_kek, KEK_LEN);
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_STA: KCK", sm->pasn_kck, KCK_LEN);
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_STA: PTK", sm->pasn_ptk, PTK_LEN);

    if (wpa_drv_set_key(sm->wpa_s, -1, WPA_ALG_CCMP, sm->wpa_s->bssid, 
                        0, 1, NULL, 0, sm->pasn_tk, TK_LEN, KEY_FLAG_PAIRWISE) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to install TK to hardware");
    } else {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - TK installed successfully");
    }

    sm->wpa_s->pairwise_cipher = WPA_CIPHER_CCMP;
    sm->wpa_s->group_cipher = WPA_CIPHER_CCMP;
    sm->wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X;

    u8 broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* GTK */
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_STA: GTK", gtk, 16);
    if (wpa_drv_set_key(sm->wpa_s, -1, WPA_ALG_CCMP, broadcast_mac, 
                        1, 0, NULL, 0, gtk, 16, KEY_FLAG_GROUP) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to install GTK to hardware");
    } else {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - GTK installed successfully");
    }

    /* IGTK */
    wpa_hexdump(MSG_ERROR, "PQC_DEBUG_STA: IGTK", igtk, 16);
    if (wpa_drv_set_key(sm->wpa_s, -1, WPA_ALG_BIP_CMAC_128, broadcast_mac, 
                        4, 0, NULL, 0, igtk, 16, KEY_FLAG_GROUP) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to install IGTK to hardware");
    } else {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - IGTK installed successfully");
    }

    /* END (finally) */
    if (wpa_drv_set_supp_port(sm->wpa_s, 1) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to authorize port");
    } else {
        wpa_printf(MSG_INFO, "PQC_LOG: PASN - Port authorized successfully!");
    }
    
    wpa_supplicant_set_state(sm->wpa_s, WPA_COMPLETED);

    
    wpa_printf(MSG_INFO, "PQC_LOG: *** PASN PHASE COMPLETE!! Fully connected and secure (PQC) [PQC_STAGE_7_END]***");

    return 0;
}