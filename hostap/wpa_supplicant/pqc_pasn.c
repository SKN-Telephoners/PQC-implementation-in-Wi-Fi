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

/**
 * pqc_pasn_generate_mldsa_keys - Generate ML-DSA key pair for PASN
 *
 * This function generates a new ML-DSA key pair that will be used in PASN-1 frame.
 * ML-DSA is used for digital signature operations in the PASN phase.
 *
 * @sm: PQC state machine
 * Returns: 0 on success, -1 on failure
 */
int pqc_pasn_generate_mldsa_keys(struct wpa_pqc_sm *sm) {
    OQS_SIG *sig = NULL;
    int ret = -1;

    if (!sm || !sm->pqc_enabled) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid state machine");
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Generating ML-DSA key pair");

    const char *alg_name = get_oqs_dsa_alg(sm->pqc_choice);
    if (!alg_name) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Error in mapping DSA algorithm");
        return -1;
    }

    sig = OQS_SIG_new(alg_name);
    if (!sig) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Error in initializing OQS SIG");
        return -1;
    }

    /* Memory allocation */
    sm->sta_mldsa_public_len = sig->length_public_key;
    sm->sta_mldsa_public_key = os_malloc(sm->sta_mldsa_public_len);

    sm->sta_mldsa_secret_len = sig->length_secret_key;
    sm->sta_mldsa_secret_key = os_malloc(sm->sta_mldsa_secret_len);

    if (!sm->sta_mldsa_public_key || !sm->sta_mldsa_secret_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Memory allocation error for ML-DSA keys");
        ret = -1;
        goto cleanup;
    }

    /* Generate ML-DSA key pair */
    if (OQS_SIG_keypair(sig, sm->sta_mldsa_public_key, sm->sta_mldsa_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Error in OQS SIG keypair generation");
        ret = -1;
        goto cleanup;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: PASN - ML-DSA key pair generated successfully (public_len=%zu, secret_len=%zu)",
               sm->sta_mldsa_public_len, sm->sta_mldsa_secret_len);

    ret = 0;

cleanup:
    if (ret != 0) {
        if (sm->sta_mldsa_public_key) {
            os_free(sm->sta_mldsa_public_key);
            sm->sta_mldsa_public_key = NULL;
        }
        if (sm->sta_mldsa_secret_key) {
            OQS_MEM_secure_free(sm->sta_mldsa_secret_key, sm->sta_mldsa_secret_len);
            sm->sta_mldsa_secret_key = NULL;
        }
    }

    if (sig) OQS_SIG_free(sig);
    return ret;
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
    int ret;
    struct wpabuf *buf = NULL;
    // Use the ML-KEM key generated during association/pqc_sm_assoc_success
    if (!sm || !sm->sta_second_pub_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Missing ML-KEM public key");
        return -1;
    }

    // Payload: Type (1) + Subtype (1) + ML-KEM Key Len (2) + ML-KEM Key (Var) + MAC (6)
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + 2 + sm->sta_second_pub_len + ETH_ALEN;
    buf = wpabuf_alloc(frame_len);
    if (!buf) return -1;

    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PASN);
    wpabuf_put_u8(buf, PQC_PASN_TYPE_1);

    /* ML-KEM public key */
    wpabuf_put_be16(buf, sm->sta_second_pub_len);
    wpabuf_put_data(buf, sm->sta_second_pub_key, sm->sta_second_pub_len);

    /* Payload: STA MAC address for verification on AP side */
    wpabuf_put_data(buf, sm->wpa_s->own_addr, ETH_ALEN);

    /* Get frequency and target BSSID */
    unsigned int freq = sm->wpa_s->current_bss ? sm->wpa_s->current_bss->freq : 2412;
    const u8 *target_bssid = sm->wpa_s->pending_bssid;

    static const u8 zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
    if (os_memcmp(target_bssid, zero_mac, ETH_ALEN) == 0 && sm->wpa_s->current_bss) {
        target_bssid = sm->wpa_s->current_bss->bssid;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: PASN - Sending PASN-1 frame to: " MACSTR
           " (ML-KEM pub key len: %zu bytes)",
           MAC2STR(target_bssid), sm->sta_second_pub_len);

    /* Send action frame */
    ret = wpa_drv_send_action(sm->wpa_s, freq, 0,
                              target_bssid,
                              sm->wpa_s->own_addr,
                              target_bssid,
                              wpabuf_head(buf), wpabuf_len(buf), 0);

    if (ret == 0) {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-1 frame sent successfully");
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to send PASN-1 frame");
    }

    wpabuf_free(buf);
    return ret;
}

/* pqc_sm_rx_pasn2 - Save ciphertext and MIC1 from PASN-2 frame.
 * Crypto verification is deferred until all PASN-2-SIG fragments arrive.
 *
 * Frame payload: ct_len(2) + ciphertext + MIC1(32)
 */
int pqc_sm_rx_pasn2(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len) {
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Processing PASN-2 frame from AP");
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-2 payload length: %zu bytes", payload_len);

    if (!sm || !payload || payload_len < 4 + 32) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid PASN-2 frame (too short)");
        return -1;
    }

    const u8 *pos = payload;
    u16 ciphertext_len = WPA_GET_BE16(pos);
    pos += 2;

    if (payload_len < (size_t)(2 + ciphertext_len + 32)) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2 truncated");
        return -1;
    }

    const u8 *ciphertext = pos;
    const u8 *mic1 = pos + ciphertext_len;

    /* Save ciphertext */
    if (sm->pasn_ciphertext)
        os_free(sm->pasn_ciphertext);
    sm->pasn_ciphertext = os_malloc(ciphertext_len);
    if (!sm->pasn_ciphertext)
        return -1;
    os_memcpy(sm->pasn_ciphertext, ciphertext, ciphertext_len);
    sm->pasn_ciphertext_len = ciphertext_len;

    /* Save MIC1 for later verification */
    os_memcpy(sm->pasn_mic1, mic1, 32);

    /* Reset signature reassembly state */
    if (sm->pasn_sig_buf) {
        os_free(sm->pasn_sig_buf);
        sm->pasn_sig_buf = NULL;
    }
    sm->pasn_sig_buf_len = 0;
    sm->pasn_sig_total_len = 0;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-2 saved (ct=%u bytes, MIC1 saved). Waiting for PASN-2-SIG...",
               ciphertext_len);
    return 0;
}

/* pqc_sm_rx_pasn2_sig - Accumulate ML-DSA signature fragments from PASN-2-SIG frames.
 * When all fragments are received, perform full crypto verification.
 *
 * Frame payload: frag_idx(1) + total_sig_len(2) + data_len(2) + data
 */
int pqc_sm_rx_pasn2_sig(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len) {
    OQS_SIG *sig = NULL;
    OQS_KEM *kem = NULL;
    int ret = -1;

    if (!sm || !payload || payload_len < 5) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid PASN-2-SIG frame");
        return -1;
    }

    const u8 *pos = payload;
    u8 frag_idx = *pos++;
    u16 total_sig_len = WPA_GET_BE16(pos); pos += 2;
    u16 data_len = WPA_GET_BE16(pos); pos += 2;

    if ((size_t)(pos - payload) + data_len > payload_len) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2-SIG data overruns frame");
        return -1;
    }

    /* Allocate reassembly buffer on first fragment */
    if (frag_idx == 0) {
        if (sm->pasn_sig_buf)
            os_free(sm->pasn_sig_buf);
        sm->pasn_sig_buf = os_malloc(total_sig_len);
        if (!sm->pasn_sig_buf)
            return -1;
        sm->pasn_sig_total_len = total_sig_len;
        sm->pasn_sig_buf_len = 0;
    }

    if (!sm->pasn_sig_buf || sm->pasn_sig_buf_len + data_len > sm->pasn_sig_total_len) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2-SIG buffer error (frag %u)", frag_idx);
        return -1;
    }

    os_memcpy(sm->pasn_sig_buf + sm->pasn_sig_buf_len, pos, data_len);
    sm->pasn_sig_buf_len += data_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-2-SIG frag %u received (%u bytes, total %zu/%zu)",
               frag_idx, data_len, sm->pasn_sig_buf_len, sm->pasn_sig_total_len);

    /* Wait for more fragments */
    if (sm->pasn_sig_buf_len < sm->pasn_sig_total_len)
        return 0;

    /* All fragments received — run crypto */
    const u8 *signature = sm->pasn_sig_buf;
    size_t sig_len = sm->pasn_sig_total_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - All PASN-2-SIG fragments received (%zu bytes). Verifying...", sig_len);

    if (!sm->dsa_public_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - AP ML-DSA public key missing (should have been saved from PAKE-2)");
        return -1;
    }
    if (!sm->pasn_ciphertext) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Ciphertext missing (PASN-2 not received first?)");
        return -1;
    }

    const char *dsa_alg = get_oqs_dsa_alg(sm->pqc_choice);
    const char *kem_alg = get_oqs_kem_alg(sm->pqc_choice);
    if (!dsa_alg || !kem_alg)
        return -1;

    sig = OQS_SIG_new(dsa_alg);
    kem = OQS_KEM_new(kem_alg);
    if (!sig || !kem)
        goto cleanup;

    /* ML-DSA: verify signature over ciphertext using AP's key from PAKE-2 */
    if (OQS_SIG_verify(sig, sm->pasn_ciphertext, sm->pasn_ciphertext_len,
                       signature, sig_len, sm->dsa_public_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - ML-DSA signature verification failed");
        goto cleanup;
    }
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - ML-DSA signature verification successful");

    /* ML-KEM decapsulation */
    sm->pasn_shared_secret_len = kem->length_shared_secret;
    if (sm->pasn_shared_secret)
        OQS_MEM_secure_free(sm->pasn_shared_secret, sm->pasn_shared_secret_len);
    sm->pasn_shared_secret = os_malloc(sm->pasn_shared_secret_len);
    if (!sm->pasn_shared_secret)
        goto cleanup;

    if (OQS_KEM_decaps(kem, sm->pasn_shared_secret, sm->pasn_ciphertext, sm->sta_second_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - ML-KEM decapsulation failed");
        goto cleanup;
    }
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - ML-KEM decapsulation successful (shared secret len: %zu)",
               sm->pasn_shared_secret_len);

    /* PTK derivation */
    if (pqc_derive_pasn_ptk(sm->pmk, sm->wpa_s->own_addr, sm->wpa_s->bssid,
                            sm->pasn_shared_secret, sm->pasn_shared_secret_len,
                            sm->pasn_ptk) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PTK derivation failed");
        goto cleanup;
    }
    os_memcpy(sm->pasn_kek, sm->pasn_ptk, 16);
    os_memcpy(sm->pasn_kck, sm->pasn_ptk + 16, 16);
    os_memcpy(sm->pasn_tk, sm->pasn_ptk + 32, 16);
    
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PTK derived successfully");

    /* MIC1 verification: HMAC-SHA256(KCK, ciphertext || signature) */
    struct wpabuf *mic1_input = wpabuf_alloc(sm->pasn_ciphertext_len + sig_len);
    if (!mic1_input)
        goto cleanup;
    wpabuf_put_data(mic1_input, sm->pasn_ciphertext, sm->pasn_ciphertext_len);
    wpabuf_put_data(mic1_input, signature, sig_len);

    u8 mic1_calculated[MIC_LEN];
    hmac_sha256(sm->pasn_kck, 16, wpabuf_head(mic1_input), wpabuf_len(mic1_input), mic1_calculated);
    wpabuf_free(mic1_input);

    if (os_memcmp_const(mic1_calculated, sm->pasn_mic1, 32) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - MIC1 verification failed");
        goto cleanup;
    }

    /* MIC2 generation */
    size_t mic2_input_len = PTK_LEN;
    u8 *mic2_input = os_malloc(mic2_input_len);
    if (!mic2_input) goto cleanup;

    os_memcpy(mic2_input, sm->pasn_ptk, PTK_LEN);

    hmac_sha256(sm->pasn_kck, KCK_LEN, mic2_input, mic2_input_len, sm->pasn_mic2);
    os_free(mic2_input);
    wpa_printf(MSG_INFO, "PQC_LOG: PASN - generated MIC2 and saved in state machine");

    /* Send PASN-3*/
    wpa_printf(MSG_DEBUG, "PQC_LOG: Sending PASN-3 frame with MIC2");

    if (wpas_pqc_send_pasn3(sm) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Failed to send PASN-3 frame");
        return -1;
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
    int ret;
    struct wpabuf *buf = NULL;
    // Use the MIC2 derived earlier (during PASN-2 parsing)
    if (!sm) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Missing MIC2");
        return -1;
    }

    // Payload: Type (1) + Subtype (1) + MIC_len (32)
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + MIC_LEN;
    buf = wpabuf_alloc(frame_len);
    if (!buf) return -1;

    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PASN);
    wpabuf_put_u8(buf, PQC_PASN_TYPE_3);

    /* Payload: MIC2 */
    wpabuf_put_data(buf, sm->pasn_mic2, MIC_LEN);

    /* Get frequency and target BSSID */
    unsigned int freq = sm->wpa_s->current_bss ? sm->wpa_s->current_bss->freq : 2412;
    const u8 *target_bssid = sm->wpa_s->pending_bssid;

    static const u8 zero_mac[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
    if (os_memcmp(target_bssid, zero_mac, ETH_ALEN) == 0 && sm->wpa_s->current_bss) {
        target_bssid = sm->wpa_s->current_bss->bssid;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: PASN - Sending PASN-3 frame to: " MACSTR, MAC2STR(target_bssid));

    /* Send action frame */
    ret = wpa_drv_send_action(sm->wpa_s, freq, 0,
                              target_bssid,
                              sm->wpa_s->own_addr,
                              target_bssid,
                              wpabuf_head(buf), wpabuf_len(buf), 0);

    if (ret == 0) {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-3 frame sent successfully");
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to send PASN-3 frame");
    }

    wpabuf_free(buf);
    return ret;
}

/* Parsing of PASN-4 */
int pqc_sm_rx_pasn4(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len) {
    if (!sm || !payload || payload_len < 40 + MIC_LEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid PASN-4 frame");
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Processing PASN-4 frame from AP");

    /* Parsing of payload: Encrypted keys(40B) + MIC3(32B) */
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
    u8 group_keys[32]; // 16B GTK + 16B IGTK
    if (aes_unwrap(sm->pasn_kek, KEK_LEN, 4, enc_keys, group_keys) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to decrypt group keys (AES Unwrap error)");
        return -1;
    }

    const u8 *gtk = group_keys;
    const u8 *igtk = group_keys + 16;
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Group keys decrypted successfully");

    /* instalation of keys in hardware */
    
    /* TK */
    if (wpa_drv_set_key(sm->wpa_s, -1, WPA_ALG_CCMP, sm->wpa_s->bssid, 
                        0, 1, NULL, 0, sm->pasn_tk, TK_LEN, KEY_FLAG_PAIRWISE) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to install TK to hardware");
    } else {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - TK installed successfully");
    }

    sm->wpa_s->pairwise_cipher = WPA_CIPHER_CCMP;
    sm->wpa_s->group_cipher = WPA_CIPHER_CCMP;
    sm->wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X;

    /* GTK */
    u8 broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (wpa_drv_set_key(sm->wpa_s, -1, WPA_ALG_CCMP, broadcast_mac, 
                        1, 0, NULL, 0, gtk, 16, KEY_FLAG_GROUP) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to install GTK to hardware");
    } else {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - GTK installed successfully");
    }

    /* IGTK */
    if (wpa_drv_set_key(sm->wpa_s, -1, WPA_ALG_BIP_CMAC_128, broadcast_mac, 
                        4, 0, NULL, 0, igtk, 16, KEY_FLAG_GROUP) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Failed to install IGTK to hardware");
    } else {
        wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - IGTK installed successfully");
    }

    /* END (finally) */
    wpa_supplicant_set_state(sm->wpa_s, WPA_COMPLETED);
    // wpa_supplicant_port_cb(sm->wpa_s, sm->wpa_s->bssid, 1);
    
    wpa_printf(MSG_INFO, "PQC_LOG: *** PASN PHASE COMPLETE! Fully connected and secure. ***");

    return 0;
}