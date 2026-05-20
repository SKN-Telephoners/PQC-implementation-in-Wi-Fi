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
    struct wpabuf *buf = NULL;
    int ret = -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Starting PASN-1 frame construction");

    if (!sm || !sm->sta_mldsa_public_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Missing ML-DSA public key");
        return -1;
    }

    /* Frame length calculation:
     * Header: Category (1) + Action (1) + OUI (3) + Type (1) + Subtype (1)
     * Payload: ML-DSA pub key length (2) + ML-DSA pub key + MAC (6)
     */
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + 2 + sm->sta_mldsa_public_len + ETH_ALEN;
    buf = wpabuf_alloc(frame_len);
    if (!buf) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Buffer allocation failed");
        return -1;
    }

    /* Action Frame header */
    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);             // Category: Public (4)
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);        // Action: Vendor Specific (9)

    /* OUI */
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);

    /* PQC Type and Subtype */
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PASN);              // Type: PASN
    wpabuf_put_u8(buf, PQC_PASN_TYPE_1);                // Subtype: PASN-1

    /* Payload: ML-DSA public key with length prefix */
    wpabuf_put_be16(buf, sm->sta_mldsa_public_len);
    wpabuf_put_data(buf, sm->sta_mldsa_public_key, sm->sta_mldsa_public_len);

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
               " (ML-DSA pub key len: %zu bytes)",
               MAC2STR(target_bssid), sm->sta_mldsa_public_len);

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

/**
 * pqc_sm_rx_pasn2 - Process received PASN-2 frame from AP
 *
 * PASN-2 frame contains:
 * - AP's ML-DSA public key (for signature verification)
 * - ML-KEM ciphertext (for KEM decapsulation)
 * - ML-DSA signature over ciphertext
 * - MIC1 (HMAC-SHA256 for integrity verification)
 *
 * @sm: PQC state machine
 * @payload: PASN-2 payload
 * @payload_len: Payload length
 * Returns: 0 on success, -1 on failure
 */
int pqc_sm_rx_pasn2(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len) {
    OQS_SIG *sig = NULL;
    OQS_KEM *kem = NULL;
    int ret = -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Processing PASN-2 frame from AP");
    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PASN-2 payload length: %zu bytes", payload_len);

    if (!sm || !payload || payload_len < 10) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Invalid PASN-2 frame (too short)");
        return -1;
    }

    const char *dsa_alg = get_oqs_dsa_alg(sm->pqc_choice);
    if (!dsa_alg) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Error in mapping DSA algorithm");
        return -1;
    }

    sig = OQS_SIG_new(dsa_alg);
    if (!sig) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Error in initializing OQS SIG for verification");
        return -1;
    }

    const char *kem_alg = get_oqs_kem_alg(sm->pqc_choice);
    if (!kem_alg) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Error in mapping KEM algorithm");
        goto cleanup;
    }

    kem = OQS_KEM_new(kem_alg);
    if (!kem) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Error in initializing OQS KEM");
        goto cleanup;
    }

    /* Parse PASN-2 payload:
     * Offset 0-1: AP ML-DSA public key length (BE16)
     * Offset 2-(2+key_len): AP ML-DSA public key
     * Offset (2+key_len) to (2+key_len+1): Ciphertext length (BE16)
     * Offset (2+key_len+2)-(2+key_len+2+c_len): ML-KEM ciphertext
     * Offset (2+key_len+2+c_len) to (2+key_len+2+c_len+1): Signature length (BE16)
     * Offset (2+key_len+2+c_len+2)-(2+key_len+2+c_len+2+s_len): ML-DSA signature
     * Offset (2+key_len+2+c_len+2+s_len)-(2+key_len+2+c_len+2+s_len+31): MIC1 (32 bytes)
     */
    const u8 *pos = payload;
    size_t remaining = payload_len;

    /* Read AP's ML-DSA public key length */
    if (remaining < 2) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2 payload too short for AP key length");
        goto cleanup;
    }

    u16 ap_mldsa_pub_len = WPA_GET_BE16(pos);
    pos += 2;
    remaining -= 2;

    if (remaining < ap_mldsa_pub_len + 6) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2 payload too short for AP key");
        goto cleanup;
    }

    const u8 *ap_mldsa_pub = pos;
    pos += ap_mldsa_pub_len;
    remaining -= ap_mldsa_pub_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Parsed AP ML-DSA public key (len: %u)", ap_mldsa_pub_len);

    /* Read ciphertext length */
    u16 ciphertext_len = WPA_GET_BE16(pos);
    pos += 2;
    remaining -= 2;

    if (remaining < ciphertext_len + 4) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2 payload too short for ciphertext");
        goto cleanup;
    }

    const u8 *ciphertext = pos;
    pos += ciphertext_len;
    remaining -= ciphertext_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Parsed ML-KEM ciphertext (len: %u)", ciphertext_len);

    /* Read signature length */
    u16 sig_len = WPA_GET_BE16(pos);
    pos += 2;
    remaining -= 2;

    if (remaining < sig_len + 32) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2 payload too short for signature and MIC1");
        goto cleanup;
    }

    const u8 *signature = pos;
    pos += sig_len;
    remaining -= sig_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Parsed ML-DSA signature (len: %u)", sig_len);

    /* Read MIC1 (32 bytes) */
    if (remaining < 32) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - PASN-2 payload too short for MIC1");
        goto cleanup;
    }

    const u8 *mic1_received = pos;

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Parsed MIC1");

    /* Save AP's ML-DSA public key */
    if (sm->dsa_public_key) {
        os_free(sm->dsa_public_key);
    }
    sm->dsa_public_key = os_malloc(ap_mldsa_pub_len);
    if (!sm->dsa_public_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Memory allocation error for AP ML-DSA key");
        goto cleanup;
    }

    os_memcpy(sm->dsa_public_key, ap_mldsa_pub, ap_mldsa_pub_len);
    sm->dsa_keys_len = ap_mldsa_pub_len;

    /* Verify ML-DSA signature over ciphertext */
    if (OQS_SIG_verify(sig, ciphertext, ciphertext_len,
                       signature, sig_len, ap_mldsa_pub) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - ML-DSA signature verification failed");
        goto cleanup;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - ML-DSA signature verification successful");

    /* ML-KEM Decapsulation */
    sm->pasn_shared_secret_len = kem->length_shared_secret;
    sm->pasn_shared_secret = os_malloc(sm->pasn_shared_secret_len);
    if (!sm->pasn_shared_secret) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Memory allocation error for shared secret");
        goto cleanup;
    }

    if (OQS_KEM_decaps(kem, sm->pasn_shared_secret, ciphertext, sm->sta_second_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - ML-KEM decapsulation failed");
        goto cleanup;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - ML-KEM decapsulation successful (shared secret len: %zu)",
               sm->pasn_shared_secret_len);

    /* Save ciphertext and signature for MIC1 verification */
    if (sm->pasn_ciphertext) os_free(sm->pasn_ciphertext);
    sm->pasn_ciphertext = os_malloc(ciphertext_len);
    if (!sm->pasn_ciphertext) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Memory allocation error for ciphertext");
        goto cleanup;
    }
    os_memcpy(sm->pasn_ciphertext, ciphertext, ciphertext_len);
    sm->pasn_ciphertext_len = ciphertext_len;

    if (sm->pasn_dsa_signature) os_free(sm->pasn_dsa_signature);
    sm->pasn_dsa_signature = os_malloc(sig_len);
    if (!sm->pasn_dsa_signature) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Memory allocation error for signature");
        goto cleanup;
    }
    os_memcpy(sm->pasn_dsa_signature, signature, sig_len);
    sm->pasn_dsa_signature_len = sig_len;

    /* Verify MIC1 = HMAC-SHA256(ciphertext || signature || KCK) */
    /* First, derive PTK from shared secret */
    struct wpabuf *ptk_input = wpabuf_alloc(32 + 19 + ETH_ALEN + ETH_ALEN + sm->pasn_shared_secret_len);
    if (!ptk_input) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Memory allocation error for PTK derivation");
        goto cleanup;
    }

    /* Get PMK from WPA state machine */
    u8 pmk[32];
    /* Try to get PMK from wpas_glue if available, otherwise use a derived value */
    if (!sm->wpa_s) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - WPA supplicant not available");
        wpabuf_free(ptk_input);
        goto cleanup;
    }

    /* PMK is set during WPA initialization - if not available, derive from K_aes */
    /* As fallback, use shared K_aes from PAKE phase as part of PTK input */
    os_memcpy(pmk, sm->K_aes, 32);

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - Using K_aes as PMK source for PTK derivation");

    wpabuf_put_data(ptk_input, pmk, 32);
    wpabuf_put_data(ptk_input, (const u8 *)"PASN key deriviation", 19);
    wpabuf_put_data(ptk_input, sm->wpa_s->own_addr, ETH_ALEN);
    wpabuf_put_data(ptk_input, sm->wpa_s->bssid, ETH_ALEN);
    wpabuf_put_data(ptk_input, sm->pasn_shared_secret, sm->pasn_shared_secret_len);

    /* Derive PTK */
    hmac_sha256_kdf(pmk, 32, "PASN PTK", wpabuf_head(ptk_input), wpabuf_len(ptk_input),
                    sm->pasn_ptk, 32);
    wpabuf_free(ptk_input);

    /* Extract KCK from PTK */
    os_memcpy(sm->pasn_kck, sm->pasn_ptk + 16, 16);

    wpa_printf(MSG_DEBUG, "PQC_LOG: PASN - PTK derived successfully");

    /* Calculate expected MIC1 */
    struct wpabuf *mic1_input = wpabuf_alloc(ciphertext_len + sig_len);
    if (!mic1_input) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - Memory allocation error for MIC1 calculation");
        goto cleanup;
    }

    wpabuf_put_data(mic1_input, ciphertext, ciphertext_len);
    wpabuf_put_data(mic1_input, signature, sig_len);

    u8 mic1_calculated[32];
    hmac_sha256(sm->pasn_kck, 16, wpabuf_head(mic1_input), wpabuf_len(mic1_input), mic1_calculated);
    wpabuf_free(mic1_input);

    /* Compare MIC1 */
    if (os_memcmp_const(mic1_calculated, mic1_received, 32) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: PASN - MIC1 verification failed");
        goto cleanup;
    }

    os_memcpy(sm->pasn_mic1, mic1_received, 32);

    wpa_printf(MSG_INFO, "PQC_LOG: PASN - PASN-2 verification successful (signature + MIC1 verified)");

    ret = 0;

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return ret;
}



