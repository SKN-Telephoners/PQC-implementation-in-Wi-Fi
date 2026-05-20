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
#include "pqc_pasn.h"

#include <string.h>

int hostapd_pqc_send_pasn2(struct hostapd_data *hapd, struct sta_info *sta,
                           const u8 *ap_mldsa_pub, size_t ap_mldsa_pub_len,
                           const u8 *ciphertext, size_t ciphertext_len,
                           const u8 *signature, size_t sig_len,
                           const u8 *mic1);

/**
 * pqc_ap_sm_rx_pasn1 - Process received PASN-1 frame from STA
 *
 * PASN-1 frame structure:
 * - Offset 0-1: ML-DSA public key length (BE16)
 * - Offset 2-(2+key_len): ML-DSA public key
 * - Offset (2+key_len)-(2+key_len+6): STA MAC address
 *
 * After parsing PASN-1, AP generates a signature over the received data
 * and sends it back in PASN-2 frame.
 *
 * @sm: AP PQC state machine
 * @sta: STA info structure
 * @hapd: Hostapd data
 * @payload: PASN-1 payload
 * @len: Payload length
 * Returns: 0 on success, -1 on failure
 */
int pqc_ap_sm_rx_pasn1(struct hostapd_pqc_sm *sm, struct sta_info *sta, struct hostapd_data *hapd,
                       const u8 *payload, size_t len) {
    OQS_SIG *sig = NULL;
    OQS_KEM *kem = NULL;
    int ret = -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Processing PASN-1 frame from STA");

    if (!sm || !sta || !hapd || !payload || len < 8) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Invalid PASN-1 frame parameters");
        return -1;
    }

    /* --- Parsing PASN-1 --- */
    const u8 *pos = payload;
    size_t remaining = len;

    /* Read STA's ML-DSA public key length */
    if (remaining < 2) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PASN-1 payload too short for key length");
        return -1;
    }

    u16 sta_mldsa_pub_len = WPA_GET_BE16(pos);
    pos += 2;
    remaining -= 2;

    if (remaining < sta_mldsa_pub_len + ETH_ALEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PASN-1 payload too short for key and MAC");
        return -1;
    }

    const u8 *sta_mldsa_pub = pos;
    pos += sta_mldsa_pub_len;
    remaining -= sta_mldsa_pub_len;

    const u8 *sta_mac = pos;

    /* Verify MAC address matches STA */
    if (os_memcmp(sta_mac, sta->addr, ETH_ALEN) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PASN-1 STA MAC mismatch. Expected " MACSTR ", got " MACSTR,
                   MAC2STR(sta->addr), MAC2STR(sta_mac));
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - PASN-1 parsed successfully (ML-DSA pub key len: %u)", sta_mldsa_pub_len);

    /* Save STA's ML-DSA public key */
    if (sm->sta_mldsa_public_key) {
        os_free(sm->sta_mldsa_public_key);
    }
    sm->sta_mldsa_public_key = os_malloc(sta_mldsa_pub_len);
    if (!sm->sta_mldsa_public_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Memory allocation error for STA ML-DSA key");
        return -1;
    }

    os_memcpy(sm->sta_mldsa_public_key, sta_mldsa_pub, sta_mldsa_pub_len);
    sm->sta_mldsa_public_len = sta_mldsa_pub_len;

    /* --- ML-KEM Encapsulation --- */
    const char *kem_alg = get_oqs_kem_alg(sm->pqc_choice);
    if (!kem_alg) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Error in mapping KEM algorithm");
        return -1;
    }

    kem = OQS_KEM_new(kem_alg);
    if (!kem) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Error in initializing OQS KEM");
        return -1;
    }

    /* Allocate memory for ciphertext and shared secret */
    sm->pasn_ciphertext_len = kem->length_ciphertext;
    sm->pasn_ciphertext = os_malloc(sm->pasn_ciphertext_len);

    sm->pasn_shared_secret_len = kem->length_shared_secret;
    sm->pasn_shared_secret = os_malloc(sm->pasn_shared_secret_len);

    if (!sm->pasn_ciphertext || !sm->pasn_shared_secret) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Memory allocation error for KEM encapsulation");
        goto cleanup;
    }

    /* ML-KEM encapsulation using STA's ML-KEM public key */
    if (OQS_KEM_encaps(kem, sm->pasn_ciphertext, sm->pasn_shared_secret, sm->kem_pub_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Error in KEM encapsulation");
        goto cleanup;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - ML-KEM encapsulation successful (ciphertext len: %zu, shared secret len: %zu)",
               sm->pasn_ciphertext_len, sm->pasn_shared_secret_len);

    /* --- ML-DSA Sign over ciphertext --- */
    const char *dsa_alg = get_oqs_dsa_alg(sm->pqc_choice);
    if (!dsa_alg) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Error in mapping DSA algorithm");
        goto cleanup;
    }

    sig = OQS_SIG_new(dsa_alg);
    if (!sig) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Error in initializing OQS SIG");
        goto cleanup;
    }

    sm->pasn_dsa_signature_len = sig->length_signature;
    sm->pasn_dsa_signature = os_malloc(sm->pasn_dsa_signature_len);
    if (!sm->pasn_dsa_signature) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Memory allocation error for DSA signature");
        goto cleanup;
    }

    size_t actual_sig_len = sm->pasn_dsa_signature_len;
    if (OQS_SIG_sign(sig, sm->pasn_dsa_signature, &actual_sig_len,
                     sm->pasn_ciphertext, sm->pasn_ciphertext_len,
                     sm->ap_mldsa_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Error in ML-DSA signature generation");
        goto cleanup;
    }

    sm->pasn_dsa_signature_len = actual_sig_len;
    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - ML-DSA signature generated successfully (sig len: %zu)", sm->pasn_dsa_signature_len);

    /* --- PTK Derivation via KDF-SHA256 --- */
    /* PTK input: PMK || "PASN key deriviation" || MAC_STA || MAC_AP || PQC_shared_secret */
    struct wpabuf *ptk_input = wpabuf_alloc(32 + 19 + ETH_ALEN + ETH_ALEN + sm->pasn_shared_secret_len);
    if (!ptk_input) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Memory allocation error for PTK derivation");
        goto cleanup;
    }

    /* Get PMK from WPA state machine */
    u8 pmk[32];
    if (pqc_ap_sm_derive_pmk(sm, pmk) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to derive PMK");
        wpabuf_free(ptk_input);
        goto cleanup;
    }

    wpabuf_put_data(ptk_input, pmk, 32);
    wpabuf_put_data(ptk_input, (const u8 *)"PASN key deriviation", 19);
    wpabuf_put_data(ptk_input, sta->addr, ETH_ALEN);
    wpabuf_put_data(ptk_input, hapd->own_addr, ETH_ALEN);
    wpabuf_put_data(ptk_input, sm->pasn_shared_secret, sm->pasn_shared_secret_len);

    /* Derive PTK using KDF-SHA256 */
    hmac_sha256_kdf(pmk, 32, "PASN PTK", wpabuf_head(ptk_input), wpabuf_len(ptk_input),
                    sm->pasn_ptk, 32);
    wpabuf_free(ptk_input);

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - PTK derived successfully");

    /* Split PTK into KEK, KCK, TK */
    os_memcpy(sm->pasn_kek, sm->pasn_ptk, 16);
    os_memcpy(sm->pasn_kck, sm->pasn_ptk + 16, 16);
    /* TK would be for additional encryption if needed */
    os_memcpy(sm->pasn_tk, sm->pasn_ptk, 16);

    /* --- Generate MIC1 --- */
    /* MIC1 = HMAC-SHA256(ciphertext || signature || KCK) */
    struct wpabuf *mic1_input = wpabuf_alloc(sm->pasn_ciphertext_len + sm->pasn_dsa_signature_len);
    if (!mic1_input) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Memory allocation error for MIC1");
        goto cleanup;
    }

    wpabuf_put_data(mic1_input, sm->pasn_ciphertext, sm->pasn_ciphertext_len);
    wpabuf_put_data(mic1_input, sm->pasn_dsa_signature, sm->pasn_dsa_signature_len);

    hmac_sha256(sm->pasn_kck, 16, wpabuf_head(mic1_input), wpabuf_len(mic1_input), sm->pasn_mic1);
    wpabuf_free(mic1_input);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - MIC1 generated successfully");

    /* Send PASN-2 response */
    ret = hostapd_pqc_send_pasn2(hapd, sta, sm->ap_mldsa_public_key, sm->ap_mldsa_public_len,
                                 sm->pasn_ciphertext, sm->pasn_ciphertext_len,
                                 sm->pasn_dsa_signature, sm->pasn_dsa_signature_len,
                                 sm->pasn_mic1);

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return ret;
}

/**
 * hostapd_pqc_send_pasn2 - Build and send PASN-2 frame with ML-KEM ciphertext, ML-DSA signature, and MIC1
 *
 * Frame structure:
 * - Category (1B): WLAN_ACTION_PUBLIC
 * - Action (1B): WLAN_PA_VENDOR_SPECIFIC
 * - OUI (3B): PQC_OUI
 * - Type (1B): PQC_OUI_TYPE_PASN
 * - Subtype (1B): PQC_PASN_TYPE_2
 * - Payload:
 *   - AP ML-DSA public key length (2B)
 *   - AP ML-DSA public key (variable)
 *   - Ciphertext length (2B)
 *   - ML-KEM ciphertext (variable)
 *   - Signature length (2B)
 *   - ML-DSA signature (variable)
 *   - MIC1 (32B)
 */
int hostapd_pqc_send_pasn2(struct hostapd_data *hapd, struct sta_info *sta,
                            const u8 *ap_mldsa_pub, size_t ap_mldsa_pub_len,
                            const u8 *ciphertext, size_t ciphertext_len,
                            const u8 *signature, size_t sig_len,
                            const u8 *mic1) {
    struct wpabuf *buf;
    int ret;

    if (!hapd || !sta || !ap_mldsa_pub || !ciphertext || !signature || !mic1) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Invalid PASN-2 parameters");
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Constructing PASN-2 frame");

    /* Frame length calculation:
     * Header: Category (1) + Action (1) + OUI (3) + Type (1) + Subtype (1)
     * Payload: AP ML-DSA pub key len (2) + AP ML-DSA pub key
     *        + ciphertext len (2) + ciphertext
     *        + signature len (2) + signature
     *        + MIC1 (32)
     */
    size_t frame_len = 1 + 1 + 3 + 1 + 1 +
                      2 + ap_mldsa_pub_len +
                      2 + ciphertext_len +
                      2 + sig_len +
                      32;
    buf = wpabuf_alloc(frame_len);
    if (!buf) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Buffer allocation failed");
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
    wpabuf_put_u8(buf, PQC_PASN_TYPE_2);                // Subtype: PASN-2

    /* Payload: AP ML-DSA public key with length prefix */
    wpabuf_put_be16(buf, ap_mldsa_pub_len);
    wpabuf_put_data(buf, ap_mldsa_pub, ap_mldsa_pub_len);

    /* Payload: ML-KEM ciphertext with length prefix */
    wpabuf_put_be16(buf, ciphertext_len);
    wpabuf_put_data(buf, ciphertext, ciphertext_len);

    /* Payload: ML-DSA signature with length prefix */
    wpabuf_put_be16(buf, sig_len);
    wpabuf_put_data(buf, signature, sig_len);

    /* Payload: MIC1 (fixed 32 bytes) */
    wpabuf_put_data(buf, mic1, 32);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - Sending PASN-2 frame to " MACSTR
               " (AP ML-DSA pub key len: %zu, ciphertext len: %zu, sig len: %zu)",
               MAC2STR(sta->addr), ap_mldsa_pub_len, ciphertext_len, sig_len);

    /* Send action frame */
    ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
                                  wpabuf_head(buf), wpabuf_len(buf));

    if (ret == 0) {
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - PASN-2 frame sent successfully");
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-2 frame");
    }

    wpabuf_free(buf);
    return ret;
}



