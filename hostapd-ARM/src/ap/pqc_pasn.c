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
#include "wpa_auth.h"
#include "wpa_auth_i.h"
#include "../crypto/aes_wrap.h"

#include <string.h>

static int hostapd_pqc_send_pasn2(struct hostapd_pqc_sm *sm,
                                   const u8 *ciphertext, size_t ciphertext_len,
                                   const u8 *mic1);
static int hostapd_pqc_send_pasn2_sig(struct hostapd_pqc_sm *sm,
                                       const u8 *signature, size_t sig_len);
static int hostapd_pqc_send_pasn4(struct hostapd_pqc_sm *sm,
                                  const u8 *enc_keys, size_t enc_keys_len, const u8 *mic3);

static int ap_tx_action_wrapper(void *ctx, const u8 *dst_mac, const u8 *data, size_t data_len) {
    struct hostapd_pqc_sm *sm = ctx;
    /* Send via AP driver interface on the current frequency */
    return hostapd_drv_send_action(sm->hapd, sm->hapd->iface->freq, 0, dst_mac, data, data_len);
}

/**
 * pqc_ap_sm_rx_pasn1 - Process received PASN-1 frame from STA
 *
 * PASN-1 frame structure:
 * - Offset 0-1: ML-KEM public key length (BE16)
 * - Offset 2-(2+key_len): ML-KEM public key
 * - Offset (2+key_len)-(2+key_len+ETH_ALEN): STA MAC address
 *
 * After parsing PASN-1, AP encapsulates a shared secret, generates 
 * a signature over the ciphertext, derives the PTK, and sends PASN-2.
 *
 * @sm: AP PQC state machine
 * @sta: STA info structure
 * @hapd: Hostapd data
 * @payload: PASN-1 payload (fully reassembled by interception loop)
 * @len: Payload length
 * Returns: 0 on success, -1 on failure
 */
int pqc_ap_sm_rx_pasn1(struct hostapd_pqc_sm *sm, struct sta_info *sta, struct hostapd_data *hapd,
                       const u8 *payload, size_t len) {
    OQS_SIG *sig = NULL;
    OQS_KEM *kem = NULL;
    int ret = -1;
    u8 pmk[PMK_LEN];

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Processing PASN-1 frame (ML-KEM focus)");

    if (!sm || !sta || !hapd || !payload || len < 2 +ETH_ALEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Invalid PASN-1 parameters (or frame too short)");
        return -1;
    }

    /* Parsing PASN-1 (Extract ML-KEM Key) */
    const u8 *pos = payload;
    size_t remaining = len;

    u16 sta_kem_pub_len = WPA_GET_BE16(pos);
    pos += 2;
    remaining -= 2;

    if (remaining < (size_t)sta_kem_pub_len + ETH_ALEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PASN-1 too short for KEM key and MAC");
        return -1;
    }

    const u8 *sta_kem_pub = pos;
    pos += sta_kem_pub_len;
    const u8 *sta_mac = pos;

    /* Verify MAC address matches STA */
    if (os_memcmp(sta_mac, sta->addr, ETH_ALEN) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - MAC mismatch in PASN-1");
        return -1;
    }

    /* Save the STA's ML-KEM public key into the state machine */
    if (sm->kem_pub_key) {
        os_free(sm->kem_pub_key);
    }
    sm->kem_pub_key = os_malloc(sta_kem_pub_len);
    if (!sm->kem_pub_key) return -1;

    os_memcpy(sm->kem_pub_key, sta_kem_pub, sta_kem_pub_len);
    sm->kem_pub_key_len = sta_kem_pub_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Parsed ML-KEM public key (len: %u)", sta_kem_pub_len);

    /* ML-KEM Encapsulation */
    kem = OQS_KEM_new(get_oqs_kem_alg(sm->pqc_choice));
    if (!kem) goto cleanup;

    /* Prevent memory leaks on state machine retries */
    if (sm->pasn_ciphertext) os_free(sm->pasn_ciphertext);
    if (sm->pasn_shared_secret) OQS_MEM_secure_free(sm->pasn_shared_secret, sm->pasn_shared_secret_len);

    sm->pasn_ciphertext_len = kem->length_ciphertext;
    sm->pasn_ciphertext = os_malloc(sm->pasn_ciphertext_len);
    sm->pasn_shared_secret_len = kem->length_shared_secret;
    sm->pasn_shared_secret = os_malloc(sm->pasn_shared_secret_len);

    if (!sm->pasn_ciphertext || !sm->pasn_shared_secret) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Encapsulation memory allocation failed");
        goto cleanup;
    }

    /* Encapsulate using the key we just parsed from the STA */
    if (OQS_KEM_encaps(kem, sm->pasn_ciphertext, sm->pasn_shared_secret, sm->kem_pub_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - ML-KEM Encapsulation failed");
        goto cleanup;
    }

    /* ML-DSA Signature Generation */
    sig = OQS_SIG_new(get_oqs_dsa_alg(sm->pqc_choice));
    if (!sig) goto cleanup;

    if (sm->pasn_dsa_signature) os_free(sm->pasn_dsa_signature);

    sm->pasn_dsa_signature_len = sig->length_signature;
    sm->pasn_dsa_signature = os_malloc(sm->pasn_dsa_signature_len);
    if (!sm->pasn_dsa_signature) goto cleanup;

    size_t actual_sig_len = sm->pasn_dsa_signature_len;
    if (OQS_SIG_sign(sig, sm->pasn_dsa_signature, &actual_sig_len,
                     sm->pasn_ciphertext, sm->pasn_ciphertext_len,
                     sm->dsa_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - ML-DSA Signing failed");
        goto cleanup;
    }
    sm->pasn_dsa_signature_len = actual_sig_len;

    /* PTK Derivation (PBKDF2-SHA256) */
    /* Get the PMK (from earlier PAKE phase) */
    if (pqc_ap_sm_derive_pmk(sm, pmk) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PMK derivation failed");
        goto cleanup;
    }
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_AP: PMK", pmk, PMK_LEN);
    /* PBKDF2-SHA256: Password is PMK, Salt is the concatenated buffer */
    if (pqc_derive_pasn_ptk(pmk, sta->addr, hapd->own_addr,
                            sm->pasn_shared_secret, sm->pasn_shared_secret_len,
                            sm->pasn_ptk) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PBKDF2-SHA256 failed");
        goto cleanup;
    }

    /* Split PTK into KEK and KCK */
    os_memcpy(sm->pasn_kek, sm->pasn_ptk, KEK_LEN);
    os_memcpy(sm->pasn_kck, sm->pasn_ptk + KEK_LEN, KCK_LEN);
    os_memcpy(sm->pasn_tk, sm->pasn_ptk + KEK_LEN + KCK_LEN, TK_LEN);

    /* MIC1 Generation */
    size_t mic_input_len = sm->pasn_ciphertext_len + sm->pasn_dsa_signature_len;
    struct wpabuf *mic_input = wpabuf_alloc(mic_input_len);
    if (!mic_input) goto cleanup;

    wpabuf_put_data(mic_input, sm->pasn_ciphertext, sm->pasn_ciphertext_len);
    wpabuf_put_data(mic_input, sm->pasn_dsa_signature, sm->pasn_dsa_signature_len);

    hmac_sha256(sm->pasn_kck, KCK_LEN, wpabuf_head(mic_input), wpabuf_len(mic_input), sm->pasn_mic1);
    wpabuf_free(mic_input);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - PASN-2 prepared (PTK derived via PBKDF2)");

    /* Send Response */
    ret = hostapd_pqc_send_pasn2(sm, 
                                 sm->pasn_ciphertext, sm->pasn_ciphertext_len,
                                 sm->pasn_mic1);
    if (ret == 0)
        ret = hostapd_pqc_send_pasn2_sig(sm,
                                         sm->pasn_dsa_signature, sm->pasn_dsa_signature_len);

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return ret;
}

/* PASN-2: ciphertext + MIC1 only (AP ML-DSA key is already known to STA from PAKE-2;
 * signature is sent separately in PASN-2-SIG frames to stay under frame size limits). */
static int hostapd_pqc_send_pasn2(struct hostapd_pqc_sm *sm,
                                   const u8 *ciphertext, size_t ciphertext_len,
                                   const u8 *mic1) {
    struct wpabuf *payload;
    int ret = -1;

    if (!sm || !sm->hapd || !ciphertext || !mic1)
        return -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Constructing PASN-2 frame");

    /* Payload - ct_len(2) + ct + mic1(32) */
    size_t payload_len = 2 + ciphertext_len + MIC_LEN;
    payload = wpabuf_alloc(payload_len);
    if (!payload)
        return -1;

    wpabuf_put_be16(payload, (u16)ciphertext_len);
    wpabuf_put_data(payload, ciphertext, ciphertext_len);
    wpabuf_put_data(payload, mic1, MIC_LEN);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - Sending PASN-2 frame to " MACSTR
               " (ciphertext len: %zu)", MAC2STR(sm->sta->addr), ciphertext_len);

    ret = pqc_send_fragmented_action_frame(sm, ap_tx_action_wrapper, sm->sta->addr,
                                           PQC_OUI_TYPE_PASN, PQC_PASN_TYPE_2,
                                           wpabuf_head(payload), wpabuf_len(payload));
    if (ret == 0)
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - PASN-2 frame sent successfully");
    else
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-2 frame");

    wpabuf_free(payload);
    return ret;
}

/* PASN-2-SIG: send ML-DSA signature in 1400-byte fragments.
 * Frame payload: total_sig_len(2) + signature (variable) */
static int hostapd_pqc_send_pasn2_sig(struct hostapd_pqc_sm *sm,
                                       const u8 *signature, size_t sig_len) {
    int ret = -1;

    if (!sm || !sm->hapd || !sm->sta || !signature)
        return -1;                                        

    wpa_printf(MSG_INFO, "PQC_LOG: AP - Sending PASN-2-SIG frame to " MACSTR
               " (signature len: %zu bytes)", MAC2STR(sm->sta->addr), sig_len);

    ret = pqc_send_fragmented_action_frame(sm, ap_tx_action_wrapper, sm->sta->addr,
                                            PQC_OUI_TYPE_PASN, PQC_PASN_TYPE_2_SIG,
                                            signature, sig_len);
    if (ret == 0)
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - PASN-2-SIG frame sent successfully");
    else
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-2-SIG frame");

    return ret;
}


/* parsing PASN-3 */
int pqc_ap_sm_rx_pasn3(struct hostapd_pqc_sm *sm, struct sta_info *sta, struct hostapd_data *hapd,
                       const u8 *payload, size_t len) {

    if (!sm || !sta || !payload || len < MIC_LEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Invalid PASN-3 frame parameters");
        return -1;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Processing PASN-3 frame. Verifying MIC2...");

    /* MIC2 Verification */
    u8 mic2_calculated[MIC_LEN];
    hmac_sha256(sm->pasn_kck, KCK_LEN, sm->pasn_ptk, PTK_LEN, mic2_calculated);

    if (os_memcmp_const(mic2_calculated, payload, MIC_LEN) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - MIC2 verification failed. Dropping connection.");
        return -1;
    }
    wpa_printf(MSG_INFO, "PQC_LOG: AP - MIC2 verified successfully.");

    /* GTK and IGTK extraction */
    const size_t UNWRAPPED_KEYS_LEN = 32; /* 16B GTK + 16B IGTK */
    const size_t WRAPPED_KEYS_LEN = UNWRAPPED_KEYS_LEN + 8; /* AES Wrap overhead */

    u8 group_keys[UNWRAPPED_KEYS_LEN]; 
    u8 *gtk = group_keys;
    u8 *igtk = group_keys + 16;
    
    /* Fetch real GTK/IGTK from authenticator if ready */
    if (hapd->wpa_auth && hapd->wpa_auth->group) {
        os_memcpy(gtk, hapd->wpa_auth->group->GTK[hapd->wpa_auth->group->GN - 1], 16);
        os_memcpy(igtk, hapd->wpa_auth->group->IGTK[hapd->wpa_auth->group->GN_igtk - 4], 16);
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Fetched real GTK and IGTK from authenticator");
    } else {
        wpa_printf(MSG_WARNING, "PQC_LOG: AP - wpa_auth group not ready, using random keys (fallback)");
        os_get_random(gtk, 16);
        os_get_random(igtk, 16);
    }

    /* Encrypting GTK and IGTK with AES-WRAP*/
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_AP: GTK", gtk, 16);
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_AP: IGTK", igtk, 16);
    u8 enc_group_keys[WRAPPED_KEYS_LEN]; 
    if (aes_wrap(sm->pasn_kek, KEK_LEN, TIMES_AES_WRAP, group_keys, enc_group_keys) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to encrypt group keys");
        return -1;
    }

    /* MIC3 generation */
    u8 mic3[MIC_LEN];
    hmac_sha256(sm->pasn_kck, KCK_LEN, enc_group_keys, WRAPPED_KEYS_LEN, mic3);

    /* send PASN-4 */
    if (hostapd_pqc_send_pasn4(sm, enc_group_keys, WRAPPED_KEYS_LEN, mic3) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-4");
        return -1;
    }

    /* Instalation of TK (temporal key) in NIC driver*/
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_AP: TK", sm->pasn_tk, TK_LEN);
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_AP: KEK", sm->pasn_kek, KEK_LEN);
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_AP: KCK", sm->pasn_kck, KCK_LEN);
    wpa_hexdump(MSG_DEBUG, "PQC_DEBUG_AP: PTK", sm->pasn_ptk, PTK_LEN);

    if (hostapd_drv_set_key(hapd->conf->iface, hapd, WPA_ALG_CCMP, sta->addr, 
                            0, 0, 1, NULL, 0, sm->pasn_tk, TK_LEN, KEY_FLAG_PAIRWISE) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to install TK to hardware");
    } else {
        wpa_printf(MSG_INFO, "PQC_LOG: AP - TK installed successfully to hardware");
    }
    
    /* Port authorization (Opening 802.1X traffic for this station) */
    sta->flags |= WLAN_STA_AUTHORIZED;
    ap_sta_set_authorized(hapd, sta, 1);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - PASN phase complete. Station fully authorized.");
    return 0;
}

/* Function that sends PASN-4 to STA */
static int hostapd_pqc_send_pasn4(struct hostapd_pqc_sm *sm,
                                  const u8 *enc_keys, size_t enc_keys_len, const u8 *mic3) {
    struct wpabuf *payload;
    int ret  = -1;
                                    
    if (!sm || !sm->hapd || !sm->sta || !enc_keys || !mic3) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Invalid PASN-4 arguments");
        return -1;
    }

    /* Length: Keys(40) + MIC3(32) */
    size_t payload_len = enc_keys_len + MIC_LEN;
    payload = wpabuf_alloc(payload_len);
    if (!payload) return -1;

    /* pack the data */
    wpabuf_put_data(payload, enc_keys, enc_keys_len);
    wpabuf_put_data(payload, mic3, MIC_LEN);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - Sending PASN-4 frame to " MACSTR, MAC2STR(sm->sta->addr));

    ret = pqc_send_fragmented_action_frame(sm, ap_tx_action_wrapper, sm->sta->addr,
                                           PQC_OUI_TYPE_PASN, PQC_PASN_TYPE_4, 
                                           wpabuf_head(payload), wpabuf_len(payload));

    if (ret == 0) {
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - PASN-4 sent successfully");
    } else {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-4");
    }

    wpabuf_free(payload);
    return ret;
}
