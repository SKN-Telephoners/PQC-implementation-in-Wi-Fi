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

static int hostapd_pqc_send_pasn2(struct hostapd_data *hapd, struct sta_info *sta,
                                   const u8 *ciphertext, size_t ciphertext_len,
                                   const u8 *mic1);
static int hostapd_pqc_send_pasn4(struct hostapd_data *hapd, struct sta_info *sta,
                                  const u8 *enc_keys, size_t enc_keys_len, const u8 *mic3);
static int hostapd_pqc_send_pasn2_sig(struct hostapd_data *hapd, struct sta_info *sta,
                                       const u8 *signature, size_t sig_len);

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
    u8 pmk[32];

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Processing PASN-1 frame (ML-KEM focus)");

    if (!sm || !sta || !hapd || !payload || len < 8) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Invalid PASN-1 parameters");
        return -1;
    }

    /* --- 1. Parsing PASN-1 (Extract ML-KEM Key) --- */
    const u8 *pos = payload;
    size_t remaining = len;

    if (remaining < 2) return -1;
    u16 sta_kem_pub_len = WPA_GET_BE16(pos);
    pos += 2;
    remaining -= 2;

    if (remaining < (size_t)sta_kem_pub_len + ETH_ALEN) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PASN-1 too short for KEM key and MAC");
        return -1;
    }

    const u8 *sta_kem_pub = pos;
    pos += sta_kem_pub_len;
    remaining -= sta_kem_pub_len;
    const u8 *sta_mac = pos;

    /* Verify MAC address matches STA */
    if (os_memcmp(sta_mac, sta->addr, ETH_ALEN) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - MAC mismatch in PASN-1");
        return -1;
    }

    /* Save the STA's ML-KEM public key into the state machine */
    os_free(sm->kem_pub_key);
    sm->kem_pub_key = os_malloc(sta_kem_pub_len);
    if (!sm->kem_pub_key) return -1;
    os_memcpy(sm->kem_pub_key, sta_kem_pub, sta_kem_pub_len);
    sm->kem_pub_key_len = sta_kem_pub_len;

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Parsed ML-KEM public key (len: %u)", sta_kem_pub_len);

    /* --- 2. ML-KEM Encapsulation --- */
    kem = OQS_KEM_new(get_oqs_kem_alg(sm->pqc_choice));
    if (!kem) goto cleanup;

    sm->pasn_ciphertext_len = kem->length_ciphertext;
    sm->pasn_ciphertext = os_malloc(sm->pasn_ciphertext_len);
    sm->pasn_shared_secret_len = kem->length_shared_secret;
    sm->pasn_shared_secret = os_malloc(sm->pasn_shared_secret_len);

    if (!sm->pasn_ciphertext || !sm->pasn_shared_secret) goto cleanup;

    /* Encapsulate using the key we just parsed from the STA */
    if (OQS_KEM_encaps(kem, sm->pasn_ciphertext, sm->pasn_shared_secret, sm->kem_pub_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - ML-KEM Encapsulation failed");
        goto cleanup;
    }

    /* --- 3. ML-DSA Signature Generation --- */
    sig = OQS_SIG_new(get_oqs_dsa_alg(sm->pqc_choice));
    if (!sig) goto cleanup;

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

    /* --- 4. PTK Derivation (PBKDF2-SHA256) --- */
    /* Get the PMK (from earlier PAKE phase) */
    if (pqc_ap_sm_derive_pmk(sm, pmk) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PMK derivation failed");
        goto cleanup;
    }

    /* PBKDF2-SHA256: Password is PMK, Salt is the concatenated buffer */
    if (pqc_derive_pasn_ptk(pmk, sta->addr, hapd->own_addr,
                            sm->pasn_shared_secret, sm->pasn_shared_secret_len,
                            sm->pasn_ptk) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - PBKDF2-SHA256 failed");
        goto cleanup;
    }

    /* Split PTK into KEK and KCK */
    os_memcpy(sm->pasn_kek, sm->pasn_ptk, 16);
    os_memcpy(sm->pasn_kck, sm->pasn_ptk + 16, 16);
    os_memcpy(sm->pasn_tk, sm->pasn_ptk + 32, 16);

    /* --- 5. MIC1 Generation --- */
    size_t mic_input_len = sm->pasn_ciphertext_len + sm->pasn_dsa_signature_len;
    u8 *mic_input = os_malloc(mic_input_len);
    if (!mic_input) goto cleanup;

    os_memcpy(mic_input, sm->pasn_ciphertext, sm->pasn_ciphertext_len);
    os_memcpy(mic_input + sm->pasn_ciphertext_len, sm->pasn_dsa_signature, sm->pasn_dsa_signature_len);

    hmac_sha256(sm->pasn_kck, 16, mic_input, mic_input_len, sm->pasn_mic1);
    os_free(mic_input);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - PASN-2 prepared (PTK derived via PBKDF2)");

    /* --- 6. Send Response --- */
    ret = hostapd_pqc_send_pasn2(hapd, sta,
                                 sm->pasn_ciphertext, sm->pasn_ciphertext_len,
                                 sm->pasn_mic1);
    if (ret == 0)
        ret = hostapd_pqc_send_pasn2_sig(hapd, sta,
                                         sm->pasn_dsa_signature, sm->pasn_dsa_signature_len);

cleanup:
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return ret;
}
/* PASN-2: ciphertext + MIC1 only (AP ML-DSA key is already known to STA from PAKE-2;
 * signature is sent separately in PASN-2-SIG frames to stay under frame size limits). */
static int hostapd_pqc_send_pasn2(struct hostapd_data *hapd, struct sta_info *sta,
                                   const u8 *ciphertext, size_t ciphertext_len,
                                   const u8 *mic1) {
    struct wpabuf *buf;
    int ret;

    if (!hapd || !sta || !ciphertext || !mic1)
        return -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Constructing PASN-2 frame");

    /* header(7) + ct_len(2) + ct + mic1(32) */
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + 2 + ciphertext_len + MIC_LEN;
    buf = wpabuf_alloc(frame_len);
    if (!buf)
        return -1;

    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PASN);
    wpabuf_put_u8(buf, PQC_PASN_TYPE_2);

    wpabuf_put_be16(buf, ciphertext_len);
    wpabuf_put_data(buf, ciphertext, ciphertext_len);
    wpabuf_put_data(buf, mic1, MIC_LEN);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - Sending PASN-2 frame to " MACSTR
               " (ciphertext len: %zu)", MAC2STR(sta->addr), ciphertext_len);

    ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
                                  wpabuf_head(buf), wpabuf_len(buf));
    if (ret == 0)
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - PASN-2 frame sent successfully");
    else
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-2 frame");

    wpabuf_free(buf);
    return ret;
}

/* PASN-2-SIG: send ML-DSA signature in 1400-byte fragments.
 * Frame payload: frag_idx(1) + total_sig_len(2) + data_len(2) + data */
static int hostapd_pqc_send_pasn2_sig(struct hostapd_data *hapd, struct sta_info *sta,
                                       const u8 *signature, size_t sig_len) {
    const size_t chunk = 1400;
    size_t offset = 0;
    u8 frag_idx = 0;
    int ret = 0;

    while (offset < sig_len) {
        size_t data_len = sig_len - offset;
        if (data_len > chunk)
            data_len = chunk;

        /* header(7) + frag_idx(1) + total_sig_len(2) + data_len(2) + data */
        size_t frame_len = 1 + 1 + 3 + 1 + 1 + 1 + 2 + 2 + data_len;
        struct wpabuf *buf = wpabuf_alloc(frame_len);
        if (!buf)
            return -1;

        wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
        wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
        wpabuf_put_u8(buf, PQC_OUI_0);
        wpabuf_put_u8(buf, PQC_OUI_1);
        wpabuf_put_u8(buf, PQC_OUI_2);
        wpabuf_put_u8(buf, PQC_OUI_TYPE_PASN);
        wpabuf_put_u8(buf, PQC_PASN_TYPE_2_SIG);

        wpabuf_put_u8(buf, frag_idx);
        wpabuf_put_be16(buf, (u16)sig_len);
        wpabuf_put_be16(buf, (u16)data_len);
        wpabuf_put_data(buf, signature + offset, data_len);

        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Sending PASN-2-SIG frag %u (offset=%zu, len=%zu)",
                   frag_idx, offset, data_len);

        ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
                                      wpabuf_head(buf), wpabuf_len(buf));
        wpabuf_free(buf);

        if (ret != 0) {
            wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-2-SIG frag %u", frag_idx);
            return ret;
        }

        offset += data_len;
        frag_idx++;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: AP - PASN-2-SIG sent (%u fragments, %zu bytes total)",
               frag_idx, sig_len);
    return 0;
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
    /* MIC2 = HMAC-SHA256(KCK, PTK) zgodnie z generowaniem na STA */
    hmac_sha256(sm->pasn_kck, KCK_LEN, sm->pasn_ptk, PTK_LEN, mic2_calculated);

    if (os_memcmp_const(mic2_calculated, payload, MIC_LEN) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - MIC2 verification failed. Dropping connection.");
        return -1;
    }
    wpa_printf(MSG_INFO, "PQC_LOG: AP - MIC2 verified successfully.");

    /* GTK and IGTK generation */
    u8 group_keys[32]; 
    u8 *gtk = group_keys;
    u8 *igtk = group_keys + 16;
    
    /* we hope taht hapd->wpa_auth is initialized by hostapd */
    if (hapd->wpa_auth && hapd->wpa_auth->group) {
        /* copy current GTK */
        os_memcpy(gtk, hapd->wpa_auth->group->GTK[hapd->wpa_auth->group->GN - 1], 16);
        /* copy current IGTK */
        os_memcpy(igtk, hapd->wpa_auth->group->IGTK[hapd->wpa_auth->group->GN_igtk - 4], 16);
        wpa_printf(MSG_DEBUG, "PQC_LOG: AP - Fetched real GTK and IGTK from authenticator");
    } else {
        wpa_printf(MSG_WARNING, "PQC_LOG: AP - wpa_auth group not ready, using random keys (fallback)");
        os_get_random(gtk, 16);
        os_get_random(igtk, 16);
    }

    /* Encrypting GTK and IGTK with AES-WRAP*/
    u8 enc_group_keys[40]; 
    if (aes_wrap(sm->pasn_kek, KEK_LEN, 4, group_keys, enc_group_keys) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to encrypt group keys");
        return -1;
    }

    /* MIC3 generation */
    u8 mic3[MIC_LEN];
    hmac_sha256(sm->pasn_kck, KCK_LEN, enc_group_keys, sizeof(enc_group_keys), mic3);

    /* send PASN-4 */
    if (hostapd_pqc_send_pasn4(hapd, sta, enc_group_keys, sizeof(enc_group_keys), mic3) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: AP - Failed to send PASN-4");
        return -1;
    }

    /* Instalation of TK (temporal key) in NIC driver*/
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
static int hostapd_pqc_send_pasn4(struct hostapd_data *hapd, struct sta_info *sta,
                                  const u8 *enc_keys, size_t enc_keys_len, const u8 *mic3) {
    struct wpabuf *buf;
    int ret;

    /* Length: Category(1) + Action(1) + OUI(3) + Type(1) + Subtype(1) + Keys(40) + MIC3(32) */
    size_t frame_len = 1 + 1 + 3 + 1 + 1 + enc_keys_len + MIC_LEN;
    buf = wpabuf_alloc(frame_len);
    if (!buf) return -1;

    wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
    wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PASN);
    wpabuf_put_u8(buf, PQC_PASN_TYPE_4); 

    wpabuf_put_data(buf, enc_keys, enc_keys_len);
    wpabuf_put_data(buf, mic3, MIC_LEN);

    wpa_printf(MSG_INFO, "PQC_LOG: AP - Sending PASN-4 frame to " MACSTR, MAC2STR(sta->addr));

    ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
                                  wpabuf_head(buf), wpabuf_len(buf));
    wpabuf_free(buf);
    return ret;
}

