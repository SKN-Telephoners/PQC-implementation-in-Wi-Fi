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
#include "rsn_supp/wpa.h"
#include "sme.h"
#include "../src/common/pqc_help.h"
#include "pqc_pake.h"
#include "pqc_pasn.h"


/* STATE LIFECYCLE */
struct wpa_pqc_sm * pqc_sm_init(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid) {
    struct wpa_pqc_sm *sm;

    if(!ssid || !ssid->pqc_enabled) return NULL;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Initializing State Machine (choice mask: 0x%02x)", ssid->pqc_choice);
    
    sm = os_zalloc(sizeof(*sm));
    if (!sm) return NULL;

    sm->wpa_s = wpa_s;
    sm->pqc_choice = ssid->pqc_choice;
    sm->pqc_enabled = ssid->pqc_enabled;

    // AP's pub KEM key (probe response)
    sm->ap_kem_pub_len = get_oqs_kem_pub_len(sm->pqc_choice); 
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
    if (sm->T) os_free(sm->T);
    
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

    /* ML-DSA cleanup */
    if (sm->sta_mldsa_public_key) {
        os_free(sm->sta_mldsa_public_key);
    }
    if (sm->sta_mldsa_secret_key) {
        OQS_MEM_secure_free(sm->sta_mldsa_secret_key, sm->sta_mldsa_secret_len);
    }

    /* PASN cleanup */
    if (sm->pasn_ciphertext)
        os_free(sm->pasn_ciphertext);
    if (sm->pasn_sig_buf)
        os_free(sm->pasn_sig_buf);
    if (sm->pasn_dsa_signature) {
        os_free(sm->pasn_dsa_signature);
    }
    if (sm->pasn_shared_secret) {
        OQS_MEM_secure_free(sm->pasn_shared_secret, sm->pasn_shared_secret_len);
    }

    forced_memzero(sm->pasn_ptk, sizeof(sm->pasn_ptk));
    forced_memzero(sm->pasn_kek, sizeof(sm->pasn_kek));
    forced_memzero(sm->pasn_kck, sizeof(sm->pasn_kck));
    forced_memzero(sm->pasn_tk, sizeof(sm->pasn_tk));
    forced_memzero(sm->pasn_mic1, sizeof(sm->pasn_mic1));

    forced_memzero(sm->pwd, sizeof(sm->pwd));
    forced_memzero(sm->K_aes, sizeof(sm->K_aes));
    forced_memzero(sm->pmk, sizeof(sm->pmk));

    os_free(sm);

    OQS_destroy();
}

/* after receiving authentication response  */
int pqc_sm_rx_auth_req(struct wpa_pqc_sm *sm) {
    OQS_KEM *kem = NULL;
    u8 *ciphertext = NULL;
    u8 enc_id[PQC_SID_LEN]; // 16B
    int ret = -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: State Machine processing Auth Response, preparing PAKE-1 data");

    if (!sm || !sm->ap_kem_public_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Missing AP KEM public key");
        return -1;
    }

    const char *alg_name = get_oqs_kem_alg(sm->pqc_choice);
    kem = OQS_KEM_new(alg_name);
    if (!kem) return -1;

    ciphertext = os_malloc(kem->length_ciphertext);
    if (!ciphertext) goto cleanup;

    /* KEM Encapsulation -> (c, Kses) */
    if (OQS_KEM_encaps(kem, ciphertext, sm->K_aes, sm->ap_kem_public_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: KEM encaps failed");
        goto cleanup;
    }

    wpa_printf(MSG_DEBUG, "PQC_LOG: KEM Encapsulation successful, K_aes derived");
    wpa_hexdump(MSG_DEBUG, "PQC_DBG STA: K_aes[0:8]", sm->K_aes, 8);

    /* Generating random STA id */
    if (os_get_random(sm->id, PQC_SID_LEN) < 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Failed to generate random STA id");
        goto cleanup;
    }

    /* Encryption of id */
    void *aes_ctx = aes_encrypt_init(sm->K_aes, AES_KEY_LEN);
    if (!aes_ctx) goto cleanup;
    aes_encrypt(aes_ctx, sm->id, enc_id);
    aes_encrypt_deinit(aes_ctx);

    /* sending function call */
    ret = wpas_pqc_send_pake1(sm, ciphertext, kem->length_ciphertext, enc_id, sizeof(enc_id));

cleanup:
    if (ciphertext) os_free(ciphertext);
    if (kem) OQS_KEM_free(kem);
    return ret;
}


int pqc_sm_assoc_success(struct wpa_pqc_sm *sm) {
    OQS_KEM *kem = NULL;

    if (!sm || !sm->pqc_enabled) return -1;

    wpa_printf(MSG_DEBUG, "PQC_LOG: Received Association Response. Generating the second pair of KEM keys");

    const char *alg_name = get_oqs_kem_alg(sm->pqc_choice);
    if (!alg_name) return -1;

    kem = OQS_KEM_new(alg_name);
    if (!kem) return -1;

    /* Memory allocation */
    sm->sta_second_pub_len = kem->length_public_key;
    sm->sta_second_pub_key = os_malloc(sm->sta_second_pub_len);

    sm->sta_second_secret_len = kem->length_secret_key;
    sm->sta_second_secret_key = os_malloc(sm->sta_second_secret_len);

    if (!sm->sta_second_pub_key || !sm->sta_second_secret_key) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in memory allocation for the second pair of KEM keys");
        goto cleanup;
    }

    /* Keys generating  */
    if (OQS_KEM_keypair(kem, sm->sta_second_pub_key, sm->sta_second_secret_key) != OQS_SUCCESS) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Error in liboqs library");
        goto cleanup;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: Generation of the second key pair ended successfully");

    OQS_KEM_free(kem);

    /* PASN Phase: Generate ML-DSA keys and send PASN-1 */
    wpa_printf(MSG_DEBUG, "PQC_LOG: Transitioning to PASN phase. Generating ML-DSA keys...");

    if (pqc_pasn_generate_mldsa_keys(sm) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Failed to generate ML-DSA keys for PASN");
        return -1;
    }

    /* Send PASN-1 frame with ML-DSA public key */
    wpa_printf(MSG_DEBUG, "PQC_LOG: Sending PASN-1 frame with ML-DSA public key");

    if (wpas_pqc_send_pasn1(sm) != 0) {
        wpa_printf(MSG_ERROR, "PQC_LOG: Failed to send PASN-1 frame");
        return -1;
    }

    wpa_printf(MSG_INFO, "PQC_LOG: PASN-1 frame sent successfully. Waiting for PASN-2...");

    return 0;

cleanup:
    if (sm->sta_second_pub_key) { 
        os_free(sm->sta_second_pub_key); 
        sm->sta_second_pub_key = NULL;
    }
    if (sm->sta_second_secret_key) { 
        OQS_MEM_secure_free(sm->sta_second_secret_key, sm->sta_second_secret_len); 
        sm->sta_second_secret_key = NULL; 
    }
    if (kem) OQS_KEM_free(kem);
    return -1;
}