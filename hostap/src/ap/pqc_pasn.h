#ifndef PQC_AP_PASN_H
#define PQC_AP_PASN_H

#include "../utils/common.h"
#include "../src/common/pqc_help.h"
#include "hostapd.h"
#include "sta_info.h"

/**
 * pqc_ap_sm_rx_pasn1 - Process received PASN-1 frame from STA
 *
 * PASN-1 contains STA's ML-DSA public key. After receiving and parsing it,
 * AP generates ML-DSA signature and sends PASN-2 response.
 *
 * @sm: AP PQC state machine
 * @sta: STA info structure
 * @hapd: Hostapd data
 * @payload: PASN-1 payload
 * @len: Payload length
 * Returns: 0 on success, -1 on failure
 */
int pqc_ap_sm_rx_pasn1(struct hostapd_pqc_sm *sm, struct sta_info *sta, struct hostapd_data *hapd,
                       const u8 *payload, size_t len);

/**
 * hostapd_pqc_send_pasn2 - Build and send PASN-2 frame with ML-KEM ciphertext, ML-DSA signature, and MIC1
 *
 * PASN-2 frame contains:
 * - AP's ML-DSA public key (for STA to verify signature)
 * - ML-KEM ciphertext (for STA decapsulation)
 * - ML-DSA signature over ciphertext
 * - MIC1 (HMAC-SHA256 for integrity verification)
 *
 * @hapd: Hostapd data
 * @sta: STA info structure
 * @ap_mldsa_pub: AP's ML-DSA public key
 * @ap_mldsa_pub_len: Public key length
 * @ciphertext: ML-KEM ciphertext
 * @ciphertext_len: Ciphertext length
 * @signature: ML-DSA signature over ciphertext
 * @sig_len: Signature length
 * @mic1: MIC1 for integrity check
 * Returns: 0 on success, -1 on failure
 */
int hostapd_pqc_send_pasn2(struct hostapd_data *hapd, struct sta_info *sta,
                            const u8 *ap_mldsa_pub, size_t ap_mldsa_pub_len,
                            const u8 *ciphertext, size_t ciphertext_len,
                            const u8 *signature, size_t sig_len,
                            const u8 *mic1);

#endif // PQC_AP_PASN_H

