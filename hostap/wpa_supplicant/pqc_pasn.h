#ifndef PQC_STA_PASN_H
#define PQC_STA_PASN_H

#include "../utils/common.h"

/**
 * wpas_pqc_send_pasn1 - Build and send PASN-1 frame with ML-DSA public key
 * @sm: PQC state machine
 * Returns: 0 on success, -1 on failure
 */
int wpas_pqc_send_pasn1(struct wpa_pqc_sm *sm);

/**
 * pqc_sm_rx_pasn2 - Process received PASN-2 frame from AP
 * @sm: PQC state machine
 * @payload: PASN-2 payload
 * @payload_len: Payload length
 * Returns: 0 on success, -1 on failure
 */
int pqc_sm_rx_pasn2(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len);
int pqc_sm_rx_pasn2_sig(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len);

/**
 * pqc_pasn_generate_mldsa_keys - Generate ML-DSA key pair for PASN
 * @sm: PQC state machine
 * Returns: 0 on success, -1 on failure
 */
int pqc_pasn_generate_mldsa_keys(struct wpa_pqc_sm *sm);

#endif // PQC_STA_PASN_H

