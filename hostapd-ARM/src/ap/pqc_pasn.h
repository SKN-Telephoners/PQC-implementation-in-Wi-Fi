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
int pqc_ap_sm_rx_pasn3(struct hostapd_pqc_sm *sm, struct sta_info *sta, struct hostapd_data *hapd,
                       const u8 *payload, size_t len);

#endif // PQC_AP_PASN_H

