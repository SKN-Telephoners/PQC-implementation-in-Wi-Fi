#ifndef PQC_STA_PAKE_H
#define PQC_STA_PAKE_H

#include "../utils/common.h"

int pqc_sm_rx_pake2(struct wpa_pqc_sm *sm, const u8 *enc_sid, size_t enc_sid_len); 
int pqc_sm_rx_pake4(struct wpa_pqc_sm *sm, const u8 *payload, size_t payload_len);
int wpas_pqc_send_pake3(struct wpa_pqc_sm *sm, const u8 *s, size_t s_len, const u8 *T, size_t T_len);
int wpas_pqc_send_pake1(struct wpa_pqc_sm *sm, const u8 *c, size_t c_len, const u8 *enc_id, size_t enc_id_len);

#endif // PQC_STA_PAKE_H
