#ifndef PQC_AP_PAKE_H
#define PQC_AP_PAKE_H

#include "../utils/common.h"
#include "../src/common/pqc_help.h"

int pqc_ap_sm_rx_pake1(struct hostapd_pqc_sm *sm, struct hostapd_data *hapd, struct sta_info *sta, const u8 *payload, size_t len);
int pqc_ap_sm_rx_pake3(struct hostapd_pqc_sm *sm, const u8 *s, size_t s_len, const u8 *T, size_t T_len);

#endif //PQC_AP_PAKE_H