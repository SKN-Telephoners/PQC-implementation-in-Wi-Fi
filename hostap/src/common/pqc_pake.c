/* src/common/pqc_pake.c */

#include "includes.h"
#include "common.h"
#include "pqc_pake.h"

size_t pqc_build_pake1(u8 *buf, size_t buf_len,
               const struct pqc_pake1_fields *f)
{
    u8 *pos = buf;
    u8 *end = buf + buf_len;

    if (!f || !f->c || !f->enc_id)
        return 0;

    if (end - pos < 1 + 2 + (int) f->c_len + 2 + (int) f->id_len)
        return 0;

    *pos++ = f->pake_type; /* PQC_PAKE_TYPE_1 */

    WPA_PUT_BE16(pos, f->c_len);
    pos += 2;
    os_memcpy(pos, f->c, f->c_len);
    pos += f->c_len;

    WPA_PUT_BE16(pos, f->id_len);
    pos += 2;
    os_memcpy(pos, f->enc_id, f->id_len);
    pos += f->id_len;

    return pos - buf;
}

int pqc_parse_pake1(const u8 *buf, size_t len,
            struct pqc_pake1_fields *out)
{
    const u8 *pos = buf;
    const u8 *end = buf + len;
    u16 c_len, id_len;

    if (!out || len < 1 + 2 + 2)
        return -1;

    os_memset(out, 0, sizeof(*out));

    out->pake_type = *pos++;
    if (out->pake_type != PQC_PAKE_TYPE_1)
        return -1;

    if (end - pos < 2)
        return -1;
    c_len = WPA_GET_BE16(pos);
    pos += 2;
    if (end - pos < c_len)
        return -1;
    out->c = pos;
    out->c_len = c_len;
    pos += c_len;

    if (end - pos < 2)
        return -1;
    id_len = WPA_GET_BE16(pos);
    pos += 2;
    if (end - pos < id_len)
        return -1;
    out->enc_id = pos;
    out->id_len = id_len;
    pos += id_len;

    if (pos != end)
        return -1;

    return 0;
}

size_t pqc_build_pake2(u8 *buf, size_t buf_len,
               const struct pqc_pake2_fields *f)
{
    u8 *pos = buf;
    u8 *end = buf + buf_len;

    if (!f || !f->enc_sid || !f->dp)
        return 0;

    if (end - pos < 1 + 2 + (int) f->sid_len + 2 + (int) f->dp_len)
        return 0;

    *pos++ = f->pake_type; /* PQC_PAKE_TYPE_2 */

    WPA_PUT_BE16(pos, f->sid_len);
    pos += 2;
    os_memcpy(pos, f->enc_sid, f->sid_len);
    pos += f->sid_len;

    WPA_PUT_BE16(pos, f->dp_len);
    pos += 2;
    os_memcpy(pos, f->dp, f->dp_len);
    pos += f->dp_len;

    return pos - buf;
}

int pqc_parse_pake2(const u8 *buf, size_t len,
            struct pqc_pake2_fields *out)
{
    const u8 *pos = buf;
    const u8 *end = buf + len;
    u16 sid_len, dp_len;

    if (!out || len < 1 + 2 + 2)
        return -1;

    os_memset(out, 0, sizeof(*out));

    out->pake_type = *pos++;
    if (out->pake_type != PQC_PAKE_TYPE_2)
        return -1;

    if (end - pos < 2)
        return -1;
    sid_len = WPA_GET_BE16(pos);
    pos += 2;
    if (end - pos < sid_len)
        return -1;
    out->enc_sid = pos;
    out->sid_len = sid_len;
    pos += sid_len;

    if (end - pos < 2)
        return -1;
    dp_len = WPA_GET_BE16(pos);
    pos += 2;
    if (end - pos < dp_len)
        return -1;
    out->dp = pos;
    out->dp_len = dp_len;
    pos += dp_len;

    if (pos != end)
        return -1;

    return 0;
}
