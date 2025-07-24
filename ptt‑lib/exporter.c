#include "exporter.h"
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

krb5_error_code exporter_serialize(krb5_context ctx,
                                   krb5_creds *creds,
                                   void *buf,
                                   size_t buf_cap,
                                   size_t *written)
{
    size_t tlen = creds->ticket.length;
    const unsigned char *tdata = (const unsigned char*)creds->ticket.data;
    if (!tdata || tlen == 0) {
        return 0;
    }

    size_t offset = *written;
    if (offset > buf_cap) {
        return KRB5_CC_NOMEM;
    }

    size_t remain = buf_cap - offset;
    if (remain < sizeof(uint32_t) + tlen) {
        return KRB5_CC_NOMEM;
    }

    unsigned char *p = (unsigned char*)buf + offset;
    uint32_t be_len = htonl((uint32_t)tlen);
    memcpy(p, &be_len, sizeof(be_len));
    memcpy(p + sizeof(be_len), tdata, tlen);

    *written = offset + sizeof(be_len) + tlen;
    return 0;
}
