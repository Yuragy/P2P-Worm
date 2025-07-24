#include "kerb_reader.h"

krb5_error_code kerb_open_ccache(krb5_context ctx,
                                 const char *path,
                                 krb5_ccache *out_cc)
{
    if (path && *path)
        return krb5_cc_resolve(ctx, path, out_cc);
    return krb5_cc_default(ctx, out_cc);
}

krb5_error_code kerb_read_all_creds(krb5_context ctx,
                                    krb5_ccache cc,
                                    kerb_cred_cb_t cb,
                                    void *buf,
                                    size_t buf_cap,
                                    size_t *out_len)
{
    krb5_cc_cursor cursor;
    krb5_creds creds;
    size_t total = 0;
    krb5_error_code ret = krb5_cc_start_seq_get(ctx, cc, &cursor);
    if (ret) return ret;

    while ((ret = krb5_cc_next_cred(ctx, cc, &cursor, &creds)) == 0) {
        ret = cb(ctx, &creds, buf, buf_cap, &total);
        krb5_free_cred_contents(ctx, &creds);
        if (ret) break;
    }

    krb5_cc_end_seq_get(ctx, cc, &cursor);

    if (out_len) *out_len = total;
    return (ret == KRB5_CC_END ? 0 : ret);
}
