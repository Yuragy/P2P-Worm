#ifndef KERB_READER_H
#define KERB_READER_H

#include <krb5.h>
#include <stddef.h>

typedef krb5_error_code (*kerb_cred_cb_t)(krb5_context,
                                          krb5_creds *,
                                          void *buf,
                                          size_t buf_cap,
                                          size_t *written);

krb5_error_code kerb_open_ccache(krb5_context ctx,
                                 const char *path,
                                 krb5_ccache *out_cc);

krb5_error_code kerb_read_all_creds(krb5_context ctx,
                                    krb5_ccache cc,
                                    kerb_cred_cb_t cb,
                                    void *buf,
                                    size_t buf_cap,
                                    size_t *out_len);

#endif // KERB_READER_H
