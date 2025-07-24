#ifndef EXPORTER_H
#define EXPORTER_H

#include <krb5.h>
#include <stddef.h>

krb5_error_code exporter_serialize(krb5_context ctx,
                                   krb5_creds *creds,
                                   void *buf,
                                   size_t buf_cap,
                                   size_t *written);

#endif // EXPORTER_H
