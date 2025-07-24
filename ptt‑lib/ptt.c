#include "ptt.h"
#include "kerb_reader.h"
#include "exporter.h"
#include <krb5.h>

static krb5_context g_ctx = NULL;
static krb5_ccache  g_ccache = NULL;

int ptt_init(void) {
    return krb5_init_context(&g_ctx) ? 1 : 0;
}

int ptt_export(const char *ccache_path,
               unsigned char *out_buf,
               size_t out_capacity,
               size_t *out_len)
{
    krb5_error_code ret;

    ret = kerb_open_ccache(g_ctx, ccache_path, &g_ccache);
    if (ret) return (int)ret;

    ret = kerb_read_all_creds(
        g_ctx,
        g_ccache,
        exporter_serialize,
        out_buf,
        out_capacity,
        out_len
    );

    krb5_cc_close(g_ctx, g_ccache);
    return (int)ret;
}

void ptt_cleanup(void) {
    if (g_ctx) krb5_free_context(g_ctx);
}
