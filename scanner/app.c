#define _GNU_SOURCE

#include "app.h"
#include "sysinfo.h"
#include "cve_db.h"
#include "exploit_db.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_cves(const char *what, const char *ver, const cve_list_t *list) {
    printf("\n[%s] %s\n", what, ver && *ver ? ver : "(unknown)");
    if (!list || list->count == 0) {
        printf("  No CVEs found.\n");
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        printf("  %s - %s\n", list->items[i].id, list->items[i].summary);
    }
}

int run_app(const config_t *cfg) {
    if (!cfg || !cfg->cve_db_path || !cfg->exploit_csv) {
        fprintf(stderr, "Invalid config\n");
        return 1;
    }

    if (cve_db_open(cfg->cve_db_path) != 0) {
        fprintf(stderr, "Failed to open CVE DB: %s\n", cfg->cve_db_path);
        return 1;
    }

    exploit_db_t exdb;
    if (exploit_db_load(&exdb, cfg->exploit_csv) != 0) {
        fprintf(stderr, "Failed to load exploit CSV: %s\n", cfg->exploit_csv);
        cve_db_close();
        return 1;
    }

    /* Kernel */
    if (cfg->check_kernel) {
        char *kv = get_kernel_version();
        if (!kv) {
            fprintf(stderr, "Failed to get kernel version\n");
            kv = strdup("");
        }
        cve_list_t kl = cve_db_find_kernel(kv);
        print_cves("Kernel", kv, &kl);
        exploit_db_print_for_cves(&exdb, &kl);
        cve_list_free(&kl);
        free(kv);
    }

    /* Packages */
    if (cfg->pkg_count && cfg->packages) {
        for (size_t i = 0; i < cfg->pkg_count; i++) {
            const char *pkg = cfg->packages[i];
            if (!pkg || !*pkg) continue;

            char *ver = get_package_version(pkg);
            if (!ver) {
                printf("\n[Package] %s: NOT INSTALLED / UNKNOWN\n", pkg);
                continue;
            }

            cve_list_t pl = cve_db_find_pkg(pkg, ver);
            char header[256];
            snprintf(header, sizeof(header), "Package %s", pkg);
            print_cves(header, ver, &pl);
            exploit_db_print_for_cves(&exdb, &pl);
            cve_list_free(&pl);
            free(ver);
        }
    }

    exploit_db_free(&exdb);
    cve_db_close();
    fflush(stdout);
    return 0;
}
