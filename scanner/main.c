#define _GNU_SOURCE

#include "app.h"
#include "util.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --db PATH --exploits PATH [--kernel] [--packages p1,p2,...]\n"
        "Options:\n"
        "  -d, --db PATH         Path to CVE SQLite DB (nvd.sqlite3)\n"
        "  -e, --exploits PATH   Path to exploits CSV\n"
        "  -k, --kernel          Scan kernel version\n"
        "  -p, --packages LIST   Comma-separated package names\n"
        "  -h, --help            This help\n",
        prog);
}

int main(int argc, char **argv) {
    config_t cfg = {
        .cve_db_path  = NULL,
        .exploit_csv  = NULL,
        .check_kernel = false,
        .packages     = NULL,
        .pkg_count    = 0
    };

    static struct option long_opts[] = {
        {"db",       required_argument, 0, 'd'},
        {"exploits", required_argument, 0, 'e'},
        {"kernel",   no_argument,       0, 'k'},
        {"packages", required_argument, 0, 'p'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };

    int opt, idx;
    while ((opt = getopt_long(argc, argv, "d:e:kp:h", long_opts, &idx)) != -1) {
        switch (opt) {
        case 'd': cfg.cve_db_path = optarg; break;
        case 'e': cfg.exploit_csv = optarg; break;
        case 'k': cfg.check_kernel = true;  break;
        case 'p': {
            cfg.packages = str_split(optarg, ',', &cfg.pkg_count);
            break;
        }
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!cfg.cve_db_path || !cfg.exploit_csv) {
        usage(argv[0]);
        free_strv(cfg.packages, cfg.pkg_count);
        return 1;
    }

    int rc = run_app(&cfg);

    free_strv(cfg.packages, cfg.pkg_count);
    return rc;
}
