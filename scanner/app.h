#ifndef APP_H
#define APP_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    const char *cve_db_path;   // nvd.sqlite3
    const char *exploit_csv;   // exploits.csv
    bool        check_kernel;  // scan kernel
    char      **packages;      // package names
    size_t      pkg_count;     // packages count
} config_t;

int run_app(const config_t *cfg);

#endif // APP_H
