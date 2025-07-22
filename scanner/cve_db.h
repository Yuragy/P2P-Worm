#ifndef CVE_DB_H
#define CVE_DB_H

#include <stddef.h>

typedef struct {
    char *id;
    char *summary;
} cve_item_t;

typedef struct {
    cve_item_t *items;
    size_t      count;
} cve_list_t;

int  cve_db_open(const char *path);
void cve_db_close(void);
int  cve_db_ready(void);

cve_list_t cve_db_find_kernel(const char *kernel_ver);
cve_list_t cve_db_find_pkg(const char *pkg_name, const char *pkg_ver);

void cve_list_free(cve_list_t *list);

#endif // CVE_DB_H
