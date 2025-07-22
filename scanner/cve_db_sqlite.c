#define _GNU_SOURCE

#include "cve_db.h"
#include "util.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static sqlite3 *g_db = NULL;
static sqlite3_stmt *stmt_kernel  = NULL;
static sqlite3_stmt *stmt_package = NULL;

static void finalize_stmts(void) {
    if (stmt_kernel)  { sqlite3_finalize(stmt_kernel);  stmt_kernel  = NULL; }
    if (stmt_package) { sqlite3_finalize(stmt_package); stmt_package = NULL; }
}

int cve_db_open(const char *path) {
    if (!path) return -1;

    if (sqlite3_open_v2(path, &g_db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "sqlite open: %s\n", sqlite3_errmsg(g_db));
        if (g_db) { sqlite3_close(g_db); g_db = NULL; }
        return -1;
    }
    sqlite3_extended_result_codes(g_db, 1);
    sqlite3_exec(g_db, "PRAGMA case_sensitive_like = ON;", NULL, NULL, NULL);
    const char *sql_kernel =
        "SELECT id, summary, version_start_inc, version_end_exc "
        "FROM cves WHERE product = 'linux_kernel'";
    if (sqlite3_prepare_v2(g_db, sql_kernel, -1, &stmt_kernel, NULL) != SQLITE_OK) {
        fprintf(stderr, "sqlite prepare kernel: %s\n", sqlite3_errmsg(g_db));
        cve_db_close();
        return -1;
    }

    const char *sql_pkg =
        "SELECT id, summary, version_start_inc, version_end_exc "
        "FROM cves WHERE product = ?";
    if (sqlite3_prepare_v2(g_db, sql_pkg, -1, &stmt_package, NULL) != SQLITE_OK) {
        fprintf(stderr, "sqlite prepare package: %s\n", sqlite3_errmsg(g_db));
        cve_db_close();
        return -1;
    }

    return 0;
}

int cve_db_ready(void) {
    return g_db != NULL;
}

void cve_db_close(void) {
    finalize_stmts();
    if (g_db) sqlite3_close(g_db);
    g_db = NULL;
}

static void list_push(cve_list_t *list, const char *id, const char *summary) {
    cve_item_t *tmp = realloc(list->items, (list->count + 1) * sizeof(*tmp));
    if (!tmp) return; /* OOM: skip */
    list->items = tmp;
    list->items[list->count].id      = strdup(id      ? id      : "");
    list->items[list->count].summary = strdup(summary ? summary : "");
    list->count++;
}

static cve_list_t run_stmt_and_filter(sqlite3_stmt *st, const char *ver) {
    cve_list_t out = {0};
    if (!st || !ver) return out;

    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *id   = (const char*)sqlite3_column_text(st, 0);
        const char *sum  = (const char*)sqlite3_column_text(st, 1);
        const char *vmin = (const char*)sqlite3_column_text(st, 2);
        const char *vmax = (const char*)sqlite3_column_text(st, 3);

        if (ver_in_range(ver, vmin, vmax))
            list_push(&out, id, sum);
    }
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "sqlite step error: %s\n", sqlite3_errmsg(g_db));
    }
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    return out;
}

cve_list_t cve_db_find_kernel(const char *kernel_ver) {
    return run_stmt_and_filter(stmt_kernel, kernel_ver);
}

cve_list_t cve_db_find_pkg(const char *pkg_name, const char *pkg_ver) {
    cve_list_t out = {0};
    if (!pkg_name || !pkg_ver) return out;

    if (sqlite3_bind_text(stmt_package, 1, pkg_name, -1, SQLITE_STATIC) != SQLITE_OK) {
        fprintf(stderr, "sqlite bind: %s\n", sqlite3_errmsg(g_db));
        sqlite3_reset(stmt_package);
        sqlite3_clear_bindings(stmt_package);
        return out;
    }
    return run_stmt_and_filter(stmt_package, pkg_ver);
}

void cve_list_free(cve_list_t *list) {
    if (!list || !list->items) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].id);
        free(list->items[i].summary);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}
