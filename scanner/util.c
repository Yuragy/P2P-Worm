#define _GNU_SOURCE

#include "util.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *str_trim(char *s) {
    if (!s) return NULL;
    char *end;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

char **str_split(const char *s, char delim, size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!s) return NULL;

    size_t cap = 4, n = 0;
    char **res = malloc(cap * sizeof(char*));
    const char *start = s, *p = s;

    while (1) {
        if (*p == delim || *p == '\0') {
            size_t len = p - start;
            char *part = malloc(len + 1);
            memcpy(part, start, len);
            part[len] = '\0';
            if (n == cap) {
                cap *= 2;
                res = realloc(res, cap * sizeof(char*));
            }
            res[n++] = part;
            if (*p == '\0') break;
            start = p + 1;
        }
        p++;
    }
    if (out_count) *out_count = n;
    return res;
}

void free_strv(char **v, size_t count) {
    if (!v) return;
    for (size_t i = 0; i < count; i++) free(v[i]);
    free(v);
}

static int cmp_token(const char *a, const char *b) {
    // Compare numeric if both are digits
    char *endA, *endB;
    long na = strtol(a, &endA, 10);
    long nb = strtol(b, &endB, 10);
    if (endA != a && endB != b) {
        if (na < nb) return -1;
        if (na > nb) return 1;
        return 0;
    }
    return strcmp(a, b);
}

int ver_cmp(const char *a, const char *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;

    size_t ca, cb;
    char **va = str_split(a, '.', &ca);
    char **vb = str_split(b, '.', &cb);
    size_t max = (ca > cb) ? ca : cb;

    for (size_t i = 0; i < max; i++) {
        const char *ta = (i < ca) ? va[i] : "0";
        const char *tb = (i < cb) ? vb[i] : "0";
        int r = cmp_token(ta, tb);
        if (r != 0) {
            free_strv(va, ca);
            free_strv(vb, cb);
            return r;
        }
    }
    free_strv(va, ca);
    free_strv(vb, cb);
    return 0;
}

int ver_in_range(const char *ver, const char *start_inc, const char *end_exc) {
    if (!ver) return 0;
    if (start_inc && ver_cmp(ver, start_inc) < 0) return 0;
    if (end_exc   && ver_cmp(ver, end_exc)   >= 0) return 0;
    return 1;
}

char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    if (out_size) *out_size = (size_t)sz;
    return buf;
}
