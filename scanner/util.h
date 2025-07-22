#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

char *str_trim(char *s);
char **str_split(const char *s, char delim, size_t *out_count);
void free_strv(char **v, size_t count);

// Return -1/0/1 like strcmp
int ver_cmp(const char *a, const char *b);

int ver_in_range(const char *ver, const char *start_inc, const char *end_exc);
char *read_file(const char *path, size_t *out_size);

#endif // UTIL_H
