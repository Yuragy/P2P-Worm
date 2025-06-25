#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "vm.h"  

static const unsigned char key[] = "1234qwerty";
static const size_t keylen = sizeof(key) - 1;
static const unsigned char marker[] = { 0xDE,0xAD,0xBE,0xEF };
static const size_t marker_len = sizeof(marker);

static off_t find_marker(const unsigned char *buf, size_t buf_len) {
    for (size_t i = 0; i + marker_len <= buf_len; i++) {
        if (memcmp(buf + i, marker, marker_len) == 0)
            return (off_t)i;
    }
    return -1;
}

static unsigned char *read_file(const char *path, size_t *sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); exit(1); }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); exit(1); }
    unsigned char *buf = malloc(st.st_size);
    if (!buf) { perror("malloc"); exit(1); }
    if (read(fd, buf, st.st_size) != st.st_size) { perror("read"); exit(1); }
    close(fd);
    *sz = st.st_size;
    return buf;
}

static void xor_crypt(const unsigned char *in, unsigned char *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = in[i] ^ key[i % keylen];
    }
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "pack") == 0) {
        char me[PATH_MAX];
        ssize_t r = readlink("/proc/self/exe", me, sizeof(me)-1);
        if (r <= 0) { perror("readlink"); return 1; }
        me[r] = 0;
        size_t me_sz;
        unsigned char *me_buf = read_file(me, &me_sz);
        off_t off = find_marker(me_buf, me_sz);
        if (off < 0) { fprintf(stderr, "Marker not found\n"); return 1; }
        size_t stub_sz = off + marker_len;
        size_t pl_sz;
        unsigned char *pl = read_file(argv[2], &pl_sz);
        unsigned char *enc = malloc(pl_sz);
        xor_crypt(pl, enc, pl_sz);

        int outfd = open(argv[3],
                         O_CREAT|O_TRUNC|O_WRONLY, 0755);
        if (outfd < 0) { perror("open out"); return 1; }
        if (write(outfd, me_buf, stub_sz) != (ssize_t)stub_sz) { perror("write"); return 1; }
        if (write(outfd, enc, pl_sz)  != (ssize_t)pl_sz)  { perror("write"); return 1; }
        close(outfd);

        printf("Packed '%s' → '%s' (payload %zu bytes)\n",
               argv[2], argv[3], pl_sz);
        return 0;
    }

    char me[PATH_MAX];
    ssize_t rl = readlink("/proc/self/exe", me, sizeof(me)-1);
    if (rl <= 0) { perror("readlink"); return 1; }
    me[rl] = 0;
    size_t me_sz;
    unsigned char *me_buf = read_file(me, &me_sz);
    off_t off2 = find_marker(me_buf, me_sz);
    if (off2 < 0) { fprintf(stderr, "No payload marker\n"); return 1; }
    size_t enc_sz = me_sz - (off2 + marker_len);
    unsigned char *enc_payload = me_buf + (off2 + marker_len);
    unsigned char *dec = malloc(enc_sz);
    if (!dec) { perror("malloc dec"); return 1; }
    xor_crypt(enc_payload, dec, enc_sz);
    run_vm(dec, enc_sz);
    free(dec);
    free(me_buf);

    return 0;
}

static const unsigned char __attribute__((section(".marker"))) _mk[sizeof(marker)] = {
    0xDE,0xAD,0xBE,0xEF
};
