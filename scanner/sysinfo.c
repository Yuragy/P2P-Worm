#define _GNU_SOURCE

#include "sysinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *run_and_get_first_line(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    char *line = NULL;
    size_t cap = 0;
    ssize_t nread = getline(&line, &cap, fp);
    int rc = pclose(fp);

    if (nread <= 0 || rc == -1) {
        free(line);
        return NULL;
    }
    while (nread > 0 && (line[nread-1] == '\n' || line[nread-1] == '\r'))
        line[--nread] = '\0';
    return line;
}

static int command_exists(const char *cmd) {
    char buf[256];
    snprintf(buf, sizeof(buf), "command -v %s >/dev/null 2>&1", cmd);
    return system(buf) == 0;
}

char *get_kernel_version(void) {
    return run_and_get_first_line("uname -r");
}

char *get_package_version(const char *pkg_name) {
    if (!pkg_name || !*pkg_name) return NULL;

    char cmd[512];

    if (command_exists("dpkg-query")) {
        snprintf(cmd, sizeof(cmd),
                 "dpkg-query -W -f='${Version}' %s 2>/dev/null", pkg_name);
        char *ver = run_and_get_first_line(cmd);
        if (ver && *ver) return ver;
        free(ver);
    }

    if (command_exists("rpm")) {
        snprintf(cmd, sizeof(cmd),
                 "rpm -q --qf '%%{VERSION}-%%{RELEASE}\\n' %s 2>/dev/null", pkg_name);
        char *ver = run_and_get_first_line(cmd);
        if (ver && strncmp(ver, "package ", 8) != 0 && strncmp(ver, "no package", 10) != 0)
            return ver;
        free(ver);
    }

    return NULL;
}
