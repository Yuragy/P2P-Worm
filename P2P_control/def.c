#define _GNU_SOURCE
#include "def.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cpuid.h>

static bool check_tracerpid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return false;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return false;
}

bool is_debugger_present(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1 && errno == EPERM) {
        return true;
    }
    ptrace(PTRACE_DETACH, 0, 0, 0);
    return check_tracerpid();
}

bool is_running_in_vm(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1u << 31)) != 0;
    }
    return false;
}

static bool file_contains(const char *path, const char *substr) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[256];
    bool found = false;
    while (fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, substr)) { found = true; break; }
    }
    fclose(f);
    return found;
}

bool is_sandbox_environment(void) {
    const char *dmi_files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor"
    };
    const char *indicators[] = {
        "VirtualBox", "VMware", "KVM", "Microsoft Corporation", "Xen", "QEMU"
    };

    for (size_t i = 0; i < sizeof(dmi_files)/sizeof(dmi_files[0]); i++) {
        struct stat st;
        if (stat(dmi_files[i], &st) == 0) {
            for (size_t j = 0; j < sizeof(indicators)/sizeof(indicators[0]); j++) {
                if (file_contains(dmi_files[i], indicators[j])) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool is_compromised(void) {
    return is_debugger_present() ||
           is_running_in_vm() ||
           is_sandbox_environment();
}
