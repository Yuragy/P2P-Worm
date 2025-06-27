#ifndef P2P_LOADER_H
#define P2P_LOADER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    HMODULE module;         // Windows module handle
    unsigned int count;     // Number of C2 addresses
    const char **addresses; // Pointer to array of C2 address strings
} P2PConfig;

int p2p_init(const char *dll_path, P2PConfig *cfg);


void p2p_cleanup(P2PConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif // P2P_LOADER_H
