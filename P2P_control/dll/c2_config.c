#include <windows.h>

// Exported count of C2 addresses
__declspec(dllexport) unsigned int C2Count = 3;

// Exported array of C2 URL strings
__declspec(dllexport) const char *C2Addresses[] = {
    "http://localhost/",
    "http://localhost/",
    "http://localhost/"
};

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    return TRUE;
}
