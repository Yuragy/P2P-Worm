# Self-Propagating Worm

> Collection of scripts **and** a binary agent for automated reconnaissance scanning, SSH/Telnet propagation, and C2 control.

---

## 🚫 Disclaimer  
This repository is provided for **educational purposes only** and intended for **authorized security research**.  
Use of these materials in unauthorized or illegal activities is **strictly prohibited**.

---

## 📜 Description  

This project implements a multi-component **self-propagating worm**, consisting of:

| Component | Role |
|-----------|------|
| **`recon.py`** | Reconnaissance module: gathers SSH credentials, scans the network, launches attack plugins |
| **`guid/*.py`** | Technique plugins for remote access over **SSH** and **Telnet** |
| **`agent.go`** | Lightweight C2 agent: deploys on victims, enables peer-to-peer propagation & remote command execution |

---

## ⚡ Quick Usage

```bash
# 1 – Run network reconnaissance
python recon.py

# 2 – When prompted:
#    • staging directory (default: /tmp/ssh_creds)
#    • any additional credentials
````

The script will automatically:

1. **Collect** SSH private keys & `known_hosts` → save as JSON in the staging dir.
2. **Discover** live hosts in the LAN.
3. For each host, apply the first **successful** technique from `ALL_TECHNIQUES`.

---

## 🔍 Recon Module — `recon.py`

| Function                               | Purpose                                                                                                                     |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **`find_private_keys()`**              | Locate `~/.ssh/id_*` (excluding `.pub`), set `600`, return paths                                                            |
| **`parse_known_hosts()`**              | Parse `~/.ssh/known_hosts`, ignore comments / hashes, return host list                                                      |
| **`copy_to_staging(keys)`**            | Create `/tmp/ssh_creds`, copy keys, return new paths                                                                        |
| **`prepare_ssh_data()`**               | Aggregate keys & hosts → write `/tmp/ssh_creds/ssh_data.json`<br>Returns:<br>`{"keys": [...], "known_hosts": [...]}`        |
| **`discover_hosts()`**                 | Find live hosts via:<br>• mDNS/Bonjour → `dns-sd -B _ssh._tcp`<br>• ARP + ping sweep                                        |
| **`load_creds_db(path="creds.json")`** | Load `(user, password)` pairs from JSON;<br>append key-based creds for current user                                         |
| **`probe_ports(ip)`**                  | Test ports **22, 23, 80, 445** with `nc -z`; return open list                                                               |
| **`main()`**                           | Orchestrates:<br>1️⃣ `prepare_ssh_data()` → 2️⃣ `load_creds_db()` → 3️⃣ `discover_hosts()` → 4️⃣ iterate hosts & techniques |

---

## 🧩 Plugins — `guid/*.py`

All plugins share a **Technique interface**:

```python
def applicable(host) -> bool
def execute(host, creds_db) -> bool
```

| Plugin               | What it does                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **`SSHBruteForce`**  | Targets port **22** → tries user/pass combos **&** SSH keys; on success, uploads & runs the payload/agent via SFTP |
| **`TelnetDefaults`** | Targets port **23** → attempts default Telnet creds; on success, transfers the agent in Base64 and executes        |

All are aggregated into **`ALL_TECHNIQUES`** for use by `recon.py`.

---

## 🤖 Agent — `agent.go`

| Stage                | Behaviour                                                                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Bootstrap**        | Copy binary → safe dir (macOS `~/Library/Application Support`, Linux `~/.local/bin`, Win `%APPDATA%`)<br>Remove macOS quarantine<br>Relaunch & exit original |
| **Persistence**      | macOS → LaunchAgent plist<br>Linux → systemd user unit<br>Windows → `HKCU\Run` key                                                                           |
| **P2P Listener**     | Default TCP **40444** → exchange peer lists (`savePeers` / `listPeers`)                                                                                      |
| **Main C2 Loop**     | Every **90 s**:<br>• gather host info + peers<br>• POST to CDN endpoint<br>• execute returned commands in parallel                                           |
| **Command Handling** | `self-update` → hot-swap binary<br>`exfil-keys` → collect SSH data<br>`scan-subnet` → built-in port scanner<br>*anything else* → run as shell cmd            |
| **Core**             | Go 1.XX, statically linked (OS + arch: macOS/Linux/Windows, arm/x86)                                                                                         |

---

## 🔧 Extensibility

The project is **under active development**—expect new techniques, transports, and evasions.
Feel free to open issues or pull requests!

```mermaid
flowchart LR
    subgraph Future Roadmap
        A[SMB Lateral Move]
        B[Kerberos Ticket Hunt]
        C[Reverse-TLS Transport]
        D[ELF Worm Variant]
        A --> B --> C --> D
    end
```

Stay tuned for updates.

