# Self-Propagating Worm
Collection of scripts and a binary agent for automated reconnaissance scanning, SSH/Telnet propagation, and C2 control.

## 🚫 Disclaimer

This repository is provided for **educational purposes only** and intended for **authorized security research**.
Use of these materials in unauthorized or illegal activities is **strictly prohibited**.


## Description
This project implements a multi-component self-propagating worm, consisting of:
1. **recon.py** — a reconnaissance module that gathers SSH credentials, scans the local network, and launches attack plugins.  
2. **guid/*.py** — a set of techniques plugins for accessing remote hosts over SSH and Telnet.  
3. **agent.go** — a lightweight C2 agent that deploys on the victim, enables peer-to-peer propagation, P2P communication, and remote command execution.

## Usage
1. Run the reconnaissance script:
   python recon.py
2. Enter the staging directory path (default: /tmp/ssh_creds) and provide credentials when prompted.
3. The script will automatically:
   * Collect SSH private keys and known_hosts → save as JSON in staging
   * Discover active hosts in the LAN
   * For each host, apply the first successful technique from ALL_TECHNIQUES

## Recon Module (recon.py)
1. **find_private_keys()**
   Searches ~/.ssh for all id_* files (excluding .pub), sets their permissions to 600, and returns a list of their paths.
2. **parse_known_hosts()**
   Reads ~/.ssh/known_hosts, ignores commented or hashed entries, and returns a list of hostnames/IPs.
3. **copy_to_staging(keys)**
   Creates /tmp/ssh_creds, copies the provided key files there, and returns their new paths.
4. **prepare_ssh_data()**
   Gathers private keys and known hosts, writes /tmp/ssh_creds/ssh_data.json, and returns a dict:
     {
       "keys": [ "/tmp/ssh_creds/id_rsa", ... ],
       "known_hosts": [ "host1.com", "192.168.0.5", ... ]
     }
5. **discover_hosts()**
   Finds live hosts on the LAN via:
   mDNS/Bonjour: dns-sd -B _ssh._tcp
   ARP + ping sweep
   Returns a list of IP addresses.
6. **load_creds_db(path="creds.json")**
   Loads (user, password) pairs from a JSON file.
   Appends (current_user, path_to_ssh_key) for each key in staging.
7. **probe_ports(ip)**
   Checks ports 22, 23, 80, and 445 with nc -z.
   Returns a list of open ports.
8. **main()**
   Executes in sequence:
     1. prepare_ssh_data()
     2. creds_db = load_creds_db()
     3. hosts = discover_hosts()
     4. For each host, builds {"ip":…, "ports": …} and iterates through ALL_TECHNIQUES until one succeeds.

## Plugins (guid/*.py)
* **Technique interface**
  Defines applicable(host) and execute(host, creds_db) methods.
* **SSHBruteForce**
  Tests port 22.
  Attempts username/password combos and SSH keys from creds_db.
  On success, copies and executes payload/agent via SSH/SFTP.
* **TelnetDefaults**
  Tests port 23.
  Tries default Telnet passwords.
  On success, transfers payload/agent encoded in Base64 and executes it.

All plugins are aggregated in ALL_TECHNIQUES for use by recon.py.

## Agent (agent.go)
1. **Bootstrap**
   Copies its binary to a safe directory (macOS: ~/Library/Application Support, Linux: ~/.local/bin, Windows: %APPDATA%).
   On macOS, removes the quarantine attribute.
   Restarts the copied instance and exits the original.
2. **Persistence**
   Installs startup entries:
     macOS: LaunchAgent plist in ~/Library/LaunchAgents
     Linux: systemd user unit in ~/.config/systemd/user
     Windows: Run registry key under HKCU
3. **P2P Listener**
   Opens a TCP port default 40444
   Exchanges peer lists as JSON via savePeers/listPeers.
4. **Main C2 Loop**
   Every 90 seconds, gathers host info and peer list.
   Sends it via HTTP POST to a configured CDN endpoint.
   Executes returned command strings in parallel handle.
5. **Command Handling**
   self-update: downloads and atomically replaces its binary.
   exfil-keys: collects SSH data and sends it to C2.
   scan-subnet: runs built-in port scanner activeScan.
   Any other string: runs as a shell command.
6. **Core**
   Written in Go, statically compiled for macOS/Linux/Windows (arm/x86).
   Minimal external dependencies, TLS client, JSON serialization, raw sockets.

## Extensibility
Project in development, keep an eye out for updates. 
