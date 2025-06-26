package main

import (
	"encoding/json"
	"net"
	"sync"
)

var (
	peerMu sync.Mutex
	peers  = make(map[string]struct{})
)

// startPeerListener listens on TCP port peerPort, receives JSON encoded
func startPeerListener() {
	ln, err := net.Listen("tcp", ":"+peerPort)
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			var incoming []string
			if err := json.NewDecoder(c).Decode(&incoming); err != nil {
				return
			}
			mergePeers(incoming)
		}(conn)
	}
}

// listPeers returns a snapshot of the current peer list
func listPeers() []string {
	peerMu.Lock()
	defer peerMu.Unlock()

	out := make([]string, 0, len(peers))
	for p := range peers {
		out = append(out, p)
	}
	return out
}

// mergePeers adds newPeers into the cache, removing duplicates
func mergePeers(newPeers []string) {
	peerMu.Lock()
	defer peerMu.Unlock()

	for _, p := range newPeers {
		peers[p] = struct{}{}
	}
}
