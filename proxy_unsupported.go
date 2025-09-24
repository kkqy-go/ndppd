//go:build !linux

package main

import (
	"fmt"
	"log"
	"net"
	"runtime"

	"github.com/google/gopacket"
)

func startProxyInstance(proxy Proxy) {
	log.Fatalf("Unsupported OS: %s", runtime.GOOS)
}

func findInterfaceForIP(ip net.IP) (string, error) {
	return "", fmt.Errorf("auto rule is not supported on %s", runtime.GOOS)
}

func handleNeighborSolicitation(packet gopacket.Packet, proxy Proxy) {
	log.Printf("Received Neighbor Solicitation on unsupported OS, ignoring.")
}
