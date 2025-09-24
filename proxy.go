package main

import (
	"encoding/hex"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func isNeighborSolicitation(packet gopacket.Packet) bool {
	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer == nil {
		return false
	}

	icmpv6, _ := icmpv6Layer.(*layers.ICMPv6)
	return icmpv6.TypeCode.Type() == layers.ICMPv6TypeNeighborSolicitation
}

func hexToIP(hexIP string) (net.IP, error) {
	h, err := hex.DecodeString(hexIP)
	if err != nil {
		return nil, err
	}
	return net.IP(h), nil
}

func ipInPrefix(ip net.IP, prefix string) bool {
	log.Printf("Checking if IP %s is in prefix %s", ip, prefix)
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Printf("Error parsing CIDR prefix '%s': %v", prefix, err)
		return ip.Equal(net.ParseIP(prefix))
	}
	log.Printf("Parsed prefix '%s' into network %s", prefix, ipnet.String())
	contains := ipnet.Contains(ip)
	log.Printf("Does network %s contain %s? %t", ipnet.String(), ip.String(), contains)
	return contains
}

// htons converts a short (uint16) from host-to-network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
