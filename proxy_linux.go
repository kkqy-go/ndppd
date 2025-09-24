//go:build linux

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	icmpv6FlagRouter    = 0b10000000
	icmpv6FlagSolicited = 0b01000000
	icmpv6FlagOverride  = 0b00100000
)

func startProxyInstance(proxy Proxy) {
	log.Printf("Starting proxy on interface %s", proxy.Interface)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("Error creating raw socket: %v", err)
	}
	defer syscall.Close(fd)

	iface, err := net.InterfaceByName(proxy.Interface)
	if err != nil {
		log.Fatalf("Error getting interface %s: %v", proxy.Interface, err)
	}

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	if err := syscall.Bind(fd, addr); err != nil {
		log.Fatalf("Error binding to interface %s: %v", proxy.Interface, err)
	}

	buf := make([]byte, 65536)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Printf("Error reading from raw socket: %v", err)
			continue
		}

		if fromLL, ok := from.(*syscall.SockaddrLinklayer); ok {
			if fromLL.Pkttype == syscall.PACKET_MULTICAST || fromLL.Pkttype == syscall.PACKET_OUTGOING {
				packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.Default)
				if isNeighborSolicitation(packet) {
					ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
					if ipv6Layer != nil {
						ipv6, _ := ipv6Layer.(*layers.IPv6)
						log.Printf("Received Neighbor Solicitation: src=%s, dst=%s", ipv6.SrcIP, ipv6.DstIP)
						handleNeighborSolicitation(packet, proxy, fromLL)
					} else {
						log.Printf("Received Neighbor Solicitation packet (could not parse IPv6 layer).")
					}
				}
			}
		}
	}
}

func handleNeighborSolicitation(packet gopacket.Packet, proxy Proxy, from *syscall.SockaddrLinklayer) {
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		return
	}
	ipv6, _ := ipv6Layer.(*layers.IPv6)

	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer == nil {
		return
	}
	icmpv6, _ := icmpv6Layer.(*layers.ICMPv6)

	var ns layers.ICMPv6NeighborSolicitation
	err := ns.DecodeFromBytes(icmpv6.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		log.Printf("Error decoding Neighbor Solicitation: %v", err)
		return
	}

	for _, rule := range proxy.Rules {
		if from != nil && from.Pkttype == syscall.PACKET_OUTGOING && !ipInPrefix(ns.TargetAddress, rule.Address) && proxy.RewriteSource && ipv6.SrcIP.IsLinkLocalUnicast() {
			_, ipnet, err := net.ParseCIDR(rule.Address)
			if err != nil {
				log.Printf("Error parsing CIDR %s: %v", rule.Address, err)
				continue
			}

			newSrcIP := ipnet.IP
			log.Printf("RewriteSource: replacing link-local source %s with %s", ipv6.SrcIP, newSrcIP)

			ethLayer := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

			ipv6LayerOut := &layers.IPv6{
				Version:      6,
				TrafficClass: ipv6.TrafficClass,
				FlowLabel:    ipv6.FlowLabel,
				Length:       ipv6.Length,
				NextHeader:   ipv6.NextHeader,
				HopLimit:     ipv6.HopLimit,
				SrcIP:        newSrcIP,
				DstIP:        ipv6.DstIP,
			}

			icmpv6LayerOut := &layers.ICMPv6{
				TypeCode: icmpv6.TypeCode,
				Checksum: 0, // Recalculate checksum
			}
			icmpv6LayerOut.SetNetworkLayerForChecksum(ipv6LayerOut)

			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			gopacket.SerializeLayers(buf, opts, ethLayer, ipv6LayerOut, icmpv6LayerOut, gopacket.Payload(icmpv6.Payload))

			newPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

			iface, err := findInterfaceForIP(ns.TargetAddress)
			if err != nil {
				log.Printf("Error finding interface for %s: %v", ns.TargetAddress, err)
				return
			}
			forwardPacket(newPacket, iface)
		}
		if ipInPrefix(ns.TargetAddress, rule.Address) {
			if rule.Static {
				log.Printf("Matched static rule for %s", ns.TargetAddress)
				sendNeighborAdvertisement(packet, proxy, &ns)
				return
			}
			if rule.Iface != "" {
				log.Printf("Matched iface rule for %s, forwarding to %s", ns.TargetAddress, rule.Iface)
				forwardPacket(packet, rule.Iface)
				return
			} else if rule.Auto {
				log.Printf("Matched auto rule for %s", ns.TargetAddress)
				iface, err := findInterfaceForIP(ns.TargetAddress)
				if err != nil {
					log.Printf("Error finding interface for %s: %v", ns.TargetAddress, err)
					return
				}
				forwardPacket(packet, iface)
				return
			}
		}
	}
	log.Printf("No rule matched for NS target address: %s", ns.TargetAddress)
}

func sendNeighborAdvertisement(solPacket gopacket.Packet, proxy Proxy, ns *layers.ICMPv6NeighborSolicitation) {
	ethLayer := solPacket.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)

	ipv6Layer := solPacket.Layer(layers.LayerTypeIPv6)
	ipv6, _ := ipv6Layer.(*layers.IPv6)

	iface, err := net.InterfaceByName(proxy.Interface)
	if err != nil {
		log.Printf("Error getting interface %s: %v", proxy.Interface, err)
		return
	}

	// Create the Ethernet layer
	ethLayerOut := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	// Create the IPv6 layer
	ipv6LayerOut := &layers.IPv6{
		Version:    6,
		SrcIP:      ns.TargetAddress,
		DstIP:      ipv6.SrcIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}

	// Create the ICMPv6 layer
	icmpv6LayerOut := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}

	// Create the Neighbor Advertisement
	flags := uint8(icmpv6FlagSolicited)
	if proxy.Router {
		flags |= icmpv6FlagRouter
	}
	options := []layers.ICMPv6Option{}
	if !ns.TargetAddress.Equal(ipv6.DstIP) {
		flags |= icmpv6FlagOverride
		options = append(options, layers.ICMPv6Option{
			Type: layers.ICMPv6OptTargetAddress,
			Data: iface.HardwareAddr,
		})
	}
	log.Printf("Neighbor Advertisement Flags: %08b", flags)
	na := &layers.ICMPv6NeighborAdvertisement{
		TargetAddress: ns.TargetAddress,
		Flags:         flags,
		Options:       options,
	}

	icmpv6LayerOut.SetNetworkLayerForChecksum(ipv6LayerOut)

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, ethLayerOut, ipv6LayerOut, icmpv6LayerOut, na)

	// Send the packet
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Printf("Error creating raw socket for sending: %v", err)
		return
	}
	defer syscall.Close(fd)

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	if err := syscall.Sendto(fd, buf.Bytes(), 0, addr); err != nil {
		log.Printf("Error sending packet: %v", err)
	}
}

func forwardPacket(packet gopacket.Packet, ifaceName string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Printf("Error getting interface %s: %v", ifaceName, err)
		return
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Printf("Error creating raw socket for sending: %v", err)
		return
	}
	defer syscall.Close(fd)

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	if err := syscall.Sendto(fd, packet.Data(), 0, addr); err != nil {
		log.Printf("Error sending packet: %v", err)
	}
}

func findInterfaceForIP(ip net.IP) (string, error) {
	file, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 10 {
			continue
		}

		dstNetHex := parts[0]
		dstPrefixLen, _ := strconv.ParseInt(parts[1], 16, 32)

		dstIP, err := hexToIP(dstNetHex)
		if err != nil {
			continue
		}

		_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", dstIP, dstPrefixLen))
		if err != nil {
			continue
		}

		if ipnet.Contains(ip) {
			return parts[9], nil
		}
	}

	return "", fmt.Errorf("no route found for %s", ip)
}
