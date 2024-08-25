package networkSegmentation

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Define network interfaces for segmentation (example interfaces)
	interface1 := "eth0"
	interface2 := "eth1"

	// Open the first interface for capturing packets
	handle1, err := pcap.OpenLive(interface1, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle1.Close()

	// Open the second interface for capturing packets
	handle2, err := pcap.OpenLive(interface2, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle2.Close()

	// Create a packet capture filter for each interface
	filter1 := "tcp and dst port 80"
	filter2 := "tcp and dst port 443"

	if err := handle1.SetBPFFilter(filter1); err != nil {
		log.Fatal(err)
	}

	if err := handle2.SetBPFFilter(filter2); err != nil {
		log.Fatal(err)
	}

	// Start capturing packets on each interface
	packetSource1 := gopacket.NewPacketSource(handle1, handle1.LinkType())
	packetSource2 := gopacket.NewPacketSource(handle2, handle2.LinkType())

	fmt.Println("Capturing packets on interface 1 (HTTP)...")
	handlePackets(packetSource1)

	fmt.Println("Capturing packets on interface 2 (HTTPS)...")
	handlePackets(packetSource2)
}

func handlePackets(packetSource *gopacket.PacketSource) {
	for packet := range packetSource.Packets() {
		// Extract packet information
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		fmt.Printf("Source IP: %s, Destination IP: %s, Destination Port: %d\n",
			ip.SrcIP, ip.DstIP, tcp.DstPort)
	}
}
