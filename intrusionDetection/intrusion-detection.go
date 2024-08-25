package intrusionDetection

import (
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var (
	networkInterface = "en0" // Replace with the actual network interface name
	pcapFile         = "capture.pcap"
)

type PacketInfo struct {
	Timestamp time.Time
	SourceIP  string
	DestIP    string
	Protocol  string
	Payload   []byte
}

type Incident struct {
	Timestamp time.Time
	Packet    PacketInfo
	Severity  int
}

func main() {
	setupLogging()

	// Create a PCAP packet capture
	handle, err := pcap.OpenLive(networkInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		logrus.Fatalf("Failed to open packet capture: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCh := make(chan PacketInfo)
	incidentCh := make(chan Incident)

	go processPackets(packetSource, packetCh, incidentCh)
	go monitorIncidents(incidentCh)

	// Capture packets and process them
	logrus.Infof("Capturing packets from interface %s...", networkInterface)
	for packet := range packetCh {
		logrus.Infof("Received packet from %s to %s, Protocol: %s", packet.SourceIP, packet.DestIP, packet.Protocol)
		incident := detectIncident(packet)
		if incident != nil {
			incidentCh <- *incident
		}
	}

	// Handle graceful shutdown
	handleShutdown()
}

func processPackets(packetSource *gopacket.PacketSource, packetCh chan PacketInfo, incidentCh chan Incident) {
	for packet := range packetSource.Packets() {
		packetInfo := parsePacket(packet)
		packetCh <- packetInfo
	}
}

func parsePacket(packet gopacket.Packet) PacketInfo {
	packetInfo := PacketInfo{
		Timestamp: time.Now(),
	}

	// Extract packet information
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		packetInfo.SourceIP = ip.SrcIP.String()
		packetInfo.DestIP = ip.DstIP.String()
		packetInfo.Protocol = "IPv4"

		// Extract transport layer information
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			packetInfo.Protocol = "TCP"
			tcp, _ := tcpLayer.(*layers.TCP)
			packetInfo.Payload = tcp.Payload
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			packetInfo.Protocol = "UDP"
			udp, _ := udpLayer.(*layers.UDP)
			packetInfo.Payload = udp.Payload
		}
	}

	return packetInfo
}

func detectIncident(packet PacketInfo) *Incident {
	// Simulate advanced detection techniques and threat intelligence
	severity := calculateThreatSeverity(packet)
	if severity > 0 {
		return &Incident{
			Timestamp: time.Now(),
			Packet:    packet,
			Severity:  severity,
		}
	}
	return nil
}

func calculateThreatSeverity(packet PacketInfo) int {
	// Simulate threat scoring based on payload analysis, known signatures, anomaly detection, etc.
	// For example, higher severity for potential malware payloads or known attack signatures
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(10) // Random severity score (0-9)
}

func monitorIncidents(incidentCh chan Incident) {
	for incident := range incidentCh {
		logrus.Warnf("Incident Detected - Severity: %d, Packet: %+v", incident.Severity, incident.Packet)
		// Perform incident response actions (e.g., block source IP, send alerts, log to file/database)
	}
}

func setupLogging() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)
}

func handleShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logrus.Info("Shutting down...")
	os.Exit(0)
}

