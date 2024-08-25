package NAT

import(
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// NatTable represents the NAT translation table
var NatTable map[string]*natEntry

// natEntry represents an entry in the NAT translation table
type natEntry struct {
	InternalIP     string
	InternalPort   int
	ExternalIP     string
	ExternalPort   int
	LastAccessTime time.Time
}

func main() {
	// Initialize the NAT translation table
	NatTable = make(map[string]*natEntry)

	// Start the NAT server
	go startNatServer("203.0.113.10", "192.168.1.0/24", "192.168.1.1")

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down NAT server...")
}

// startNatServer starts the NAT server with the provided configuration
func startNatServer(externalIP, internalCIDR, defaultGW string) {
	internalIP, _, _ := net.ParseCIDR(internalCIDR)

	// Setup default gateway and route
	addRoute(defaultGW, externalIP)

	// Create a UDP listener for NAT translation
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:10000", externalIP))
	if err != nil {
		log.Fatalf("Error resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		log.Fatalf("Error starting NAT server: %v", err)
	}
	defer conn.Close()

	log.Printf("NAT server started on %s:10000", externalIP)

	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		// Handle ICMP packets
		if buffer[0] == 0x08 && buffer[1] == 0x00 { // ICMP Echo Request
			go handleICMPEchoRequest(conn, clientAddr, buffer[:n], internalIP)
			continue
		}

		// Handle UDP packets
		go handleUDPPacket(conn, clientAddr, buffer[:n], internalIP)
	}
}

// handleICMPEchoRequest handles ICMP Echo Request packets (ping)
func handleICMPEchoRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte, internalIP net.IP) {
	// Perform NAT translation for ICMP Echo Reply
	reply := make([]byte, len(packet))
	copy(reply, packet)
	reply[0] = 0x00 // Change ICMP type to Echo Reply

	// Send ICMP Echo Reply to the client
	conn.WriteToUDP(reply, clientAddr)
}

// handleUDPPacket handles incoming UDP packets
func handleUDPPacket(conn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte, internalIP net.IP) {
	// Perform NAT translation for UDP packets
	externalPort := clientAddr.Port
	internalPort := translatePort(externalPort)

	// Create a NAT entry in the translation table
	natEntry := &natEntry{
		InternalIP:   internalIP.String(),
		InternalPort: internalPort,
		ExternalIP:   clientAddr.IP.String(),
		ExternalPort: externalPort,
	}
	key := fmt.Sprintf("%s:%d", clientAddr.IP.String(), clientAddr.Port)
	NatTable[key] = natEntry

	// Forward the UDP packet to the internal host
	internalAddr := fmt.Sprintf("%s:%d", internalIP.String(), internalPort)
	internalUDPAddr, _ := net.ResolveUDPAddr("udp", internalAddr)
	conn.WriteToUDP(packet, internalUDPAddr)
}

// translatePort performs port translation based on NAT mappings
func translatePort(externalPort int) int {
	// Your logic for dynamic port translation based on NAT mappings
	return externalPort + 10000 // Placeholder logic, replace with actual mapping logic
}

// addRoute simulates adding a route to the default gateway
func addRoute(defaultGW, viaIP string) {
	cmd := fmt.Sprintf("route add %s gw %s", defaultGW, viaIP)
	runCommand(cmd)
}

// runCommand simulates executing a system command
func runCommand(cmd string) {
	log.Printf("Executing command: %s", cmd)
	// Placeholder for actual command execution (not implemented for simplicity)
}
