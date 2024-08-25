package DNSpoisoning

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

func main() {
	// Start BIND DNS server on port 53
	go startDNSServer()

	// Periodically flush DNS cache and monitor DNS traffic
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		fmt.Println("Flushing DNS cache...")
		if err := flushDNSCache(); err != nil {
			logrus.Errorf("Error flushing DNS cache: %v", err)
		}

		fmt.Println("Monitoring DNS traffic...")
		monitorDNSQueries()
	}
}

// Start BIND DNS server
func startDNSServer() {
	cmd := exec.Command("named", "-c", "/etc/bind/named.conf") // Adjust path to your BIND config file
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logrus.Fatalf("Error starting BIND DNS server: %v", err)
	}
}

// Flush DNS cache using rndc command
func flushDNSCache() error {
	cmd := exec.Command("rndc", "flush")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Monitor DNS queries
func monitorDNSQueries() {
	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		logrus.Fatalf("Error listening on port 53: %v", err)
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			logrus.Errorf("Error reading UDP message: %v", err)
			continue
		}

		query := string(buffer[:n])
		logrus.Infof("Received DNS query from %s: %s", clientAddr.String(), query)

		// Log DNS queries using Logrus
		logDNSQuery(query)
	}
}

// Log DNS queries using Logrus
func logDNSQuery(query string) {
	file, err := os.OpenFile("dns_queries.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("Error opening log file: %v", err)
		return
	}
	defer file.Close()

	logger := logrus.New()
	logger.SetOutput(file)
	logger.Infof(query)
}
