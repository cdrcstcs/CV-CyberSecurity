package SSID

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

func main() {
	// SSH connection configuration
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password("your_password"),
			// Add other authentication methods as needed
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Ignore host key verification
	}

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", "your_router_ip:22", config)
	if err != nil {
		log.Fatal("SSH connection error:", err)
	}
	defer client.Close()

	// Create a session
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session:", err)
	}
	defer session.Close()

	// Run commands to modify SSID settings
	commands := []string{
		"configure terminal",
		"no dot11 ssid your_ssid",       // Disable SSID broadcasting
		"dot11 ssid your_cryptic_ssid",  // Assign cryptic SSID
		"end",
		"write memory", // Save configuration changes
	}

	for _, cmd := range commands {
		if err := session.Run(cmd); err != nil {
			log.Fatalf("Command execution error: %s - %v", cmd, err)
		}
		fmt.Printf("Executed command: %s\n", cmd)
	}
	fmt.Println("SSID settings updated successfully")
}
