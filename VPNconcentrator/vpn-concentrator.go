package VPNconcentrator

import(
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"crypto/x509/pkix"
	"time"
)

// VPNConcentrator represents a VPN concentrator server
type VPNConcentrator struct {
	listener   net.Listener
	users      map[string]string // Usernames and passwords
	routes     map[string]string // Routing table: maps username to IP address
	certificate tls.Certificate  // Server certificate and key
}

// NewVPNConcentrator creates a new VPN concentrator instance
func NewVPNConcentrator(addr string) (*VPNConcentrator, error) {
	// Generate a self-signed certificate for the VPN server
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	// Create a TCP listener on the specified address with TLS configuration
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", addr, &config)
	if err != nil {
		return nil, err
	}

	return &VPNConcentrator{
		listener:   listener,
		users:      map[string]string{"user1": "password1", "user2": "password2"}, // User credentials
		routes:     map[string]string{"user1": "10.0.0.1", "user2": "10.0.0.2"},   // Routing table
		certificate: cert,
	}, nil
}

// Serve accepts incoming VPN connections and handles them
func (vpn *VPNConcentrator) Serve() {
	for {
		conn, err := vpn.listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go vpn.handleConnection(conn)
	}
}

// handleConnection handles an incoming VPN connection
func (vpn *VPNConcentrator) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Perform TLS handshake for secure communication
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{vpn.certificate}})
	if err := tlsConn.Handshake(); err != nil {
		log.Println("TLS handshake error:", err)
		return
	}

	// Perform user authentication
	username,_, err := vpn.authenticateUser(tlsConn)
	if err != nil {
		log.Println("Authentication error:", err)
		return
	}

	// Authorize user and get routing information
	ipAddr, found := vpn.routes[username]
	if !found {
		log.Println("Authorization error: user not authorized")
		return
	}

	// Handle VPN traffic (simulated data exchange)
	for {
		data := make([]byte, 1024)
		n, err := tlsConn.Read(data)
		if err != nil {
			log.Println("Error reading from connection:", err)
			break
		}
		fmt.Printf("Received from client %s (%s): %s\n", username, ipAddr, string(data[:n]))

		// Simulate processing of received data (not implemented in this example)
		time.Sleep(time.Second) // Simulate processing time
	}
}

// authenticateUser performs user authentication using TLS client certificate
func (vpn *VPNConcentrator) authenticateUser(conn *tls.Conn) (string, string, error) {
	// Retrieve the client certificate
	certificates := conn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return "", "", fmt.Errorf("no client certificate provided")
	}
	clientCert := certificates[0]

	// Extract username and password from client certificate attributes
	username := clientCert.Subject.CommonName
	password := string(clientCert.SubjectKeyId)
	expectedPassword, found := vpn.users[username]
	if !found || password != expectedPassword {
		return "", "", fmt.Errorf("invalid username or password")
	}
	return username, password, nil
}

// generateSelfSignedCert generates a self-signed TLS certificate for the VPN server
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "VPN Server"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	// Create a new VPN concentrator on port 5000
	vpn, err := NewVPNConcentrator(":5000")
	if err != nil {
		log.Fatal("Error creating VPN concentrator:", err)
	}

	fmt.Println("VPN concentrator listening on port 5000...")
	vpn.Serve()
}
