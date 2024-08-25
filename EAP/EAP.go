package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	caCertPath    = "ca.crt"
	serverCert    = "server.crt"
	serverKey     = "server.key"
	crlPath       = "crl.pem"
	clientTimeout = 10 * time.Second
)

func main() {
	// Initialize logging
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)

	// Load CA certificate
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		logrus.Fatalf("Failed to load CA certificate: %v", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		logrus.Fatal("Failed to parse CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		logrus.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Load CRL
	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		logrus.Fatalf("Failed to load CRL: %v", err)
	}

	crlBlock, _ := pem.Decode(crlPEM)
	if crlBlock == nil {
		logrus.Fatal("Failed to parse CRL PEM")
	}

	crl, err := x509.ParseCRL(crlBlock.Bytes)
	if err != nil {
		logrus.Fatalf("Failed to parse CRL: %v", err)
	}

	// Configure TLS settings
	config := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Verify client certificate
			clientCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("Failed to parse client certificate: %v", err)
			}

			// Log client certificate details
			logrus.Infof("Client Certificate Subject: %s", clientCert.Subject)
			logrus.Infof("Client Certificate Issuer: %s", clientCert.Issuer)
			logrus.Infof("Client Certificate Valid From: %s", clientCert.NotBefore)
			logrus.Infof("Client Certificate Valid Until: %s", clientCert.NotAfter)

			// Check certificate revocation
			if err := clientCert.CheckSignatureFrom(caCert); err != nil {
				return fmt.Errorf("Certificate revoked: %v", err)
			}

			// Check certificate against CRL
			if err := clientCert.CheckCRLSignature(crl); err != nil {
				return fmt.Errorf("Certificate revoked in CRL: %v", err)
			}

			return nil
		},
	}

	// Start EAP-TLS server on port 443
	listener, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		logrus.Fatalf("Failed to start EAP-TLS server: %v", err)
	}
	defer listener.Close()

	logrus.Info("EAP-TLS server started on port 443")

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logrus.Info("Shutting down server...")
		listener.Close()
	}()

	// Accept incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.Errorf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set timeout for client handshake
	if err := conn.SetDeadline(time.Now().Add(clientTimeout)); err != nil {
		logrus.Errorf("Error setting client timeout: %v", err)
		return
	}

	// Perform TLS handshake
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		logrus.Error("Error converting to TLS connection")
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		logrus.Errorf("TLS handshake error: %v", err)
		return
	}

	// Client authenticated successfully
	logrus.Info("Client authenticated successfully")
}
