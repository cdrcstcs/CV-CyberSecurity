package interceptionAttack

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	serverPort = ":443"
	serverHost = "localhost"
)

func main() {
	// Initialize logging
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		logrus.Fatalf("Error loading server certificate: %v", err)
	}

	// Load root CA certificate for client authentication
	caCert, err := ioutil.ReadFile("rootCA.crt")
	if err != nil {
		logrus.Fatalf("Error reading root CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure TLS settings for server
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}

	// Create HTTP server with TLS
	server := &http.Server{
		Addr:         serverPort,
		Handler:      http.HandlerFunc(handleRequest),
		TLSConfig:    config,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start HTTP server
	logrus.Infof("Starting server on https://%s%s", serverHost, serverPort)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		logrus.Fatalf("HTTP server error: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Log incoming request
	logrus.Infof("Received request from %s: %s", r.RemoteAddr, r.URL.Path)

	// Validate client certificate
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		logrus.Warn("Unauthorized request: Client certificate not provided")
		return
	}

	// Authenticate client based on certificate attributes
	clientCert := r.TLS.PeerCertificates[0]
	if !isClientAuthorized(clientCert) {
		http.Error(w, "Unauthorized client", http.StatusForbidden)
		logrus.Warn("Unauthorized request: Client not authorized")
		return
	}

	// Serve response to client
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Welcome to the secure server!"))
}

// isClientAuthorized checks if the client certificate attributes are authorized
func isClientAuthorized(cert *x509.Certificate) bool {
	// Perform realistic client authorization checks here
	// For example, check the certificate's subject, issuer, expiration, etc.

	// Example authorization check: Verify the certificate's subject common name (CN)
	if cert.Subject.CommonName != "client.example.com" {
		logrus.Warnf("Client certificate rejected: Invalid common name (%s)", cert.Subject.CommonName)
		return false
	}

	// Check if the certificate is expired
	if time.Now().After(cert.NotAfter) {
		logrus.Warn("Client certificate rejected: Certificate expired")
		return false
	}

	// Additional authorization checks can be added as needed

	// If all checks pass, authorize the client
	return true
}
