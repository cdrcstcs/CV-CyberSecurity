package TLS

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal("Failed to load server certificate and key:", err)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Create HTTPS server with custom TLS configuration
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Handle requests based on HTTP method
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRequest(w, r)
		case http.MethodPost:
			handlePostRequest(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Start HTTPS server
	log.Println("Starting HTTPS server on port 8443...")
	err = server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		log.Fatal("HTTPS server error:", err)
	}
}

// Handle GET requests
func handleGetRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, TLS! This is a GET request.\n")
}

// Handle POST requests
func handlePostRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, TLS! This is a POST request.\n")
}
