package NAC

import(
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// Constants for configuration
const (
	nacEnabled         = true
	nacAllowedMAC      = "00:11:22:33:44:55" // Example allowed MAC address
	loadBalancerURL    = "http://backend:8080"
	natTranslation     = "10.0.0.2" // Example NAT translation
	intrusionThreshold = 5          // Number of allowed requests per second
)

// Global variables for load balancing
var (
	backendServers = []string{"http://server1:8080", "http://server2:8080"}
	currentBackend int
	backendMutex   sync.Mutex
)

// Global variables for NAT translation
var (
	natTable = map[string]string{
		"192.168.1.2": natTranslation,
	}
)

// Middleware for NAC, Load Balancing, NAT, and Intrusion Detection
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// NAC Check
		clientMAC := r.Header.Get("X-Client-MAC")
		if !allowAccess(clientMAC) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Access Denied: Unauthorized MAC address")
			return
		}

		// Load Balancer
		r.URL.Host = getBackendURL()
		r.URL.Scheme = "http"

		// NAT Translation
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		if translatedIP, ok := natTable[clientIP]; ok {
			r.RemoteAddr = translatedIP + ":80"
		}

		// Intrusion Detection
		if detectIntrusion(r.RemoteAddr) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Access Denied: Intrusion detected")
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// NAC Policy
func allowAccess(macAddress string) bool {
	// Simulate NAC policy check
	return nacEnabled && macAddress == nacAllowedMAC
}

// Load Balancer
func getBackendURL() string {
	backendMutex.Lock()
	defer backendMutex.Unlock()
	currentBackend = (currentBackend + 1) % len(backendServers)
	return backendServers[currentBackend]
}

// Intrusion Detection
var (
	intrusionRecords = make(map[string]int)
	intrusionMutex   sync.Mutex
)

func detectIntrusion(ipAddress string) bool {
	intrusionMutex.Lock()
	defer intrusionMutex.Unlock()

	now := time.Now().Unix()
	count, exists := intrusionRecords[ipAddress]
	if !exists || now-int64(count) > 1 { // Check for intrusion threshold per second
		intrusionRecords[ipAddress] = int(now)
		return false
	}

	return true
}

func main() {
	// Initialize the router using Gorilla Mux
	r := mux.NewRouter()

	// Attach the security middleware to all routes
	r.Use(securityMiddleware)

	// Define routes
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome to the secure server!")
	})

	// Create an HTTP server with timeouts and listen on port 8080
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start the HTTP server
	log.Println("Starting HTTP server on port 8080")
	log.Fatal(srv.ListenAndServe())
}
