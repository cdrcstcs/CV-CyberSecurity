package honeypot
import(
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	honeypotPath = "/honeypot"
	serverPort   = ":8080"
)

func main() {
	// Initialize logging
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)

	// Create a new Gorilla mux router
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/", handleIndex).Methods("GET")
	router.HandleFunc(honeypotPath, handleHoneypot).Methods("POST")

	// Define rate limiter with a limit of 5 requests per second
	limiter := rate.NewLimiter(rate.Limit(5), 1)

	// Start HTTP server
	server := &http.Server{
		Addr:         serverPort,
		Handler:      limiterMiddleware(router, limiter),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	logrus.Infof("Starting server on port %s", serverPort)
	if err := server.ListenAndServe(); err != nil {
		logrus.Fatalf("Server error: %v", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	// Serve the index page
	fmt.Fprintf(w, "Welcome to the main page!")
}

func handleHoneypot(w http.ResponseWriter, r *http.Request) {
	// Validate request to prevent malicious payloads
	if err := validateRequest(r); err != nil {
		logrus.Warnf("Invalid request received from IP %s: %v", r.RemoteAddr, err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Log honeypot activity with context
	logrus.WithFields(logrus.Fields{
		"ip":         r.RemoteAddr,
		"user_agent": r.UserAgent(),
		"method":     r.Method,
		"path":       r.URL.Path,
	}).Warn("Honeypot attack detected")

	// Add the attacker's IP to a blacklist
	blacklistIP(r.RemoteAddr)

	// Set response headers to inform attackers
	w.Header().Set("X-Honeypot", "true")
	w.Header().Set("Server", "Fake Server")

	// Respond with a generic message to the attacker
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "You've stumbled upon a honeypot. Your activity has been logged and you are now blacklisted.")
}

func limiterMiddleware(next http.Handler, limiter *rate.Limiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter.Allow() {
			next.ServeHTTP(w, r)
		} else {
			logrus.Warn("Rate limit exceeded. Blocking request.")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, "Rate limit exceeded. Please try again later.")
		}
	})
}

func validateRequest(r *http.Request) error {
	// Implement request validation logic here (e.g., check request body, headers, etc.)
	// For demonstration, we'll just check if the request is coming from a valid source
	validSources := []string{"192.168.1.1", "10.0.0.1"}
	if !contains(validSources, r.RemoteAddr) {
		return fmt.Errorf("Invalid source IP: %s", r.RemoteAddr)
	}
	return nil
}

func blacklistIP(ip string) {
	// In a real-world scenario, this function would add the attacker's IP to a persistent blacklist
	// For demonstration purposes, we'll just log the IP address
	logrus.Warnf("IP blacklisted: %s", ip)
}

func contains(arr []string, val string) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
