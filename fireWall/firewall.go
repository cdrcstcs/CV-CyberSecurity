package fireWall

import (
	"log"
	"net/http"
)

// BlockedUserAgents contains a list of user-agent strings to block.
var BlockedUserAgents = map[string]bool{
	"BadBot": true,
	"EvilCrawler": true,
}

// BlockedMethods contains a list of request methods to block.
var BlockedMethods = map[string]bool{
	http.MethodPost: true,
	http.MethodDelete: true,
}

// FirewallMiddleware is a middleware function that blocks requests based on certain criteria.
func FirewallMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block requests from specific user agents
		if BlockedUserAgents[r.UserAgent()] {
			http.Error(w, "Access denied: Blocked user agent", http.StatusForbidden)
			log.Printf("Blocked request from %s with user-agent: %s", r.RemoteAddr, r.UserAgent())
			return
		}

		// Block requests with specific methods
		if BlockedMethods[r.Method] {
			http.Error(w, "Access denied: Blocked method", http.StatusForbidden)
			log.Printf("Blocked request from %s with method: %s", r.RemoteAddr, r.Method)
			return
		}

		// Pass the request to the next handler if it's not blocked
		next.ServeHTTP(w, r)
	})
}

// Main handler
func mainHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, World!"))
}

func main() {
	mux := http.NewServeMux()

	// Use the firewall middleware for all requests
	mux.HandleFunc("/", mainHandler)
	http.ListenAndServe(":8080", FirewallMiddleware(mux))

	log.Println("Server started on port 8080")
}
