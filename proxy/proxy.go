package proxy

import(
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

var (
	proxyPort     = ":8080"
	proxyUsername = "admin"
	proxyPassword = "password"
	rateLimit     = 100 // requests per second
)

func main() {
	// Create a HTTP proxy server with basic authentication
	authProxy := &AuthProxy{
		Username: proxyUsername,
		Password: proxyPassword,
		Limiter:  NewRateLimiter(rateLimit),
	}
	http.Handle("/", authProxy)

	// Start the proxy server
	log.Printf("Starting proxy server on port %s", proxyPort)
	if err := http.ListenAndServe(proxyPort, nil); err != nil {
		log.Fatalf("Error starting proxy server: %v", err)
	}
}

// AuthProxy is a HTTP proxy handler with basic authentication and rate limiting
type AuthProxy struct {
	Username string
	Password string
	Limiter  *RateLimiter
}

// ServeHTTP handles incoming HTTP requests and forwards them to the destination server
func (p *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check rate limit
	if !p.Limiter.Allow() {
		http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
		return
	}

	// Check if the request includes valid credentials
	if !p.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Create a new reverse proxy instance
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "https", // Forward to HTTPS
		Host:   r.Host,
	})

	// Modify the director to customize the outgoing request
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
	}

	// Set up error handling for the proxy
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Proxy Error", http.StatusInternalServerError)
	}

	// Set up request logging
	log.Printf("[%s] %s %s", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.URL.String())

	// Serve the request using the reverse proxy
	proxy.ServeHTTP(w, r)
}

// authenticate checks if the request includes valid credentials
func (p *AuthProxy) authenticate(r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	return ok && username == p.Username && password == p.Password
}

// RateLimiter implements rate limiting using token bucket algorithm
type RateLimiter struct {
	mu           sync.Mutex
	tokens       int
	lastRefill   time.Time
	refillPeriod time.Duration
}

// NewRateLimiter creates a new RateLimiter with the specified rate limit (requests per second)
func NewRateLimiter(rateLimit int) *RateLimiter {
	return &RateLimiter{
		tokens:       rateLimit,
		lastRefill:   time.Now(),
		refillPeriod: time.Second,
	}
}

// Allow checks if the rate limiter allows the request
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	rl.tokens += int(elapsed / rl.refillPeriod)
	if rl.tokens > rateLimit {
		rl.tokens = rateLimit
	}
	rl.lastRefill = now

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}
