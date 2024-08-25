package cookieAttack

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/justinas/alice"
	"golang.org/x/crypto/bcrypt"
)

// Global variables for session management
var (
	cookieHandler = securecookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)

	csrfMiddleware = csrf.Protect(
		[]byte(os.Getenv("CSRF_SECRET")),
		csrf.Secure(true),
	)

	validSessions = make(map[string]time.Time)
)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/profile", handleProfileRequest).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	// Middleware chain for enhanced security
	middlewareChain := alice.New(LoggingMiddleware, RateLimitMiddleware, csrfMiddleware)
	r.Use(middlewareChain.Then)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Fatal(server.ListenAndServeTLS("server.crt", "server.key")) // Use TLS for HTTPS
}

func handleProfileRequest(w http.ResponseWriter, r *http.Request) {
	chain := alice.New(
		csrfMiddleware,
		EnhancedAuthenticationMiddleware,
	).Then(http.HandlerFunc(profileHandler))

	chain.ServeHTTP(w, r)
}

// EnhancedAuthenticationMiddleware is a middleware that performs multi-factor authentication.
func EnhancedAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate session ID (in a real scenario, check against a database)
		if !isValidSession(sessionID.Value) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the user has passed multi-factor authentication
		if !isAuthenticated(r) {
			http.Error(w, "Multi-factor authentication required", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware is a middleware that logs incoming requests.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a logger with request-specific fields
		logger := log.New(os.Stdout, "", 0)
		logger.Printf("Received %s request for %s", r.Method, r.URL.Path)

		defer func() {
			logger.Printf("Request completed in %s", time.Since(start))
		}()

		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware is a middleware that limits the number of requests per IP.
func RateLimitMiddleware(next http.Handler) http.Handler {
	limiter := NewRateLimiter(10, time.Second*60) // Allow 10 requests per minute per IP
	return limiter.LimitHTTPHandler(next)
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(limit int64, window time.Duration) *RateLimiter {
	return &RateLimiter{
		Limiter: NewLimiter(limit),
		Window:  window,
	}
}

// RateLimiter is a custom rate limiter.
type RateLimiter struct {
	Limiter *Limiter
	Window  time.Duration
}

// LimitHTTPHandler limits the requests using the rate limiter.
func (rl *RateLimiter) LimitHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr // Use IP address as key for rate limiting
		if !rl.Limiter.Allow(key, rl.Window) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Limiter is a basic rate limiter implementation.
type Limiter struct {
	Counter map[string]int64
	Limit   int64
}

// NewLimiter creates a new Limiter.
func NewLimiter(limit int64) *Limiter {
	return &Limiter{
		Counter: make(map[string]int64),
		Limit:   limit,
	}
}

// Allow checks if a key (e.g., IP address) is allowed based on the rate limit and window duration.
func (lim *Limiter) Allow(key string, window time.Duration) bool {
	if lim.Counter[key] >= lim.Limit {
		return false
	}

	lim.Counter[key]++
	time.AfterFunc(window, func() {
		lim.Counter[key]--
	})

	return true
}

// isAuthenticated checks if the user has passed multi-factor authentication.
func isAuthenticated(r *http.Request) bool {
	// Implement your multi-factor authentication logic here.
	// For example, check if a specific header or token is present in the request.
	return true // Placeholder return value, replace with actual logic
}

// isValidSession checks if a session ID is valid.
func isValidSession(sessionID string) bool {
	expiration, ok := validSessions[sessionID]
	if !ok {
		return false
	}
	return time.Now().Before(expiration)
}

// Authenticator is an interface for authentication.
type Authenticator interface {
	Authenticate(username, password string) bool
}

func authenticate(username, password string) bool {
	// Implement your authentication logic here.
	// For example, check against a database or external service.
	// For demonstration purposes, we'll use a hardcoded check.
	exampleAuth := &ExampleAuthenticator{
		Users: map[string]string{
			"username": hashPassword("password123"),
		},
	}
	return exampleAuth.Authenticate(username, password)
}
// ExampleAuthenticator is an example implementation of Authenticator.
type ExampleAuthenticator struct {
	Users map[string]string // Map of usernames to hashed passwords
}

// Authenticate checks if the username and password match the stored credentials.
func (a *ExampleAuthenticator) Authenticate(username, password string) bool {
	hashedPassword, ok := a.Users[username]
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

// StructuredLogger is a structured logger interface.
type StructuredLogger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// LoggerAdapter adapts log.Logger to StructuredLogger.
type LoggerAdapter struct {
	Logger *log.Logger
}

// Infof logs an informational message.
func (l *LoggerAdapter) Infof(format string, args ...interface{}) {
	l.Logger.Printf("[INFO] "+format, args...)
}

// Errorf logs an error message.
func (l *LoggerAdapter) Errorf(format string, args ...interface{}) {
	l.Logger.Printf("[ERROR] "+format, args...)
}

// ExampleLogger is an example implementation of StructuredLogger.
type ExampleLogger struct{}

// Infof logs an informational message.
func (l *ExampleLogger) Infof(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

// Errorf logs an error message.
func (l *ExampleLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the Home Page!")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if authenticate(username, password) {
		sessionID := generateSessionID()
		setCookie(w, "session_id", sessionID)
		validSessions[sessionID] = time.Now().Add(24 * time.Hour)
		http.Redirect(w, r, "/profile", http.StatusFound)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session_id")
	if err != nil || !isValidSession(sessionID.Value) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	fmt.Fprintf(w, "Welcome to the Profile Page!")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, "session_id")
	http.Redirect(w, r, "/", http.StatusFound)
}

func generateSessionID() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.StdEncoding.EncodeToString(token)
}

func setCookie(w http.ResponseWriter, name, value string) {
	encoded, err := cookieHandler.Encode(name, value)
	if err == nil {
		cookie := &http.Cookie{
			Name:     name,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   3600 * 24,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, cookie)
	} else {
		log.Printf("Error setting cookie: %v", err)
	}
}

func clearCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

func hashPassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return ""
	}
	return string(hashedPassword)
}
