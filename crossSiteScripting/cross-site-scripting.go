package crossSiteScripting

import (
	"crypto/tls"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/didip/tollbooth"
	"github.com/gorilla/handlers"
	"github.com/sirupsen/logrus"
)

type AppConfig struct {
	CertFilePath string
	KeyFilePath  string
}

var config AppConfig
var logger *logrus.Logger

func init() {
	config.CertFilePath = os.Getenv("CERT_FILE_PATH")
	config.KeyFilePath = os.Getenv("KEY_FILE_PATH")

	if config.CertFilePath == "" || config.KeyFilePath == "" {
		log.Fatal("CERT_FILE_PATH or KEY_FILE_PATH environment variable not set")
	}

	// Initialize logger
	logger = logrus.New()
	// Log as JSON instead of the default ASCII formatter
	logger.SetFormatter(&logrus.JSONFormatter{})
	// Output to stdout instead of the default stderr
	logger.SetOutput(os.Stdout)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/submit", handleSubmit)

	handlerChain := secureHeadersMiddleware(logRequestMiddleware(errorHandlerMiddleware(inputValidationMiddleware(authenticationMiddleware(rateLimitMiddleware(mux))))))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      handlers.LoggingHandler(os.Stdout, handlerChain),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates:             loadCertificate(),
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			InsecureSkipVerify:       false, // Set to false for production use
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
	}

	http.HandleFunc("/", handleHome)

	logger.Info("Starting server...")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	limiter := tollbooth.NewLimiter(10, nil)
	return tollbooth.LimitHandler(limiter,next)
}

func handleSubmit(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("input")
	if input == "" || !validateInput(input) {
		http.Error(w, "Invalid input provided", http.StatusBadRequest)
		logger.Warn("Invalid input provided")
		return
	}
	sanitizedInput := html.EscapeString(input)
	fmt.Fprintf(w, "Escaped Output: %s", sanitizedInput)
	logger.Info("Handled form submission")
}

func validateInput(input string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9]+$", input)
	return match
}


func authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			logger.Warn("Unauthorized access")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAuthenticated(r *http.Request) bool {
	token := r.Header.Get("Authorization")
	return token == "valid_token"
}

func inputValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.FormValue("input")
		if input == "" || !validateInput(input) {
			http.Error(w, "Invalid input provided", http.StatusBadRequest)
			logger.Warn("Invalid input provided")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=()")
	fmt.Fprintf(w, "Home Page")
}

func loadCertificate() []tls.Certificate {
	cert, err := tls.LoadX509KeyPair(config.CertFilePath, config.KeyFilePath)
	if err != nil {
		logger.Fatal("Failed to load certificate and private key", err)
	}
	return []tls.Certificate{cert}
}

func secureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func logRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			logger.WithFields(logrus.Fields{
				"method":     r.Method,
				"requestURI": r.RequestURI,
				"duration":   time.Since(start),
				"remoteAddr": r.RemoteAddr,
			}).Info("Request processed")
		}()
		next.ServeHTTP(w, r)
	})
}


func errorHandlerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.WithField("error", err).Error("Internal Server Error")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
