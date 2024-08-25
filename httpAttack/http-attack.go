package httpAttack

import (
	"fmt"
	"net/http"
	"regexp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Example of setting a secure HTTP header
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Example of reading and sanitizing headers
	userAgent := sanitizeHeader(r.Header.Get("User-Agent"))

	// Respond with sanitized User-Agent header
	fmt.Fprintf(w, "User-Agent: %s", userAgent)
}

// sanitizeHeader sanitizes input to prevent HTTP header manipulation attacks
func sanitizeHeader(headerValue string) string {
	// Regular expression to match alphanumeric characters
	reg := regexp.MustCompile("[^a-zA-Z0-9]+")

	// Replace non-alphanumeric characters with an empty string
	sanitizedValue := reg.ReplaceAllString(headerValue, "")

	return sanitizedValue
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
