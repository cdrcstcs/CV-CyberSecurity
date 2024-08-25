package clientServerSecurity

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"context"
)

// Constants
const (
	jwtSecretKey       = "secret_key"
	tokenExpiration    = time.Hour * 24 * 30 // Token expiration duration
	saltSize           = 16
	encryptedDataLabel = "ENCRYPTED:"
)

// Database connection
var db *sql.DB

// User represents a user in the system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // Hide password in JSON
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// Credentials represents user login credentials
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID int    `json:"userID"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

func main() {
	initDB()
	defer db.Close()

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Routes
	r.Post("/login", handleLogin)
	r.With(authenticateMiddleware).Get("/profile", handleProfile)
	r.NotFound(notFoundHandler)

	// HTTPS server configuration
	server := &http.Server{
		Addr:    ":443",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
	}

	log.Println("Starting HTTPS server on port 443...")
	err := server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		log.Fatal("Error starting HTTPS server:", err)
	}
}

// Initialize database connection
func initDB() {
	var err error
	cfg := mysql.Config{
		User:                 "username",
		Passwd:               "password",
		Net:                  "tcp",
		Addr:                 "localhost:3306",
		DBName:               "dbname",
		AllowNativePasswords: true,
	}

	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}

	// Create users table if not exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		password VARCHAR(100) NOT NULL,
		email VARCHAR(100) UNIQUE NOT NULL,
		role ENUM('admin', 'user') NOT NULL DEFAULT 'user'
	)`)
	if err != nil {
		log.Fatal("Error creating users table:", err)
	}
}

// Login handler
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	user, err := getUserByUsername(creds.Username)
	if err != nil || !verifyPassword(user.Password, creds.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	tokenString, err := generateJWTToken(user.ID, user.Role)
	if err != nil {
		http.Error(w, "Error generating JWT token", http.StatusInternalServerError)
		return
	}

	// Return JWT token in response
	w.Header().Set("Authorization", "Bearer "+tokenString)
	w.Write([]byte("Login successful"))
}

// Profile handler
func handleProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int)
	role := r.Context().Value("role").(string)
	user, err := getUserByID(userID)
	if err != nil {
		http.Error(w, "Error fetching user profile", http.StatusInternalServerError)
		return
	}

	// Check user role for access control
	if user.Role != role && role != "admin" {
		http.Error(w, "Unauthorized access", http.StatusForbidden)
		return
	}

	// Return user profile data
	jsonUser, err := json.Marshal(user)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonUser)
}

// Not found handler
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// Middleware for JWT authentication
func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := verifyJWTToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "role", claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Get user by username from database
func getUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, password, email, role FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Role)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Get user by ID from database
func getUserByID(userID int) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, password, email, role FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Role)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Verify password using bcrypt
func verifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// Generate JWT token
func generateJWTToken(userID int, role string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		Role:   role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenExpiration).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecretKey))
}

// Verify JWT token
func verifyJWTToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecretKey), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}
	return claims, nil
}
