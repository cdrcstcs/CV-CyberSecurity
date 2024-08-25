package deviceSecurity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	_ "github.com/mattn/go-sqlite3" // Import SQLite driver
	"golang.org/x/crypto/bcrypt"
)

// Constants for authentication
const (
	saltSize      = 16
	tokenDuration = time.Hour * 24 // Token expiration duration
)

// Database connection
var db *sql.DB

// User represents a user in the system
type User struct {
	ID          string
	Username    string
	PasswordHash string
	Email       string
}

// Credentials represents user login credentials
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID string `json:"userID"`
	jwt.StandardClaims
}

func main() {
	initDB()
	defer db.Close()

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", handleRoot)
	r.Post("/login", handleLogin)
	r.With(authenticateMiddleware).Get("/profile", handleProfile)

	log.Println("Starting HTTPS server on port 443...")
	err := http.ListenAndServeTLS(":443", "server.crt", "server.key", r)
	if err != nil {
		log.Fatal("Error starting HTTPS server:", err)
	}
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "database.db")
	if err != nil {
		log.Fatal("Error opening database:", err)
	}

	createUserTableSQL := `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT
		);
	`
	_, err = db.Exec(createUserTableSQL)
	if err != nil {
		log.Fatal("Error creating user table:", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, HTTPS!"))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	user, err := getUserByUsername(credentials.Username)
	if err != nil || !verifyPassword(user.PasswordHash, credentials.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := generateJWTToken(user.ID)
	if err != nil {
		http.Error(w, "Error generating JWT token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+token)
	w.Write([]byte("Login successful"))
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)
	user, err := getUserByID(userID)
	if err != nil {
		http.Error(w, "Error fetching user profile", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"username": user.Username,
		"email":    user.Email,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		claims, err := verifyJWTToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getUserByUsername(username string) (*User, error) {
	user := &User{}
	row := db.QueryRow("SELECT * FROM users WHERE username = ?", username)
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("User not found")
	} else if err != nil {
		return nil, err
	}
	return user, nil
}

func getUserByID(userID string) (*User, error) {
	user := &User{}
	row := db.QueryRow("SELECT * FROM users WHERE id = ?", userID)
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("User not found")
	} else if err != nil {
		return nil, err
	}
	return user, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func hashPassword(password string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(append([]byte(password), salt...), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hashedPassword), nil
}

func verifyPassword(hashedPassword, password string) bool {
	hashedPasswordBytes, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false
	}
	err = bcrypt.CompareHashAndPassword(hashedPasswordBytes, []byte(password))
	return err == nil
}

func generateJWTToken(userID string) (string, error) {
	claims := &JWTClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenDuration).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("secret_key"))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func verifyJWTToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret_key"), nil
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
