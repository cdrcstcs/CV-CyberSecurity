package sqlInjection

import(
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func main() {
	// Initialize the database connection
	initDB()

	// Setup HTTP routes with middleware
	http.HandleFunc("/login", withLogging(withAuth(handleLogin)))
	http.HandleFunc("/search", withLogging(withAuth(handleSearch)))

	// Start the HTTP server
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initDB() {
	// Initialize the database connection
	var err error
	db, err = sql.Open("mysql", "username:password@tcp(localhost:3306)/dbname")
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
}

func withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request received: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	}
}

func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate the user here (e.g., check session/token)
		if !authenticateUser(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func authenticateUser(r *http.Request) bool {
	// Implement your authentication logic here (e.g., check session/token)
	// For demonstration purposes, assume the user is always authenticated
	return true
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Perform input validation to prevent SQL injection
	if strings.ContainsAny(username, `'"`) || strings.ContainsAny(password, `'"`) {
		http.Error(w, "Invalid characters in username or password", http.StatusBadRequest)
		return
	}

	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&dbPassword)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Welcome, %s!", username)))
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("query")
	if query == "" {
		http.Error(w, "Search query is required", http.StatusBadRequest)
		return
	}

	// Perform input validation to prevent SQL injection
	if strings.ContainsAny(query, `'"`) {
		http.Error(w, "Invalid characters in search query", http.StatusBadRequest)
		return
	}

	rows, err := db.Query("SELECT id, title, description FROM articles WHERE title LIKE ?", "%"+query+"%")
	if err != nil {
		log.Printf("Error querying database: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var id int
		var title, description string
		err := rows.Scan(&id, &title, &description)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}
		results = append(results, fmt.Sprintf("%d - %s: %s", id, title, description))
	}

	w.WriteHeader(http.StatusOK)
	for _, result := range results {
		fmt.Fprintf(w, "%s\n", result)
	}
}
