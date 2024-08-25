package attachmentAttack

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// UploadFormHTML contains the HTML form for uploading attachments
const UploadFormHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
</head>
<body>
    <h1>Upload Attachment</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="attachment" required>
        <input type="submit" value="Upload">
    </form>
</body>
</html>
`

// MaxFileSize specifies the maximum allowed file size (in bytes)
const MaxFileSize = 10 << 20 // 10 MB

// AllowedFileTypes specifies the allowed file extensions
var AllowedFileTypes = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	// Add more allowed file types as needed
}

var (
	limiter      = rate.NewLimiter(rate.Limit(10), 1) // Allow 10 requests per second with a burst of 1
	requestCount = make(map[string]int)
	mutex        = &sync.Mutex{}
)

// UploadHandler handles file uploads securely
func UploadHandler(w http.ResponseWriter, r *http.Request) {
	// Perform rate limiting to prevent DoS attacks
	if !limiter.Allow() {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Increment request count for this client IP
	clientIP := r.RemoteAddr
	mutex.Lock()
	requestCount[clientIP]++
	mutex.Unlock()

	// Check if the request count exceeds the threshold
	if requestCount[clientIP] > 100 {
		http.Error(w, "Too many requests from this IP", http.StatusTooManyRequests)
		return
	}

	// Parse the multipart form
	err := r.ParseMultipartForm(MaxFileSize)
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Retrieve the file from the form
	file, handler, err := r.FormFile("attachment")
	if err != nil {
		http.Error(w, "Unable to retrieve file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Check if the file size exceeds the maximum limit
	if handler.Size > MaxFileSize {
		http.Error(w, "File size exceeds the limit", http.StatusBadRequest)
		return
	}

	// Check if the uploaded file's extension is allowed
	fileExt := filepath.Ext(handler.Filename)
	if !AllowedFileTypes[fileExt] {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	// Sanitize the filename to prevent directory traversal attacks
	safeFilename := filepath.Base(handler.Filename)
	if safeFilename == "." || safeFilename == "/" || strings.Contains(safeFilename, "..") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Create a new file on the server
	f, err := os.Create(filepath.Join("./uploads", safeFilename))
	if err != nil {
		http.Error(w, "Unable to create file", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// Copy the file data to the new file
	_, err = io.Copy(f, file)
	if err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}

	// Set appropriate content-disposition header
	w.Header().Set("Content-Disposition", "attachment; filename="+safeFilename)

	// Display success message
	fmt.Fprintf(w, "File uploaded successfully: %s", safeFilename)
}

// IndexHandler displays the upload form
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, UploadFormHTML)
}

func main() {
	// Create the uploads directory if it doesn't exist
	os.MkdirAll("./uploads", os.ModePerm)

	// Start a background goroutine to reset request counts every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			mutex.Lock()
			requestCount = make(map[string]int)
			mutex.Unlock()
		}
	}()

	// Register handlers
	http.HandleFunc("/", IndexHandler)
	http.HandleFunc("/upload", UploadHandler)

	// Start the server
	fmt.Println("Server listening on port 8080...")
	http.ListenAndServe(":8080", nil)
}
