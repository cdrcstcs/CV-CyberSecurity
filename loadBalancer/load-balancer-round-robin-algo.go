package loadBalancer

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

// BackendServer represents a backend server with an ID, address, and health status
type BackendServer struct {
	ID         int
	Address    string
	Health     bool
	HTTPClient *http.Client
}

// LoadBalancer manages the backend servers and distributes incoming requests
type LoadBalancer struct {
	servers []*BackendServer
	mutex   sync.RWMutex
}

// NewBackendServer creates a new backend server with the given ID and address
func NewBackendServer(id int, address string) *BackendServer {
	return &BackendServer{
		ID:         id,
		Address:    address,
		Health:     true,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// AddServer adds a new backend server to the load balancer
func (lb *LoadBalancer) AddServer(server *BackendServer) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	lb.servers = append(lb.servers, server)
}

// RemoveServer removes a backend server from the load balancer
func (lb *LoadBalancer) RemoveServer(server *BackendServer) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	for i, s := range lb.servers {
		if s == server {
			lb.servers = append(lb.servers[:i], lb.servers[i+1:]...)
			break
		}
	}
}

// GetHealthyServers returns a list of healthy backend servers
func (lb *LoadBalancer) GetHealthyServers() []*BackendServer {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	var healthyServers []*BackendServer
	for _, server := range lb.servers {
		if server.Health {
			healthyServers = append(healthyServers, server)
		}
	}
	return healthyServers
}

// SelectServer selects a backend server using a simple round-robin algorithm
func (lb *LoadBalancer) SelectServer() *BackendServer {
	healthyServers := lb.GetHealthyServers()
	if len(healthyServers) == 0 {
		return nil
	}
	return healthyServers[rand.Intn(len(healthyServers))]
}

// handleRequest handles incoming HTTP requests by selecting a backend server and proxying the request
func (lb *LoadBalancer) handleRequest(w http.ResponseWriter, r *http.Request) {
	server := lb.SelectServer()
	if server == nil {
		http.Error(w, "No backend servers available", http.StatusServiceUnavailable)
		return
	}
	// Proxy the request to the selected backend server
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   server.Address,
	})
	proxy.ServeHTTP(w, r)
}

func main() {
	// Create a new load balancer
	loadBalancer := &LoadBalancer{}

	// Add backend servers to the load balancer
	loadBalancer.AddServer(NewBackendServer(1, "backend1:8080"))
	loadBalancer.AddServer(NewBackendServer(2, "backend2:8080"))
	loadBalancer.AddServer(NewBackendServer(3, "backend3:8080"))

	// Start a health check routine to periodically check the backend servers' health
	go loadBalancer.HealthCheckRoutine()

	// Create an HTTP server to handle incoming requests
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(loadBalancer.handleRequest),
	}

	// Start the HTTP server
	log.Println("Load balancer started on port 8080")
	log.Fatal(server.ListenAndServe())
}

// HealthCheckRoutine periodically checks the health of backend servers and updates their status
func (lb *LoadBalancer) HealthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		lb.mutex.Lock()
		for _, server := range lb.servers {
			healthURL := fmt.Sprintf("http://%s/health", server.Address)
			resp, err := server.HTTPClient.Get(healthURL)
			if err != nil || resp.StatusCode != http.StatusOK {
				server.Health = false
			} else {
				server.Health = true
			}
			resp.Body.Close()
		}
		lb.mutex.Unlock()
	}
}
