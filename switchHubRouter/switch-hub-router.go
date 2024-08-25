package switchHubRouter

import (
	"fmt"
)

// Switch represents a network switch
type Switch struct {
	name    string
	ports   int
	devices []string
}

// NewSwitch creates a new switch with the given name and number of ports
func NewSwitch(name string, ports int) *Switch {
	return &Switch{
		name:    name,
		ports:   ports,
		devices: make([]string, ports),
	}
}

// ConnectDevice connects a device to a switch port
func (s *Switch) ConnectDevice(device string) error {
	for i, port := range s.devices {
		if port == "" {
			s.devices[i] = device
			fmt.Printf("Device %s connected to port %d of switch %s\n", device, i+1, s.name)
			return nil
		}
	}
	return fmt.Errorf("no available ports on switch %s", s.name)
}

// Router represents a network router
type Router struct {
	name   string
	ports  int
	table  map[string]string // Routing table: maps destination IP to next hop
}

// NewRouter creates a new router with the given name and number of ports
func NewRouter(name string, ports int) *Router {
	return &Router{
		name:  name,
		ports: ports,
		table: make(map[string]string),
	}
}

// AddRoute adds a route to the router's routing table
func (r *Router) AddRoute(destinationIP, nextHop string) {
	r.table[destinationIP] = nextHop
}

// ForwardPacket forwards a packet to its destination
func (r *Router) ForwardPacket(destinationIP string) error {
	nextHop, found := r.table[destinationIP]
	if !found {
		return fmt.Errorf("no route found for destination IP %s", destinationIP)
	}
	fmt.Printf("Forwarding packet to %s via next hop %s\n", destinationIP, nextHop)
	return nil
}

// Hub represents a network hub (simple broadcast device)
type Hub struct {
	name    string
	ports   int
	devices []string
}

// NewHub creates a new hub with the given name and number of ports
func NewHub(name string, ports int) *Hub {
	return &Hub{
		name:    name,
		ports:   ports,
		devices: make([]string, ports),
	}
}

// ConnectDevice connects a device to a hub port
func (h *Hub) ConnectDevice(device string) error {
	for i, port := range h.devices {
		if port == "" {
			h.devices[i] = device
			fmt.Printf("Device %s connected to port %d of hub %s\n", device, i+1, h.name)
			return nil
		}
	}
	return fmt.Errorf("no available ports on hub %s", h.name)
}

// BroadcastPacket broadcasts a packet to all connected devices
func (h *Hub) BroadcastPacket(packet string) {
	fmt.Printf("Broadcasting packet '%s' to all devices connected to hub %s\n", packet, h.name)
	for _, device := range h.devices {
		if device != "" {
			fmt.Printf("Packet received by device %s\n", device)
		}
	}
}

func main() {
	// Create a switch
	switch1 := NewSwitch("Switch1", 8)

	// Connect devices to the switch
	switch1.ConnectDevice("DeviceA")
	switch1.ConnectDevice("DeviceB")
	switch1.ConnectDevice("DeviceC")

	// Create a router
	router1 := NewRouter("Router1", 4)

	// Add routes to the router's routing table
	router1.AddRoute("192.168.1.0", "192.168.1.1")
	router1.AddRoute("192.168.2.0", "192.168.2.1")

	// Forward packets using the router
	router1.ForwardPacket("192.168.1.100")
	router1.ForwardPacket("192.168.2.200")

	// Create a hub
	hub1 := NewHub("Hub1", 4)

	// Connect devices to the hub
	hub1.ConnectDevice("DeviceX")
	hub1.ConnectDevice("DeviceY")
	hub1.ConnectDevice("DeviceZ")

	// Broadcast a packet using the hub
	hub1.BroadcastPacket("Broadcast message")
}
