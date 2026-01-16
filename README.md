# HackLAN
A go utility to perform LAN attacks, currently it supports only arp spoofing but more attacks will be added in the future.

## Features

- **Network Scanning**: Fast ARP-based network discovery
- **ARP Spoofing**: Execute ARP spoofing attacks against one or all devices on the network

## Usage

### Command-Line Tool

```bash
#install the package 
go install github.com/qa5imm/hacklan@latest

# Run the interactive tool
hacklan
```

## How It Works

### Network Discovery

The tool performs comprehensive network reconnaissance:

1. **Interface Detection**: Automatically identifies the active network interface by simulating a route to the internet (8.8.8.8)
2. **Gateway Discovery**: Uses the system routing table to find the actual gateway for internet-bound traffic (via `go-netroute`)
3. **ARP Scanning**: 
   - Sends multiple rounds of ARP requests to all IPs in the subnet
   - Listens for ARP replies using packet capture
   - Performs 5 rounds with delays to discover devices that may be in power-saving mode
   - Maps IP addresses to MAC addresses
4. **Target Filtering**: Automatically excludes your machine and the gateway from the attackable device list

### ARP Poisoning

ARP (Address Resolution Protocol) poisoning exploits the lack of authentication in ARP:

1. **Normal Flow**: Device asks "Who has IP X?" → Device with IP X responds with its MAC address
2. **Poisoned Flow**: Attacker sends unsolicited ARP replies claiming to be the gateway
3. **Result**: Victim's ARP cache is poisoned, believing the attacker's MAC is the gateway

This tool performs **unidirectional poisoning**:
- Continuously tells the target: "Gateway is at attacker's MAC address"
- Target sends all internet-bound traffic to the attacker's MAC
- Without packet forwarding enabled, the attacker acts as a black hole
- Target loses internet connectivity as packets never reach the real gateway

**Attack Modes:**
- **Single Target**: Cuts off one specific device from the network
- **Mass Attack**: Simultaneously poisons all discovered devices (excluding self and gateway)
