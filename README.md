# wifi-extender

A Linux-based software Wifi Extender that rebroadcasts your existing WiFi connection
as a new access point, extending signal range for other devices.

## How It Works

```
[Upstream WiFi Router]  ~~~wireless~~~  [YOUR LINUX BOX]  ~~~wireless~~~  [Client Devices]
                                         wlan0 (STA)       wlan0_ap (AP)
                                              \              /
                                            NAT + IP forwarding
```

Your machine connects to an existing WiFi network (station mode) on one interface,
and simultaneously runs a software access point on another (virtual or physical)
interface. Traffic from connected clients is NAT'd and forwarded to the upstream network.

## Requirements

### Hardware
- A Linux machine with WiFi (Raspberry Pi, laptop, etc.)
- WiFi chipset that supports **simultaneous STA + AP mode**, OR two WiFi interfaces
  - Check with: `iw list | grep -A 8 "valid interface combinations"`
  - Look for: `#{ managed } <= 1, #{ AP } <= 1, total <= 2`

### Software
- Python 3.8+
- `hostapd` — creates the software access point
- `dnsmasq` — DHCP server for connected clients
- `iw` — wireless interface management
- `iptables` — NAT and forwarding rules

Install on Debian/Ubuntu/Raspbian:
```bash
sudo apt update
sudo apt install hostapd dnsmasq iw iptables python3
```

## Quick Start

```bash
# Copy the project to your Pi / Linux box
cd wifi-extender

# Run the setup script (installs deps, disables conflicting services,
# checks hardware, optionally connects to upstream WiFi)
sudo ./setup.sh

# If setup passed, start the repeater
sudo python3 main.py --ssid "MyRepeater" --passphrase "supersecret"
```

Or do it manually:

```bash
# Run with defaults (interactive -- will ask for passphrase)
sudo python3 main.py

# Run with explicit config
sudo python3 main.py \
    --upstream wlan0 \
    --ssid "MyRepeater" \
    --passphrase "supersecret" \
    --channel 6 \
    --subnet 192.168.4.0/24

# See all options
sudo python3 main.py --help
```

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--upstream` | auto-detect | Upstream WiFi interface (station mode) |
| `--ap-interface` | auto-create virtual | AP interface name |
| `--ssid` | `WifiExtender` | SSID of the new access point |
| `--passphrase` | (prompted) | WPA2 passphrase (8-63 chars) |
| `--channel` | match upstream | WiFi channel |
| `--subnet` | `192.168.4.0/24` | Subnet for AP clients |
| `--hw-mode` | `g` | `a` for 5GHz, `g` for 2.4GHz |
| `--no-nat` | false | Skip NAT rules (if you handle routing yourself) |
| `--verbose` | false | Debug logging |

## Architecture

```
main.py                  CLI entry point, signal handling, orchestration
├── capabilities.py      Detect WiFi interfaces, check STA+AP support
├── interface_manager.py Create/destroy virtual interfaces, assign IPs
├── ap_manager.py        Generate hostapd.conf, start/stop hostapd
├── dhcp_manager.py      Generate dnsmasq.conf, start/stop dnsmasq
├── nat_manager.py       iptables rules for NAT + forwarding
├── monitor.py           Show connected clients, signal strength, throughput
└── cleanup.py           Teardown everything on exit (SIGINT/SIGTERM)
```

## Teardown

Press `Ctrl+C` or send SIGTERM. The tool will:
1. Stop hostapd and dnsmasq
2. Flush iptables rules it added
3. Remove the virtual AP interface (if it created one)
4. Restore ip_forward to its original value

## Troubleshooting

**"No interface supports AP mode"**
→ Your WiFi chipset/driver doesn't support AP mode. Get a USB dongle with
  RTL8812AU, MT7612U, or AR9271 chipset.

**"Cannot create virtual interface"**
→ Your chipset doesn't support simultaneous STA+AP. Use two physical interfaces.

**Clients connect but can't reach the internet**
→ Check that ip_forward is enabled: `cat /proc/sys/net/ipv4/ip_forward` should be `1`
→ Check iptables: `sudo iptables -t nat -L -v`
→ Check the upstream interface actually has connectivity: `ping -I wlan0 8.8.8.8`

**hostapd fails with "could not configure driver mode"**
→ Another process may be managing the interface. Stop NetworkManager for that interface:
  `nmcli device set wlan0_ap managed no`

## Target Platforms

- Raspberry Pi OS (primary target)
- Ubuntu / Debian
- Arch Linux
- Warning: Fedora (uses firewalld — may need `--no-nat` and manual firewall config)
- not for macOS (no hostapd, limited AP APIs)
- not for Windows