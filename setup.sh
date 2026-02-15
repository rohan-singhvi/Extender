#!/usr/bin/env bash
#
# setup.sh -- Provision a Raspberry Pi or Debian/Ubuntu machine
#             to run wifi-extender.
#
# Usage:
#   chmod +x setup.sh
#   sudo ./setup.sh
#
# What it does:
#   1. Checks this is a Debian-family system
#   2. Installs required packages (hostapd, dnsmasq, iw, iptables)
#   3. Stops and disables system-managed hostapd/dnsmasq
#      (we run our own instances, the system ones conflict)
#   4. Verifies WiFi hardware and STA+AP capability
#   5. Optionally connects to an upstream WiFi network
#   6. Runs a validation check
#
# This script is idempotent -- safe to run multiple times.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="/tmp/wifi-extender-setup.log"

# helpers 

log() {
    echo "[setup] $*"
    echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"
}

die() {
    echo "[setup] ERROR: $*" >&2
    echo "[$(date '+%H:%M:%S')] ERROR: $*" >> "$LOG_FILE"
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "This script must be run as root. Use: sudo $0"
    fi
}

# step functions

check_distro() {
    log "Checking distribution..."

    if [ ! -f /etc/os-release ]; then
        die "Cannot detect OS. This script supports Debian/Ubuntu/Raspbian."
    fi

    . /etc/os-release
    case "$ID" in
        debian|ubuntu|raspbian)
            log "Detected: $PRETTY_NAME"
            ;;
        *)
            # Might still work on derivatives, warn but continue
            log "WARNING: Detected $PRETTY_NAME -- not officially tested."
            log "         Continuing anyway, but package install may fail."
            ;;
    esac
}

install_packages() {
    log "Installing required packages..."

    local packages=(hostapd dnsmasq iw iptables python3 wireless-tools rfkill)
    local to_install=()

    for pkg in "${packages[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -eq 0 ]; then
        log "All required packages already installed."
        return
    fi

    log "Installing: ${to_install[*]}"
    apt-get update -qq >> "$LOG_FILE" 2>&1
    apt-get install -y -qq "${to_install[@]}" >> "$LOG_FILE" 2>&1
    log "Package installation complete."
}

disable_system_services() {
    # The system-installed hostapd and dnsmasq services will conflict
    # with the instances we spawn ourselves. Disable them so they don't
    # start on boot or hold ports/interfaces.
    log "Disabling system hostapd and dnsmasq services..."

    for svc in hostapd dnsmasq; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" >> "$LOG_FILE" 2>&1
            log "Stopped $svc"
        fi

        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            systemctl disable "$svc" >> "$LOG_FILE" 2>&1
            log "Disabled $svc from boot"
        fi

        # Mask prevents anything from accidentally starting them
        systemctl mask "$svc" >> "$LOG_FILE" 2>&1
    done

    log "System services disabled. wifi-extender will manage its own instances."
}

unblock_wifi() {
    # rfkill soft-blocks are a common gotcha on fresh Pi installs
    log "Checking for WiFi rfkill blocks..."

    if command -v rfkill &>/dev/null; then
        if rfkill list wifi 2>/dev/null | grep -q "Soft blocked: yes"; then
            log "WiFi is soft-blocked, unblocking..."
            rfkill unblock wifi
            sleep 1
        fi

        if rfkill list wifi 2>/dev/null | grep -q "Hard blocked: yes"; then
            die "WiFi is hardware-blocked. Check your physical WiFi switch."
        fi
    fi

    log "WiFi is unblocked."
}

check_wifi_hardware() {
    log "Checking WiFi hardware..."

    local ifaces
    ifaces=$(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}')

    if [ -z "$ifaces" ]; then
        die "No WiFi interfaces found. Is WiFi hardware present and driver loaded?"
    fi

    log "Found WiFi interface(s): $ifaces"

    # Check for STA+AP support on the first phy
    local phy
    phy=$(iw dev | grep -B1 "Interface" | head -1 | tr -d '[:space:]')

    if [ -z "$phy" ]; then
        log "WARNING: Could not determine phy device."
        return
    fi

    local phy_info
    phy_info=$(iw "$phy" info 2>/dev/null || true)

    if echo "$phy_info" | grep -q "AP"; then
        log "AP mode: supported"
    else
        log "WARNING: AP mode not detected. You may need a USB WiFi adapter."
    fi

    # Check simultaneous STA+AP
    local combos
    combos=$(echo "$phy_info" | sed -n '/valid interface combinations/,/^[^\t#*]/p')

    if echo "$combos" | grep -q "managed" && echo "$combos" | grep -q "AP"; then
        log "Simultaneous STA+AP: supported"
    else
        log "WARNING: Simultaneous STA+AP not detected."
        log "         You may need two WiFi interfaces (e.g. built-in + USB dongle)."
    fi
}

configure_networkmanager() {
    # If NetworkManager is running, tell it to leave our AP interface alone.
    # We do this preemptively for the default name pattern.
    local nm_conf="/etc/NetworkManager/NetworkManager.conf"

    if ! command -v nmcli &>/dev/null; then
        log "NetworkManager not installed, skipping NM config."
        return
    fi

    if ! systemctl is-active --quiet NetworkManager 2>/dev/null; then
        log "NetworkManager not running, skipping NM config."
        return
    fi

    log "Configuring NetworkManager to ignore AP interfaces..."

    # Add unmanaged pattern for *_ap interfaces if not already present
    local pattern="interface-name:*_ap"
    if grep -q "$pattern" "$nm_conf" 2>/dev/null; then
        log "NetworkManager already configured to ignore *_ap interfaces."
        return
    fi

    if grep -q '^\[keyfile\]' "$nm_conf" 2>/dev/null; then
        # Section exists, append to it
        sed -i "/^\[keyfile\]/a unmanaged-devices=$pattern" "$nm_conf"
    else
        # Add the section
        printf '\n[keyfile]\nunmanaged-devices=%s\n' "$pattern" >> "$nm_conf"
    fi

    systemctl restart NetworkManager >> "$LOG_FILE" 2>&1
    log "NetworkManager will now ignore *_ap interfaces."
}

setup_upstream_wifi() {
    # Check if already connected to WiFi
    local current_ssid
    current_ssid=$(iw dev 2>/dev/null | grep ssid | awk '{print $2}' | head -1)

    if [ -n "$current_ssid" ]; then
        log "Already connected to WiFi: $current_ssid"
        return
    fi

    log "Not currently connected to a WiFi network."

    # If running interactively, offer to connect
    if [ -t 0 ]; then
        echo ""
        read -rp "Connect to a WiFi network now? [y/N] " yn
        case "$yn" in
            [Yy]*)
                if command -v nmcli &>/dev/null; then
                    echo ""
                    echo "Available networks:"
                    nmcli dev wifi list 2>/dev/null | head -20
                    echo ""
                    read -rp "SSID: " ssid
                    read -rsp "Password: " pass
                    echo ""
                    nmcli dev wifi connect "$ssid" password "$pass" >> "$LOG_FILE" 2>&1 \
                        && log "Connected to $ssid" \
                        || die "Failed to connect to $ssid. Check credentials."
                else
                    echo "nmcli not available. Connect manually with wpa_supplicant or raspi-config."
                    echo "Example:"
                    echo "  sudo raspi-config  (System Options -> Wireless LAN)"
                    echo ""
                    echo "Then re-run this script."
                fi
                ;;
            *)
                log "Skipping WiFi connection. You'll need to connect before running the repeater."
                ;;
        esac
    else
        log "Non-interactive mode. Connect to WiFi manually before running the repeater."
    fi
}

run_validation() {
    log "Running validation..."

    cd "$SCRIPT_DIR"

    if [ ! -f main.py ]; then
        die "main.py not found in $SCRIPT_DIR. Run setup.sh from the wifi-extender directory."
    fi

    echo ""
    echo "--- Validation ---"
    python3 main.py --check-only
    local rc=$?

    if [ $rc -eq 0 ]; then
        echo ""
        echo "--- Setup Complete ---"
        echo ""
        echo "Everything looks good. To start the repeater:"
        echo ""
        echo "  cd $SCRIPT_DIR"
        echo "  sudo python3 main.py --ssid YourNetworkName --passphrase YourPassword"
        echo ""
        echo "To run tests first:"
        echo ""
        echo "  python3 tests.py"
        echo ""
    else
        echo ""
        echo "Validation found issues (see above). Fix them and run setup.sh again."
    fi

    return $rc
}

# main

main() {
    echo ""
    echo "wifi-extender setup"
    echo "==================="
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""

    check_root

    : > "$LOG_FILE"  # truncate log

    check_distro
    install_packages
    disable_system_services
    unblock_wifi
    check_wifi_hardware
    configure_networkmanager
    setup_upstream_wifi
    run_validation
}

main "$@"