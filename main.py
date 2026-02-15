#!/usr/bin/env python3
"""
wifi-extender — Software Wifi Extender for Linux.

Connects to an existing WiFi network and rebroadcasts it as a new access point,
extending signal range for other devices.

Requires: hostapd, dnsmasq, iw, iptables
Must be run as root.

Usage:
    sudo python3 main.py --ssid MyRepeater --passphrase secret123
    sudo python3 main.py --help
"""

import argparse
import getpass
import logging
import os
import sys
import time

from capabilities import detect_capabilities, print_capabilities
from interface_manager import InterfaceManager
from ap_manager import APManager
from dhcp_manager import DHCPManager
from nat_manager import NATManager
from monitor import print_status
from cleanup import CleanupManager


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Software Wifi Extender — rebroadcast your WiFi as a new AP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py
  sudo python3 main.py --ssid MyRepeater --passphrase hunter2
  sudo python3 main.py --upstream wlan0 --channel 11 --subnet 10.0.0.0/24
  sudo python3 main.py --check-only
        """,
    )

    p.add_argument("--upstream", "-u",
                    help="Upstream WiFi interface (default: auto-detect)")
    p.add_argument("--ap-interface", "-a",
                    help="AP interface name (default: <upstream>_ap)")
    p.add_argument("--ssid", "-s", default="WifiExtender",
                    help="SSID for the repeater AP (default: WifiExtender)")
    p.add_argument("--passphrase", "-p",
                    help="WPA2 passphrase (8-63 chars; prompted if not given)")
    p.add_argument("--channel", "-c", type=int, default=0,
                    help="WiFi channel (default: match upstream)")
    p.add_argument("--hw-mode", choices=["g", "a"], default="g",
                    help="'g' for 2.4GHz, 'a' for 5GHz (default: g)")
    p.add_argument("--country", default="US",
                    help="Country code for regulatory domain (default: US)")
    p.add_argument("--subnet", default="192.168.4.0/24",
                    help="Subnet for AP clients (default: 192.168.4.0/24)")
    p.add_argument("--no-nat", action="store_true",
                    help="Skip NAT rules (handle routing yourself)")
    p.add_argument("--no-monitor", action="store_true",
                    help="Don't show the live status dashboard")
    p.add_argument("--check-only", action="store_true",
                    help="Only check capabilities, don't start repeater")
    p.add_argument("--verbose", "-v", action="store_true",
                    help="Verbose/debug logging")

    return p.parse_args()


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def check_root() -> None:
    if os.geteuid() != 0:
        print("Error: This tool must be run as root (sudo).")
        print("  Usage: sudo python3 main.py [options]")
        sys.exit(1)


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger("main")

    check_root()

    # figure out the capabilities of the system and what interfaces we can use
    print("Scanning WiFi capabilities...")
    caps = detect_capabilities()
    print_capabilities(caps)

    if caps.errors:
        print("Cannot proceed due to errors above.")
        sys.exit(1)

    if args.check_only:
        sys.exit(0)

    # resolve the configuration based on capabilities and user input
    upstream_iface = args.upstream or caps.upstream_interface.name
    upstream_channel = caps.upstream_interface.channel or 6
    channel = args.channel if args.channel > 0 else upstream_channel
    ap_iface = args.ap_interface or f"{upstream_iface}_ap"

    # passphrase set up
    passphrase = args.passphrase
    if not passphrase:
        passphrase = getpass.getpass("Enter WPA2 passphrase for the AP (8-63 chars): ")
        if len(passphrase) < 8:
            print("Error: Passphrase must be at least 8 characters.")
            sys.exit(1)

    print(f"\nConfiguration:")
    print(f"   Upstream:    {upstream_iface} -> '{caps.upstream_interface.ssid}'")
    print(f"   AP:          {ap_iface} (SSID: {args.ssid})")
    print(f"   Channel:     {channel}")
    print(f"   Subnet:      {args.subnet}")
    print()

    # use cleanup manager to ensure we teardown properly on exit
    with CleanupManager() as cleanup:

        # interface
        print("Creating AP interface...")
        iface_mgr = InterfaceManager(upstream_iface, ap_iface, args.subnet)
        cleanup.register(iface_mgr)

        iface_mgr.create_virtual_interface()
        gateway_ip = iface_mgr.assign_ip()
        iface_mgr.disable_networkmanager_for_ap()
        iface_mgr.enable_ip_forward()

        # hostapd (Access Point)
        print("Starting access point...")
        ap_mgr = APManager(
            interface=ap_iface,
            ssid=args.ssid,
            passphrase=passphrase,
            channel=channel,
            hw_mode=args.hw_mode,
            country_code=args.country,
        )
        errors = ap_mgr.validate()
        if errors:
            for e in errors:
                print(f"  Error: {e}")
            sys.exit(1)
        cleanup.register(ap_mgr)
        ap_mgr.start()

        # dnsmasq (DHCP + DNS)
        print("Starting DHCP server...")
        dhcp_mgr = DHCPManager(
            interface=ap_iface,
            gateway=gateway_ip,
            subnet=args.subnet,
        )
        cleanup.register(dhcp_mgr)
        dhcp_mgr.start()

        # NAT
        if not args.no_nat:
            print("Configuring NAT...")
            nat_mgr = NATManager(upstream_iface, ap_iface, args.subnet)
            cleanup.register(nat_mgr)
            nat_mgr.apply_rules()

        # Run
        print("\nWifi Extender is running.")
        print(f"   SSID: {args.ssid}")
        print(f"   Connect your devices and enjoy extended WiFi range.")
        print(f"   Press Ctrl+C to stop.\n")

        # show status dashboard or just idle
        try:
            while True:
                if not args.no_monitor:
                    leases = dhcp_mgr.get_leases()
                    print_status(upstream_iface, ap_iface, leases)

                # Check that child processes are still alive
                if not ap_mgr.is_running:
                    print("Error: hostapd died unexpectedly!")
                    logger.error("hostapd process exited")
                    break
                if not dhcp_mgr.is_running:
                    print("Error: dnsmasq died unexpectedly!")
                    logger.error("dnsmasq process exited")
                    break

                time.sleep(3)

        except KeyboardInterrupt:
            pass  # Handled by CleanupManager's signal handler

    # CleanupManager.__exit__ handles teardown
    print("Goodbye!")


if __name__ == "__main__":
    main()