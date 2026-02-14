"""
monitor.py — Monitor connected clients, signal strength, and throughput.
"""

import subprocess
import re
import time
import logging
from dataclasses import dataclass
from typing import Optional

from util import human_bytes

logger = logging.getLogger(__name__)


@dataclass
class ClientInfo:
    mac: str
    signal_dbm: Optional[int] = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    connected_seconds: int = 0
    ip: Optional[str] = None
    hostname: Optional[str] = None


@dataclass
class UpstreamStatus:
    ssid: Optional[str] = None
    signal_dbm: Optional[int] = None
    frequency_mhz: Optional[int] = None
    bitrate_mbps: Optional[float] = None
    channel: Optional[int] = None


def get_upstream_status(iface: str) -> UpstreamStatus:
    """Get signal strength and connection quality of the upstream link."""
    status = UpstreamStatus()

    result = subprocess.run(
        ["iw", "dev", iface, "link"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return status

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("SSID:"):
            status.ssid = line.split(":", 1)[1].strip()
        elif "signal:" in line:
            match = re.search(r"(-?\d+)\s*dBm", line)
            if match:
                status.signal_dbm = int(match.group(1))
        elif "freq:" in line:
            match = re.search(r"(\d+)", line)
            if match:
                status.frequency_mhz = int(match.group(1))
        elif "bitrate:" in line or "tx bitrate:" in line:
            match = re.search(r"([\d.]+)\s*MBit", line)
            if match:
                status.bitrate_mbps = float(match.group(1))

    return status


def get_connected_clients(ap_iface: str) -> list[ClientInfo]:
    """Get list of clients connected to the AP, with signal and traffic stats."""
    result = subprocess.run(
        ["iw", "dev", ap_iface, "station", "dump"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []

    clients = []
    current: Optional[ClientInfo] = None

    for line in result.stdout.splitlines():
        line = line.strip()

        station_match = re.match(r"Station\s+([0-9a-fA-F:]{17})", line)
        if station_match:
            if current:
                clients.append(current)
            current = ClientInfo(mac=station_match.group(1))
            continue

        if current is None:
            continue

        if "signal:" in line:
            match = re.search(r"(-?\d+)\s*dBm", line)
            if match:
                current.signal_dbm = int(match.group(1))
        elif "rx bytes:" in line:
            match = re.search(r"(\d+)", line)
            if match:
                current.rx_bytes = int(match.group(1))
        elif "tx bytes:" in line:
            match = re.search(r"(\d+)", line)
            if match:
                current.tx_bytes = int(match.group(1))
        elif "connected time:" in line:
            match = re.search(r"(\d+)", line)
            if match:
                current.connected_seconds = int(match.group(1))

    if current:
        clients.append(current)

    return clients


def enrich_with_dhcp(clients: list[ClientInfo], leases: list[dict]) -> None:
    """Cross-reference station list with DHCP leases to get IPs and hostnames."""
    lease_map = {l["mac"].lower(): l for l in leases}
    for client in clients:
        lease = lease_map.get(client.mac.lower())
        if lease:
            client.ip = lease.get("ip")
            client.hostname = lease.get("hostname")


def signal_bars(dbm: Optional[int]) -> str:
    """Convert dBm to a visual bar indicator."""
    if dbm is None:
        return "?"
    if dbm >= -50:
        return "████ (excellent)"
    elif dbm >= -60:
        return "███░ (good)"
    elif dbm >= -70:
        return "██░░ (fair)"
    elif dbm >= -80:
        return "█░░░ (weak)"
    else:
        return "░░░░ (very weak)"


def print_status(upstream_iface: str, ap_iface: str, leases: list[dict]) -> None:
    """Print a status dashboard to the terminal."""
    upstream = get_upstream_status(upstream_iface)
    clients = get_connected_clients(ap_iface)
    enrich_with_dhcp(clients, leases)

    print("\033[2J\033[H")  # Clear screen
    print("╔══════════════════════════════════════════════════╗")
    print("║           Wifi Extender — Status                ║")
    print("╠══════════════════════════════════════════════════╣")

    # Upstream
    print(f"║ Upstream: {upstream.ssid or '(unknown)':<39}║")
    print(f"║   Signal: {signal_bars(upstream.signal_dbm):<39}║")
    if upstream.signal_dbm is not None:
        print(f"║   dBm:    {upstream.signal_dbm:<39}║")
    if upstream.bitrate_mbps is not None:
        print(f"║   Rate:   {upstream.bitrate_mbps} Mbps{'':<28}║")
    if upstream.frequency_mhz:
        band = "5 GHz" if upstream.frequency_mhz > 3000 else "2.4 GHz"
        print(f"║   Band:   {band:<39}║")

    print("╠══════════════════════════════════════════════════╣")
    print(f"║ Connected clients: {len(clients):<30}║")

    if clients:
        print("╠──────────────────────────────────────────────────╣")
        for c in clients:
            name = c.hostname or c.ip or c.mac
            print(f"║  {name:<47}║")
            print(f"║    Signal: {signal_bars(c.signal_dbm):<38}║")
            print(f"║    Traffic: ↓{human_bytes(c.rx_bytes)} ↑{human_bytes(c.tx_bytes):<20}║")
            dur = time.strftime("%H:%M:%S", time.gmtime(c.connected_seconds))
            print(f"║    Connected: {dur:<35}║")
    else:
        print("║  (no clients connected)                          ║")

    print("╚══════════════════════════════════════════════════╝")
    print("  Press Ctrl+C to stop the repeater")