"""
capabilities.py — Detect WiFi interfaces, check for STA+AP support, find upstream connection.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from util import run, tool_exists

logger = logging.getLogger(__name__)


@dataclass
class WifiInterface:
    name: str
    phy: str
    mac: str
    mode: str  # "managed", "AP", "monitor", etc.
    ssid: Optional[str] = None
    channel: Optional[int] = None
    supports_ap: bool = False
    supports_sta_ap: bool = False  # simultaneous STA + AP


@dataclass
class SystemCapabilities:
    interfaces: list[WifiInterface] = field(default_factory=list)
    upstream_interface: Optional[WifiInterface] = None
    can_virtual_ap: bool = False
    errors: list[str] = field(default_factory=list)


def check_required_tools() -> list[str]:
    """Return list of missing required tools."""
    required = ["iw", "hostapd", "dnsmasq", "iptables", "ip"]
    return [t for t in required if not tool_exists(t)]


def _parse_iw_dev() -> list[WifiInterface]:
    """Parse `iw dev` output to find all wireless interfaces."""
    result = run(["iw", "dev"], check=False)
    if result.returncode != 0:
        logger.error(f"iw dev failed: {result.stderr}")
        return []

    interfaces = []
    current_phy = None
    current_iface = None

    for line in result.stdout.splitlines():
        line = line.strip()

        phy_match = re.match(r"phy#(\d+)", line)
        if phy_match:
            current_phy = f"phy{phy_match.group(1)}"
            continue

        if line.startswith("Interface "):
            if current_iface:
                interfaces.append(current_iface)
            current_iface = WifiInterface(
                name=line.split()[1],
                phy=current_phy or "unknown",
                mac="",
                mode="unknown",
            )
        elif current_iface:
            if line.startswith("addr "):
                current_iface.mac = line.split()[1]
            elif line.startswith("type "):
                current_iface.mode = line.split()[1]
            elif line.startswith("ssid "):
                current_iface.ssid = line.split(maxsplit=1)[1]
            elif line.startswith("channel "):
                ch_match = re.match(r"channel (\d+)", line)
                if ch_match:
                    current_iface.channel = int(ch_match.group(1))

    if current_iface:
        interfaces.append(current_iface)

    return interfaces


def _check_phy_capabilities(phy: str) -> tuple[bool, bool]:
    """
    Check if a physical device supports AP mode and simultaneous STA+AP.
    Returns (supports_ap, supports_sta_ap).
    """
    result = run(["iw", phy, "info"], check=False)
    if result.returncode != 0:
        return False, False

    output = result.stdout
    supports_ap = bool(re.search(r"\*\s+AP\b", output))

    # Look for valid interface combinations that include both managed and AP.
    # We grab everything between "valid interface combinations" and the next
    # top-level section, then check if both keywords appear.
    supports_sta_ap = False
    combo_text = ""
    in_combo = False

    for line in output.splitlines():
        if "valid interface combinations" in line:
            in_combo = True
            continue
        if in_combo:
            # End of section: non-indented, non-empty line that isn't a combo entry
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("*") and not stripped.startswith("total"):
                break
            combo_text += " " + stripped

    if "managed" in combo_text and "AP" in combo_text:
        supports_sta_ap = True

    return supports_ap, supports_sta_ap


def _find_upstream(interfaces: list[WifiInterface]) -> Optional[WifiInterface]:
    """Find the interface currently connected to a WiFi network (station/managed mode)."""
    for iface in interfaces:
        if iface.mode == "managed" and iface.ssid:
            logger.info(f"Found upstream: {iface.name} connected to '{iface.ssid}' on channel {iface.channel}")
            return iface

    # Fallback: check for managed-mode interfaces with an IP and default route
    for iface in interfaces:
        if iface.mode == "managed":
            result = run(["ip", "route", "show", "dev", iface.name])
            if "default" in result.stdout:
                logger.info(f"Found upstream via routing table: {iface.name}")
                return iface

    return None


def detect_capabilities() -> SystemCapabilities:
    """
    Full system scan: find WiFi interfaces, check capabilities,
    identify the upstream connection.
    """
    caps = SystemCapabilities()

    # Check required tools
    missing = check_required_tools()
    if missing:
        caps.errors.append(f"Missing required tools: {', '.join(missing)}")
        caps.errors.append("Install with: sudo apt install " + " ".join(missing))
        return caps

    # Find interfaces
    caps.interfaces = _parse_iw_dev()
    if not caps.interfaces:
        caps.errors.append("No wireless interfaces found. Is WiFi hardware present?")
        return caps

    # Check each interface's phy capabilities
    checked_phys = {}
    for iface in caps.interfaces:
        if iface.phy not in checked_phys:
            checked_phys[iface.phy] = _check_phy_capabilities(iface.phy)
        iface.supports_ap, iface.supports_sta_ap = checked_phys[iface.phy]

    # Find upstream
    caps.upstream_interface = _find_upstream(caps.interfaces)
    if not caps.upstream_interface:
        caps.errors.append(
            "No interface is currently connected to a WiFi network. "
            "Connect to WiFi first, then run this tool."
        )

    # Determine if we can create a virtual AP
    caps.can_virtual_ap = any(i.supports_sta_ap for i in caps.interfaces)

    # Check if there's a second physical interface we could use for AP
    if not caps.can_virtual_ap and len(caps.interfaces) >= 2:
        ap_candidates = [
            i for i in caps.interfaces
            if i.supports_ap and i != caps.upstream_interface
        ]
        if ap_candidates:
            caps.can_virtual_ap = True

    if not caps.can_virtual_ap and not any(i.supports_ap for i in caps.interfaces):
        caps.errors.append(
            "No WiFi interface supports AP mode. "
            "You may need a USB WiFi adapter with AP support."
        )

    return caps


def print_capabilities(caps: SystemCapabilities) -> None:
    """Pretty-print detected capabilities."""
    print("\n=== Wifi Extender — System Capabilities ===\n")

    if caps.errors:
        for err in caps.errors:
            print(f"  [FAIL] {err}")
        print()

    for iface in caps.interfaces:
        status = f"  [{iface.name}] phy={iface.phy} mode={iface.mode}"
        if iface.ssid:
            status += f" ssid='{iface.ssid}'"
        if iface.channel:
            status += f" ch={iface.channel}"
        status += f" AP={'yes' if iface.supports_ap else 'no'}"
        status += f" STA+AP={'yes' if iface.supports_sta_ap else 'no'}"
        print(status)

    print()

    if caps.upstream_interface:
        print(f"  Upstream: {caps.upstream_interface.name} -> '{caps.upstream_interface.ssid}'")
    else:
        print("  Upstream: (none detected)")

    print(f"  Virtual AP possible: {'yes' if caps.can_virtual_ap else 'no'}")
    print()