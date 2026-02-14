"""
interface_manager.py — Create/destroy virtual AP interfaces, assign IPs.
"""

import logging
import ipaddress
from typing import Optional

from util import run

logger = logging.getLogger(__name__)


class InterfaceManager:
    """Manages the AP network interface lifecycle."""

    def __init__(
        self,
        upstream_iface: str,
        ap_iface: Optional[str] = None,
        subnet: str = "192.168.4.0/24",
    ):
        self.upstream_iface = upstream_iface
        self.ap_iface = ap_iface or f"{upstream_iface}_ap"
        self.subnet = ipaddress.IPv4Network(subnet, strict=True)
        self.gateway_ip = str(list(self.subnet.hosts())[0])  # e.g. 192.168.4.1
        self._created_virtual = False
        self._original_ip_forward: Optional[str] = None

    def create_virtual_interface(self) -> str:
        """
        Create a virtual AP interface on the same phy as the upstream interface.
        Returns the AP interface name.
        """
        logger.info(f"Creating virtual AP interface: {self.ap_iface}")

        # Check if it already exists
        result = run(["ip", "link", "show", self.ap_iface], check=False)
        if result.returncode == 0:
            logger.warning(f"Interface {self.ap_iface} already exists, removing first")
            self.destroy_virtual_interface()

        run(["iw", "dev", self.upstream_iface, "interface", "add",
              self.ap_iface, "type", "__ap"])
        self._created_virtual = True

        # Bring it up
        run(["ip", "link", "set", self.ap_iface, "up"])

        logger.info(f"Virtual interface {self.ap_iface} created and up")
        return self.ap_iface

    def assign_ip(self) -> str:
        """Assign the gateway IP to the AP interface. Returns the gateway IP."""
        prefix_len = self.subnet.prefixlen
        addr = f"{self.gateway_ip}/{prefix_len}"

        # Flush existing addresses
        run(["ip", "addr", "flush", "dev", self.ap_iface], check=False)

        run(["ip", "addr", "add", addr, "dev", self.ap_iface])
        logger.info(f"Assigned {addr} to {self.ap_iface}")
        return self.gateway_ip

    def enable_ip_forward(self) -> None:
        """Enable IPv4 forwarding, saving the original value for later restore."""
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            self._original_ip_forward = f.read().strip()

        if self._original_ip_forward != "1":
            run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            logger.info("Enabled IPv4 forwarding")
        else:
            logger.info("IPv4 forwarding already enabled")

    def disable_networkmanager_for_ap(self) -> None:
        """
        Tell NetworkManager to leave the AP interface alone.
        Fails silently if NM is not installed.
        """
        result = run(["which", "nmcli"], check=False)
        if result.returncode != 0:
            return

        run(["nmcli", "device", "set", self.ap_iface, "managed", "no"], check=False)
        logger.info(f"Told NetworkManager to ignore {self.ap_iface}")

    def destroy_virtual_interface(self) -> None:
        """Remove the virtual AP interface if we created it."""
        if self._created_virtual:
            logger.info(f"Removing virtual interface: {self.ap_iface}")
            run(["iw", "dev", self.ap_iface, "del"], check=False)
            self._created_virtual = False

    def restore_ip_forward(self) -> None:
        """Restore IPv4 forwarding to its original value."""
        if self._original_ip_forward is not None and self._original_ip_forward != "1":
            run(["sysctl", "-w", f"net.ipv4.ip_forward={self._original_ip_forward}"],
                 check=False)
            logger.info(f"Restored ip_forward to {self._original_ip_forward}")

    def teardown(self) -> None:
        """Full teardown — destroy interface and restore settings."""
        self.destroy_virtual_interface()
        self.restore_ip_forward()