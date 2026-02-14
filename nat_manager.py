"""
nat_manager.py — Manage iptables rules for NAT and forwarding between AP and upstream.
"""

import logging
from typing import Optional

from util import run

logger = logging.getLogger(__name__)


class NATManager:
    """
    Manages iptables rules to NAT traffic from the AP subnet
    out through the upstream WiFi interface.
    """

    def __init__(self, upstream_iface: str, ap_iface: str, subnet: str = "192.168.4.0/24"):
        self.upstream_iface = upstream_iface
        self.ap_iface = ap_iface
        self.subnet = subnet
        self._rules_applied = False

    def _save_existing_rules(self) -> Optional[str]:
        """Snapshot current iptables state for potential restore."""
        result = run(["iptables-save"], check=False)
        if result.returncode == 0:
            return result.stdout
        return None

    def apply_rules(self) -> None:
        """Apply NAT and forwarding rules."""
        if self._rules_applied:
            logger.warning("NAT rules already applied")
            return

        logger.info(f"Applying NAT rules: {self.ap_iface} -> {self.upstream_iface}")

        # 1. MASQUERADE — rewrite source IP for outgoing packets
        run([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", self.subnet,
            "-o", self.upstream_iface,
            "-j", "MASQUERADE",
        ])

        # 2. FORWARD — allow traffic from AP to upstream
        run([
            "iptables", "-A", "FORWARD",
            "-i", self.ap_iface,
            "-o", self.upstream_iface,
            "-j", "ACCEPT",
        ])

        # 3. FORWARD — allow established/related return traffic
        run([
            "iptables", "-A", "FORWARD",
            "-i", self.upstream_iface,
            "-o", self.ap_iface,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT",
        ])

        self._rules_applied = True
        logger.info("NAT rules applied successfully")

    def remove_rules(self) -> None:
        """Remove the NAT and forwarding rules we added."""
        if not self._rules_applied:
            return

        logger.info("Removing NAT rules...")

        # Remove in reverse order, using -D (delete) instead of -A (append)
        run([
            "iptables", "-D", "FORWARD",
            "-i", self.upstream_iface,
            "-o", self.ap_iface,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT",
        ], check=False)

        run([
            "iptables", "-D", "FORWARD",
            "-i", self.ap_iface,
            "-o", self.upstream_iface,
            "-j", "ACCEPT",
        ], check=False)

        run([
            "iptables", "-t", "nat", "-D", "POSTROUTING",
            "-s", self.subnet,
            "-o", self.upstream_iface,
            "-j", "MASQUERADE",
        ], check=False)

        self._rules_applied = False
        logger.info("NAT rules removed")

    def show_rules(self) -> str:
        """Show current relevant iptables rules for debugging."""
        output = []

        result = run(["iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n"], check=False)
        output.append("=== NAT (POSTROUTING) ===")
        output.append(result.stdout)

        result = run(["iptables", "-L", "FORWARD", "-v", "-n"], check=False)
        output.append("=== FORWARD ===")
        output.append(result.stdout)

        return "\n".join(output)

    def teardown(self) -> None:
        """Alias for remove_rules, used by the cleanup orchestrator."""
        self.remove_rules()