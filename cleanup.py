"""
cleanup.py — Centralized cleanup/teardown for all components.

Ensures that on any exit (Ctrl+C, SIGTERM, exception), we:
1. Stop hostapd
2. Stop dnsmasq
3. Remove iptables rules
4. Destroy virtual interface
5. Restore system settings
"""

import signal
import sys
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class CleanupManager:
    """
    Register components and ensure they're all torn down on exit.
    Components must implement a `.teardown()` or `.stop()` method.
    """

    def __init__(self):
        self._components: list = []
        self._original_sigint = None
        self._original_sigterm = None
        self._cleaned_up = False

    def register(self, component) -> None:
        """Register a component for cleanup. Order matters — LIFO teardown."""
        self._components.append(component)

    def install_signal_handlers(self) -> None:
        """Install SIGINT and SIGTERM handlers that trigger cleanup."""
        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._original_sigterm = signal.getsignal(signal.SIGTERM)

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame) -> None:
        sig_name = signal.Signals(signum).name
        logger.info(f"\nReceived {sig_name}, shutting down...")
        print(f"\nReceived {sig_name}, cleaning up...")
        self.cleanup()
        sys.exit(0)

    def cleanup(self) -> None:
        """Tear down all registered components in reverse order."""
        if self._cleaned_up:
            return
        self._cleaned_up = True

        logger.info("Starting cleanup...")

        for component in reversed(self._components):
            name = type(component).__name__
            try:
                if hasattr(component, "stop"):
                    logger.debug(f"Stopping {name}")
                    component.stop()
                if hasattr(component, "teardown"):
                    logger.debug(f"Tearing down {name}")
                    component.teardown()
            except Exception as e:
                logger.error(f"Error during cleanup of {name}: {e}")
                # Continue cleanup despite errors

        logger.info("Cleanup complete")
        print("Cleanup complete -- all services stopped, rules removed.")

    def __enter__(self):
        self.install_signal_handlers()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False  # Don't suppress exceptions