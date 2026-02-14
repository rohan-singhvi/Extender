"""
util.py -- Shared helpers used across all modules.
"""

import subprocess
import logging

logger = logging.getLogger(__name__)


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """
    Run a shell command, capturing stdout and stderr.
    Raises RuntimeError on failure if check=True.
    """
    logger.debug(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr.strip()}")
    return result


def tool_exists(name: str) -> bool:
    """Check if a CLI tool is available on PATH."""
    return run(["which", name], check=False).returncode == 0


def human_bytes(b: int) -> str:
    """Format a byte count as human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"