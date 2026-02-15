"""Platform hardening (non-debug) and SecurityWarning.

All debugger-detection code has been intentionally removed.
Only useful OS-level hardening remains (DEP, DLL restriction, core dump disable).
"""

from __future__ import annotations

import ctypes
import logging
import multiprocessing
import platform
import time
import warnings
from typing import Dict

logger = logging.getLogger("keyguard.harden")


# ---------------------------------------------------------------------------
#  SecurityWarning
# ---------------------------------------------------------------------------
class SecurityWarning(UserWarning):
    """Categorised security warning with auto-logging."""

    _warning_counts: Dict[str, int] = {
        "memory_protection": 0,
        "process_protection": 0,
        "crypto_fallback": 0,
        "file_permissions": 0,
        "other": 0,
    }

    def __init__(
        self,
        message: str,
        category: str = "other",
        severity: str = "medium",
        recommendation: str | None = None,
    ):
        super().__init__(message)
        self.category = category
        self.severity = severity
        self.recommendation = recommendation
        self.timestamp = time.time()

        if category in self._warning_counts:
            self._warning_counts[category] += 1
        else:
            self._warning_counts["other"] += 1

        self._auto_log()

    def _auto_log(self):
        msg = f"[{self.severity.upper()}] {self.category}: {self}"
        if self.recommendation:
            msg += f" | Recommendation: {self.recommendation}"
        level = {
            "critical": logging.CRITICAL,
            "high": logging.ERROR,
            "medium": logging.WARNING,
        }.get(self.severity, logging.INFO)
        logger.log(level, msg)

    @classmethod
    def get_security_metrics(cls) -> Dict[str, int]:
        return cls._warning_counts.copy()

    @classmethod
    def reset_metrics(cls):
        for key in cls._warning_counts:
            cls._warning_counts[key] = 0

    def __str__(self) -> str:
        base = super().__str__()
        return f"{base} [{self.category}]"


# ---------------------------------------------------------------------------
#  Convenience warning helpers
# ---------------------------------------------------------------------------
def warn_memory_protection(message: str, severity: str = "medium"):
    warnings.warn(SecurityWarning(message, "memory_protection", severity))


def warn_process_protection(message: str, severity: str = "medium"):
    warnings.warn(SecurityWarning(message, "process_protection", severity))


def warn_crypto_fallback(message: str, severity: str = "medium"):
    warnings.warn(SecurityWarning(message, "crypto_fallback", severity))


def warn_file_permissions(message: str, severity: str = "medium"):
    warnings.warn(SecurityWarning(message, "file_permissions", severity))


# ---------------------------------------------------------------------------
#  Platform hardening  (NO debugger detection)
# ---------------------------------------------------------------------------
def apply_platform_hardening() -> None:
    """Apply OS-level hardening without any debugger detection."""
    system = platform.system()
    if system == "Windows":
        _harden_windows()
    elif system in ("Linux", "Darwin"):
        _harden_unix()


def _harden_windows() -> None:
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # DEP (Data Execution Prevention)
        DEP_ENABLE = 0x00000001
        if hasattr(kernel32, "SetProcessDEPPolicy"):
            result = kernel32.SetProcessDEPPolicy(DEP_ENABLE)
            if result == 0:
                error = ctypes.get_last_error()
                if error not in (5, 50, 87):
                    logger.warning("Failed to enable DEP (error %d)", error)

        # DLL injection protection
        if hasattr(kernel32, "SetDllDirectoryW"):
            kernel32.SetDllDirectoryW("")
            logger.debug("DLL directory restricted to system")

    except Exception as exc:
        logger.error("Error applying Windows protections: %s", exc)
        warn_process_protection(
            "Some process protections could not be applied", severity="high"
        )


def _harden_unix() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        logger.debug("Core dumps disabled")
    except Exception as exc:
        logger.error("Error applying Unix protections: %s", exc)
        warn_process_protection(f"Error applying Unix protections: {exc}", severity="medium")


# ---------------------------------------------------------------------------
#  System requirements validation
# ---------------------------------------------------------------------------
def validate_system_requirements() -> None:
    import psutil

    avail = psutil.virtual_memory().available / (1024**3)
    if avail < 0.5:
        raise SystemError(f"Insufficient RAM: {avail:.1f} GB free (minimum 0.5 GB).")
    if (multiprocessing.cpu_count() or 1) < 2:
        warnings.warn("Only 1 CPU core – performance may be low.", RuntimeWarning)
