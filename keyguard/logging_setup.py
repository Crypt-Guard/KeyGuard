"""Secure logging setup — no secrets in logs, rotation, OS-appropriate dir."""

from __future__ import annotations

import logging
import logging.handlers
import os
import platform
from pathlib import Path


class SecureFormatter(logging.Formatter):
    """Formatter that sanitises potentially sensitive arguments."""

    def format(self, record):
        if hasattr(record, "args") and record.args:
            safe = []
            for arg in record.args:
                if isinstance(arg, (bytes, bytearray)):
                    safe.append(f"<{len(arg)} bytes>")
                elif isinstance(arg, str) and len(arg) > 50:
                    safe.append(f"<{len(arg)} chars>")
                else:
                    safe.append(arg)
            record.args = tuple(safe)
        return super().format(record)


def setup_secure_logging(log_dir: Path) -> logging.Logger:
    """Configure the *keyguard* logger with rotation and safe formatting."""
    log_dir.mkdir(parents=True, exist_ok=True)
    if platform.system() != "Windows":
        try:
            os.chmod(log_dir, 0o700)
        except OSError:
            pass

    log_file = log_dir / "keyguard.log"

    formatter = SecureFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger("keyguard")
    root_logger.setLevel(logging.INFO)
    # avoid duplicate handlers on repeated calls
    if not root_logger.handlers:
        root_logger.addHandler(handler)
    root_logger.propagate = False

    try:
        if platform.system() != "Windows":
            os.chmod(log_file, 0o600)
    except OSError:
        pass

    return root_logger
