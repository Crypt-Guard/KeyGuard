"""Cross-platform directory resolution and legacy migration."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import time
from pathlib import Path

logger = logging.getLogger("keyguard.paths")

_APP_NAME = "KeyGuard"
_APP_AUTHOR = "CryptGuard"


def get_data_dir() -> Path:
    """Return the platform-appropriate data directory (XDG on Linux)."""
    try:
        import platformdirs

        return Path(platformdirs.user_data_dir(_APP_NAME, _APP_AUTHOR))
    except ImportError:
        # Fallback without platformdirs
        return _fallback_data_dir()


def _fallback_data_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        return Path(base) / _APP_AUTHOR / _APP_NAME
    elif system == "Darwin":
        return Path.home() / "Library" / "Application Support" / _APP_NAME
    else:
        xdg = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
        return Path(xdg) / _APP_NAME


def get_legacy_dir() -> Path:
    """Return the old v3 data directory path."""
    return Path.home() / ".keyguard3"


def migrate_legacy_directory(data_dir: Path) -> bool:
    """Migrate from ~/.keyguard3 to the new platform directory.

    Returns True if migration was performed.
    """
    legacy = get_legacy_dir()
    if not legacy.is_dir():
        return False

    vault_in_new = data_dir / "vault.kg3"
    if vault_in_new.exists():
        logger.info("New data directory already has a vault; skipping migration")
        return False

    logger.info("Migrating from %s to %s", legacy, data_dir)
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        if platform.system() != "Windows":
            os.chmod(data_dir, 0o700)

        for item in legacy.iterdir():
            if item.is_file():
                dest = data_dir / item.name
                shutil.copy2(item, dest)
                if platform.system() != "Windows":
                    os.chmod(dest, 0o600)
                logger.debug("Copied %s -> %s", item, dest)

        # Rename legacy dir as breadcrumb
        ts = int(time.time())
        renamed = legacy.with_name(f".keyguard3.migrated-{ts}")
        legacy.rename(renamed)
        logger.info("Legacy directory renamed to %s", renamed)
        return True

    except Exception as exc:
        logger.error("Migration failed: %s", exc)
        return False


# -- path helpers -----------------------------------------------------------
def get_vault_path(data_dir: Path) -> Path:
    return data_dir / "vault.kg3"


def get_backup_path(data_dir: Path) -> Path:
    return data_dir / "vault.kg3.backup"


def get_lock_path(data_dir: Path) -> Path:
    return data_dir / "vault.kg3.lock"


def get_log_path(data_dir: Path) -> Path:
    return data_dir / "keyguard.log"


def get_config_path(data_dir: Path) -> Path:
    return data_dir / "config.ini"
