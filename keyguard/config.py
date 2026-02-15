"""Centralised configuration, KDF profiles, and config.ini I/O."""

from __future__ import annotations

import configparser
import logging
import multiprocessing
import os
import secrets
import string
import tempfile
import time
from pathlib import Path

import psutil

logger = logging.getLogger("keyguard.config")


# ============================================================================
#  KDF profiles  (compat / balanced / high)
# ============================================================================
KDF_PROFILES = {
    "compat": {
        "time_cost": 3,
        "memory_cost": 65_536,  # 64 MiB
        "parallelism": 2,
    },
    "balanced": {
        "time_cost": 4,
        "memory_cost": 262_144,  # 256 MiB
        "parallelism": min(4, multiprocessing.cpu_count() or 2),
    },
    "high": {
        "time_cost": 6,
        "memory_cost": 524_288,  # 512 MiB
        "parallelism": min(8, multiprocessing.cpu_count() or 2),
    },
}

# Security floor: never go below the compat profile
_KDF_FLOOR = KDF_PROFILES["compat"]


# ============================================================================
#  Character-set constants (password generation)
# ============================================================================
CHARSETS = {
    "numbers": string.digits,
    "letters": string.ascii_letters,
    "alphanumeric": string.ascii_letters + string.digits,
    "full": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
}
OPT_TO_KEY = {1: "numbers", 2: "letters", 3: "alphanumeric", 4: "full"}
MIN_TOTAL_BITS = 64
MIN_CLASS_BITS = 2


# ============================================================================
#  Config class
# ============================================================================
class Config:
    """Centralised settings."""

    # UI
    AUTO_HIDE_DELAY = 10_000  # ms
    MIN_MASTER_PASSWORD_LENGTH = 12
    DEFAULT_PASSWORD_LENGTH = 20
    MIN_GENERATED_PASSWORD_LENGTH = 4
    MAX_GENERATED_PASSWORD_LENGTH = 128
    CLIPBOARD_TIMEOUT = 15  # seconds

    # Security
    MAX_VAULT_SIZE = 10 * 1024 * 1024  # 10 MB
    SESSION_TIMEOUT = 300  # seconds

    # Performance
    ENTROPY_CACHE_SIZE = 100

    # ------------------------------------------------------------------
    #  KDF helpers
    # ------------------------------------------------------------------
    @staticmethod
    def get_kdf_params(data_dir: Path | None = None) -> dict:
        """Read KDF params from config.ini, enforcing a security floor."""
        if data_dir is None:
            from keyguard.paths import get_data_dir

            data_dir = get_data_dir()

        config_path = data_dir / "config.ini"
        try:
            if config_path.exists():
                cfg = configparser.ConfigParser()
                cfg.read(config_path)
                pars = {
                    "time_cost": cfg.getint(
                        "kdf", "time_cost", fallback=_KDF_FLOOR["time_cost"]
                    ),
                    "memory_cost": cfg.getint(
                        "kdf", "memory_cost", fallback=_KDF_FLOOR["memory_cost"]
                    ),
                    "parallelism": cfg.getint(
                        "kdf", "parallelism", fallback=_KDF_FLOOR["parallelism"]
                    ),
                }
                # Enforce security floor (compat profile)
                pars["memory_cost"] = max(pars["memory_cost"], _KDF_FLOOR["memory_cost"])
                pars["time_cost"] = max(pars["time_cost"], _KDF_FLOOR["time_cost"])
                pars["parallelism"] = max(pars["parallelism"], 2)
                return pars
        except Exception:
            pass
        return dict(_KDF_FLOOR)

    @staticmethod
    def calibrate_kdf(data_dir: Path, target_ms: int = 1000) -> None:
        """Select the highest KDF profile the hardware supports."""
        import argon2
        import argon2.low_level as low

        ram_total = psutil.virtual_memory().total
        ram_cap = ram_total * 3 // 4
        cores = multiprocessing.cpu_count() or 2

        salt = secrets.token_bytes(16)
        pw = b"benchmark"

        best_profile = "compat"
        best_params = dict(KDF_PROFILES["compat"])

        for name in ("compat", "balanced", "high"):
            profile = KDF_PROFILES[name]
            mem_bytes = profile["memory_cost"] * 1024
            if mem_bytes > ram_cap:
                logger.info("Skipping profile '%s': exceeds RAM cap", name)
                continue

            par = min(profile["parallelism"], cores)
            try:
                t0 = time.perf_counter()
                low.hash_secret_raw(
                    pw,
                    salt,
                    time_cost=profile["time_cost"],
                    memory_cost=profile["memory_cost"],
                    parallelism=par,
                    hash_len=32,
                    type=argon2.Type.ID,
                )
                dt = (time.perf_counter() - t0) * 1_000
                best_profile = name
                best_params = {
                    "time_cost": profile["time_cost"],
                    "memory_cost": profile["memory_cost"],
                    "parallelism": par,
                }
                logger.info(
                    "Profile '%s' OK: t=%d m=%d KiB p=%d  (%.0f ms)",
                    name,
                    profile["time_cost"],
                    profile["memory_cost"],
                    par,
                    dt,
                )
            except (MemoryError, OSError):
                logger.warning("Profile '%s' failed (not enough RAM)", name)
                break

        # Atomic write of config.ini
        _write_config(data_dir, best_params)
        logger.info("KDF calibrated: selected profile '%s'", best_profile)

    @staticmethod
    def config_exists(data_dir: Path) -> bool:
        return (data_dir / "config.ini").exists()


# ============================================================================
#  Atomic config writer
# ============================================================================
def _write_config(data_dir: Path, kdf_params: dict) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(data_dir, 0o700)
        except OSError:
            pass

    config_path = data_dir / "config.ini"
    cfg = configparser.ConfigParser()
    cfg["kdf"] = {
        "time_cost": str(kdf_params["time_cost"]),
        "memory_cost": str(kdf_params["memory_cost"]),
        "parallelism": str(kdf_params["parallelism"]),
    }

    fd = tempfile.NamedTemporaryFile(
        mode="w", dir=data_dir, prefix="cfg_tmp_", suffix=".ini", delete=False
    )
    try:
        cfg.write(fd)
        fd.flush()
        os.fsync(fd.fileno())
        fd.close()
        tmp = Path(fd.name)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        tmp.replace(config_path)
    except BaseException:
        fd.close()
        try:
            Path(fd.name).unlink(missing_ok=True)
        except OSError:
            pass
        raise
