"""StorageBackend — atomic writes, backup/restore, file locking, permissions."""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import tempfile
import time
from pathlib import Path

from keyguard.config import Config
from keyguard.crypto.formats import (
    HMAC_SIZE,
    MAGIC_LEN,
    MAGIC_V3,
    MAGIC_V4,
    HEADER_V3_SIZE,
    HEADER_V4_SIZE,
    VaultHeaderV3,
    VaultHeaderV4,
    PROTOCOL_VERSION_V3,
    PROTOCOL_VERSION_V4,
)

logger = logging.getLogger("keyguard.storage")


class StorageBackend:
    """Vault file I/O with atomic writes, backup, and cross-platform locking."""

    def __init__(self, vault_path: Path):
        self.vault_path = vault_path
        self.backup_path = vault_path.parent / (vault_path.name + ".backup")
        self.lock_path = vault_path.parent / (vault_path.name + ".lock")
        self._lock_file = None

        # Ensure directory exists
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        if platform.system() != "Windows":
            try:
                os.chmod(self.vault_path.parent, 0o700)
            except OSError:
                pass

        self._acquire_lock()

    # -- locking ------------------------------------------------------------
    def _acquire_lock(self) -> None:
        try:
            self.lock_path.touch(mode=0o600, exist_ok=True)
            self._lock_file = open(self.lock_path, "r+b")
            if platform.system() != "Windows":
                import fcntl

                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError) as exc:
            if self._lock_file is not None:
                try:
                    self._lock_file.close()
                except OSError:
                    pass
                self._lock_file = None
            raise RuntimeError("Vault is already in use by another process") from exc

    def _release_lock(self) -> None:
        if self._lock_file:
            try:
                self._lock_file.close()
            except OSError:
                pass
            finally:
                self._lock_file = None
            try:
                self.lock_path.unlink()
            except OSError:
                pass

    # -- read / write -------------------------------------------------------
    def write_atomic(self, data: bytes) -> None:
        # 1. Back up current file
        if self.vault_path.exists():
            shutil.copy2(self.vault_path, self.backup_path)
            self._secure_permissions(self.backup_path)

        # 2. Write to temp file with restricted permissions via umask
        old_umask = None
        try:
            if os.name != "nt":
                old_umask = os.umask(0o077)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.vault_path.parent,
                prefix="kg_tmp_",
                suffix=".dat",
                delete=False,
            ) as tmp:
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
                temp_path = Path(tmp.name)
        finally:
            if old_umask is not None:
                os.umask(old_umask)

        # 3. Secure permissions on temp file
        self._secure_permissions(temp_path)

        # 4. Atomic rename
        temp_path.replace(self.vault_path)
        self._secure_permissions(self.vault_path)

        # 5. Cleanup orphaned temps
        self._cleanup_temp_files()
        logger.info("Vault saved successfully")

    def read(self) -> bytes:
        if not self.vault_path.exists():
            raise FileNotFoundError("Vault not found")

        size = self.vault_path.stat().st_size
        if size > Config.MAX_VAULT_SIZE:
            raise ValueError(f"Vault too large: {size} bytes (max {Config.MAX_VAULT_SIZE})")

        # Fix open permissions
        if platform.system() != "Windows":
            st = self.vault_path.stat()
            if st.st_mode & 0o077:
                logger.warning("Vault permissions too open, fixing...")
                os.chmod(self.vault_path, 0o600)

        return self.vault_path.read_bytes()

    def exists(self) -> bool:
        return self.vault_path.exists()

    # -- backup / restore ---------------------------------------------------
    def restore_backup(self) -> bool:
        if self.verify_backup_integrity():
            shutil.copy2(self.backup_path, self.vault_path)
            logger.info("Vault restored from backup")
            return True
        return False

    def verify_backup_integrity(self) -> bool:
        if not self.backup_path.exists():
            return False
        try:
            data = self.backup_path.read_bytes()
            magic = data[:MAGIC_LEN]
            if magic == MAGIC_V3:
                if len(data) < MAGIC_LEN + HEADER_V3_SIZE + HMAC_SIZE:
                    return False
                hdr = VaultHeaderV3.from_bytes(data[MAGIC_LEN:])
                return hdr.version == PROTOCOL_VERSION_V3
            elif magic == MAGIC_V4:
                if len(data) < MAGIC_LEN + HEADER_V4_SIZE + HMAC_SIZE:
                    return False
                hdr = VaultHeaderV4.from_bytes(data[MAGIC_LEN:])
                return hdr.version == PROTOCOL_VERSION_V4
            return False
        except Exception as exc:
            logger.error("Backup corrupted: %s", exc)
            return False

    def cleanup_old_backups(self) -> None:
        """Remove backups encrypted with old keys (after password change)."""
        try:
            if self.backup_path.exists():
                old_backup = self.backup_path.parent / (
                    self.backup_path.name + f".old-{int(time.time())}"
                )
                self.backup_path.rename(old_backup)

            cutoff = time.time() - (7 * 24 * 3600)
            for old in self.vault_path.parent.glob("*.backup.old-*"):
                try:
                    m = re.search(r"\.old-(\d+)$", old.name)
                    if m:
                        ts = int(m.group(1))
                        if ts < cutoff:
                            old.unlink()
                            logger.debug("Expired backup removed: %s", old)
                except (ValueError, OSError):
                    pass
        except Exception as exc:
            logger.warning("Backup cleanup error: %s", exc)

    # -- permissions --------------------------------------------------------
    def _secure_permissions(self, path: Path) -> None:
        try:
            if platform.system() == "Windows":
                try:
                    import win32security
                    import win32api
                    import ntsecuritycon as nsec

                    user_name = win32api.GetUserName()
                    user_sid, _, _ = win32security.LookupAccountName(None, user_name)
                    dacl = win32security.ACL()
                    dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION,
                        nsec.FILE_GENERIC_READ | nsec.FILE_GENERIC_WRITE | nsec.DELETE,
                        user_sid,
                    )
                    sd = win32security.SECURITY_DESCRIPTOR()
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(
                        str(path), win32security.DACL_SECURITY_INFORMATION, sd
                    )
                except ImportError:
                    os.chmod(path, 0o600)
            else:
                os.chmod(path, 0o600)
        except Exception as exc:
            logger.warning("Error setting permissions on %s: %s", path, exc)

    def _cleanup_temp_files(self) -> None:
        try:
            for tmp in self.vault_path.parent.glob("kg_tmp_*"):
                try:
                    if time.time() - tmp.stat().st_mtime > 3600:
                        tmp.unlink()
                except Exception:
                    pass
        except Exception:
            pass

    # -- lifecycle ----------------------------------------------------------
    def __del__(self):
        self._release_lock()
