"""VaultManager — CRUD, open/save, and v3-to-v4 migration."""

from __future__ import annotations

import json
import logging
import secrets
import shutil
import struct
import time
from typing import Dict, List, Optional

from keyguard.config import Config
from keyguard.crypto.engine import CryptoEngine
from keyguard.crypto.formats import (
    HEADER_V3_FMT,
    HEADER_V3_SIZE,
    HEADER_V4_FMT,
    HEADER_V4_SIZE,
    HMAC_SIZE,
    KDF_ARGON2ID,
    KDF_VERSION_19,
    KEY_SIZE,
    MAGIC_LEN,
    MAGIC_V3,
    MAGIC_V4,
    NONCE_SIZE,
    PROTOCOL_VERSION_V3,
    PROTOCOL_VERSION_V4,
    SALT_SIZE,
    VaultHeaderV3,
    VaultHeaderV4,
    is_legacy_vault,
    parse_vault_header,
)
from keyguard.storage.backend import StorageBackend
from keyguard.util.memory import KeyObfuscator, SecureMemory, TimedExposure
from keyguard.util.rate_limit import RateLimiter
from keyguard.vault.models import VaultEntry

logger = logging.getLogger("keyguard.vault")


class VaultManager:
    """High-level vault operations."""

    def __init__(self, storage: StorageBackend, crypto: CryptoEngine):
        self.storage = storage
        self.crypto = crypto
        self.entries: Dict[str, VaultEntry] = {}
        self.entry_order: List[str] = []
        self.header: Optional[VaultHeaderV4] = None
        self._enc_ko: Optional[KeyObfuscator] = None
        self._hmac_ko: Optional[KeyObfuscator] = None
        self._modified = False
        self.rate_limiter = RateLimiter()

    # ------------------------------------------------------------------
    #  Create
    # ------------------------------------------------------------------
    def create_new(self, password: SecureMemory) -> None:
        pwd_str = password.get_bytes().decode("utf-8")
        if len(pwd_str) < Config.MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                f"Master password must be at least "
                f"{Config.MIN_MASTER_PASSWORD_LENGTH} characters"
            )

        has_upper = any(c.isupper() for c in pwd_str)
        has_lower = any(c.islower() for c in pwd_str)
        has_digit = any(c.isdigit() for c in pwd_str)
        has_special = any(not c.isalnum() for c in pwd_str)
        if sum([has_upper, has_lower, has_digit, has_special]) < 3:
            raise ValueError(
                "Master password must contain at least 3 character types "
                "(upper, lower, digit, symbol)"
            )

        salt = secrets.token_bytes(SALT_SIZE)
        try:
            enc_key, hmac_key = self.crypto.derive_keys(password, salt)
            self._enc_ko = KeyObfuscator(SecureMemory(enc_key))
            self._enc_ko.obfuscate()
            self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key))
            self._hmac_ko.obfuscate()

            self.header = VaultHeaderV4(
                version=PROTOCOL_VERSION_V4,
                counter=0,
                salt=salt,
                created=time.time(),
                modified=time.time(),
                kdf_algorithm=KDF_ARGON2ID,
                kdf_version=KDF_VERSION_19,
                kdf_time_cost=self.crypto.time_cost,
                kdf_memory_cost=self.crypto.memory_cost,
                kdf_parallelism=self.crypto.parallelism,
                kdf_hash_len=KEY_SIZE,
                reserved=0,
                hmac=b"\x00" * HMAC_SIZE,
            )
            self._save()
            logger.info("New vault created")
        finally:
            if "enc_key" in locals():
                ba = bytearray(enc_key)
                for i in range(len(ba)):
                    ba[i] = 0
            if "hmac_key" in locals():
                ba2 = bytearray(hmac_key)
                for i in range(len(ba2)):
                    ba2[i] = 0

    # ------------------------------------------------------------------
    #  Open  (supports v3 legacy + v4)
    # ------------------------------------------------------------------
    def open(self, password: SecureMemory) -> None:
        self.rate_limiter.check()
        try:
            data = self.storage.read()

            if len(data) < MAGIC_LEN:
                raise ValueError("File is not a valid vault")

            magic = data[:MAGIC_LEN]
            if magic == MAGIC_V3:
                self._open_v3(data, password)
            elif magic == MAGIC_V4:
                self._open_v4(data, password)
            else:
                raise ValueError("Unrecognised vault format")

            self.rate_limiter.reset()
            logger.info("Vault opened — %d entries", len(self.entries))

        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise
        except (IOError, OSError):
            raise
        except Exception:
            raise

    def _open_v3(self, data: bytes, password: SecureMemory) -> None:
        """Open a legacy v3 vault, then migrate to v4."""
        hdr = VaultHeaderV3.from_bytes(data[MAGIC_LEN:])
        if hdr.version != PROTOCOL_VERSION_V3:
            raise ValueError(f"Unsupported v3 vault version: {hdr.version}")

        # Use current engine params as fallback, but with v3 HKDF info
        enc_key, hmac_key = self.crypto.derive_keys(
            password, hdr.salt, hkdf_info=CryptoEngine.HKDF_INFO_V3
        )
        try:
            self._enc_ko = KeyObfuscator(SecureMemory(enc_key))
            self._enc_ko.obfuscate()
            self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key))
            self._hmac_ko.obfuscate()

            # Verify HMAC
            with TimedExposure(self._hmac_ko) as hk:
                header_hmac = self.crypto.compute_hmac(
                    hk.get_bytes(), data[: MAGIC_LEN + HEADER_V3_SIZE]
                )
            if not CryptoEngine.constant_time_compare(header_hmac, hdr.hmac):
                self._clear_keys()
                raise ValueError("Invalid header HMAC — wrong password or corrupted vault")

            # Decrypt
            encrypted = data[MAGIC_LEN + HEADER_V3_SIZE + HMAC_SIZE :]
            self._decrypt_entries(encrypted, data[: MAGIC_LEN + HEADER_V3_SIZE + HMAC_SIZE])

            # Migrate to v4: build v4 header with current KDF params
            self.header = VaultHeaderV4(
                version=PROTOCOL_VERSION_V4,
                counter=hdr.counter,
                salt=hdr.salt,
                created=hdr.created,
                modified=hdr.modified,
                kdf_algorithm=KDF_ARGON2ID,
                kdf_version=KDF_VERSION_19,
                kdf_time_cost=self.crypto.time_cost,
                kdf_memory_cost=self.crypto.memory_cost,
                kdf_parallelism=self.crypto.parallelism,
                kdf_hash_len=KEY_SIZE,
                reserved=0,
                hmac=b"\x00" * HMAC_SIZE,
            )

            # Re-derive keys with v4 HKDF info for the new vault format
            enc_key_v4, hmac_key_v4 = self.crypto.derive_keys(
                password, hdr.salt, hkdf_info=CryptoEngine.HKDF_INFO_V4
            )
            self._enc_ko.clear()
            self._hmac_ko.clear()
            self._enc_ko = KeyObfuscator(SecureMemory(enc_key_v4))
            self._enc_ko.obfuscate()
            self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key_v4))
            self._hmac_ko.obfuscate()

            # Backup original v3 file before overwriting
            v3_backup = self.storage.vault_path.parent / (
                self.storage.vault_path.name + f".v3backup-{int(time.time())}"
            )
            shutil.copy2(self.storage.vault_path, v3_backup)
            logger.info("v3 vault backed up to %s", v3_backup)

            # Re-save as v4
            self._save()
            logger.info("Vault migrated from v3 to v4")

        finally:
            ba = bytearray(enc_key)
            for i in range(len(ba)):
                ba[i] = 0
            ba2 = bytearray(hmac_key)
            for i in range(len(ba2)):
                ba2[i] = 0
            if "enc_key_v4" in locals():
                ba3 = bytearray(enc_key_v4)
                for i in range(len(ba3)):
                    ba3[i] = 0
            if "hmac_key_v4" in locals():
                ba4 = bytearray(hmac_key_v4)
                for i in range(len(ba4)):
                    ba4[i] = 0

    def _open_v4(self, data: bytes, password: SecureMemory) -> None:
        """Open a v4 vault (self-descriptive KDF params in header)."""
        hdr = VaultHeaderV4.from_bytes(data[MAGIC_LEN:])
        if hdr.version != PROTOCOL_VERSION_V4:
            raise ValueError(f"Unsupported v4 vault version: {hdr.version}")

        # Use KDF params from the header itself
        kdf_params = hdr.get_kdf_params()
        engine = CryptoEngine(kdf_params)
        enc_key, hmac_key = engine.derive_keys(password, hdr.salt)

        try:
            self._enc_ko = KeyObfuscator(SecureMemory(enc_key))
            self._enc_ko.obfuscate()
            self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key))
            self._hmac_ko.obfuscate()

            # Verify HMAC
            with TimedExposure(self._hmac_ko) as hk:
                header_hmac = engine.compute_hmac(
                    hk.get_bytes(), data[: MAGIC_LEN + HEADER_V4_SIZE]
                )
            if not CryptoEngine.constant_time_compare(header_hmac, hdr.hmac):
                self._clear_keys()
                raise ValueError("Invalid header HMAC — wrong password or corrupted vault")

            # Decrypt
            encrypted = data[MAGIC_LEN + HEADER_V4_SIZE + HMAC_SIZE :]
            self._decrypt_entries(encrypted, data[: MAGIC_LEN + HEADER_V4_SIZE + HMAC_SIZE])

            self.header = hdr
            # Keep the header's engine for future saves
            self.crypto = engine

        finally:
            ba = bytearray(enc_key)
            for i in range(len(ba)):
                ba[i] = 0
            ba2 = bytearray(hmac_key)
            for i in range(len(ba2)):
                ba2[i] = 0

    def _decrypt_entries(self, encrypted: bytes, ad: bytes) -> None:
        """Shared decryption logic for both v3 and v4."""
        if not encrypted:
            self.entries = {}
            self.entry_order = []
            return

        nonce = encrypted[:NONCE_SIZE]
        ciphertext = encrypted[NONCE_SIZE:]

        with TimedExposure(self._enc_ko) as ek:
            plaintext = self.crypto.decrypt_data(ek.get_bytes(), nonce, ciphertext, ad)

        try:
            vault_data = json.loads(plaintext.decode("utf-8"))

            if isinstance(vault_data, dict) and "entries" in vault_data:
                entries_data = vault_data["entries"]
                self.entry_order = vault_data.get("order", [])
            else:
                entries_data = vault_data
                self.entry_order = []

            self.entries = {
                name: VaultEntry.from_dict(entry) for name, entry in entries_data.items()
            }

            if not self.entry_order:
                self.entry_order = sorted(self.entries.keys())
        finally:
            pt_ba = bytearray(plaintext)
            for i in range(len(pt_ba)):
                pt_ba[i] = 0

    # ------------------------------------------------------------------
    #  Save (always v4)
    # ------------------------------------------------------------------
    def _save(self) -> None:
        vault_data = {
            "entries": {n: e.to_dict() for n, e in self.entries.items()},
            "order": self.entry_order,
        }
        plaintext = json.dumps(vault_data, indent=2).encode("utf-8")

        try:
            self.header.counter += 1
            self.header.modified = time.time()

            header_bytes = struct.pack(
                HEADER_V4_FMT,
                self.header.version,
                self.header.counter,
                self.header.salt,
                int(self.header.created),
                self.header.modified,
                self.header.kdf_algorithm,
                self.header.kdf_version,
                self.header.kdf_time_cost,
                self.header.kdf_memory_cost,
                self.header.kdf_parallelism,
                self.header.kdf_hash_len,
                self.header.reserved,
            )

            with TimedExposure(self._hmac_ko) as hk:
                self.header.hmac = self.crypto.compute_hmac(
                    hk.get_bytes(), MAGIC_V4 + header_bytes
                )

            ad = MAGIC_V4 + header_bytes + self.header.hmac

            with TimedExposure(self._enc_ko) as ek:
                nonce, ciphertext = self.crypto.encrypt_data(ek.get_bytes(), plaintext, ad)

            blob = MAGIC_V4 + header_bytes + self.header.hmac + nonce + ciphertext
            self.storage.write_atomic(blob)
            self._modified = False
        finally:
            if "plaintext" in locals():
                pt_ba = bytearray(plaintext)
                for i in range(len(pt_ba)):
                    pt_ba[i] = 0

    # ------------------------------------------------------------------
    #  CRUD
    # ------------------------------------------------------------------
    def add_entry(self, name: str, password: str, metadata: Optional[Dict] = None) -> None:
        if name in self.entries:
            raise ValueError(f"Entry '{name}' already exists")
        self.entries[name] = VaultEntry(name, password, metadata)
        if name not in self.entry_order:
            self.entry_order.append(name)
        self._modified = True
        self._save()

    def update_entry(
        self, name: str, password: str | None = None, metadata: Optional[Dict] = None
    ) -> None:
        if name not in self.entries:
            raise ValueError(f"Entry '{name}' not found")
        entry = self.entries[name]
        if password is not None:
            entry.set_password(password)
        if metadata is not None:
            entry.metadata = metadata
            entry.modified = time.time()
        self._modified = True
        self._save()

    def delete_entry(self, name: str) -> None:
        if name not in self.entries:
            raise ValueError(f"Entry '{name}' not found")
        self.entries[name]._pw_ko.clear()
        del self.entries[name]
        if name in self.entry_order:
            self.entry_order.remove(name)
        self._modified = True
        self._save()

    def list_entries(self) -> List[str]:
        """Return ordered entry names without mutating internal state."""
        ordered = [n for n in self.entry_order if n in self.entries]
        remaining = [n for n in self.entries if n not in self.entry_order]
        return ordered + sorted(remaining)

    def update_all_passwords(self, password_gen) -> int:
        if not self.entries:
            return 0
        from keyguard.config import CHARSETS

        count = 0
        for entry in self.entries.values():
            new_pw = password_gen.generate(20, CHARSETS["full"])
            entry.set_password(new_pw)
            count += 1
        self._modified = True
        self._save()
        logger.info("%d passwords bulk-updated", count)
        return count

    # ------------------------------------------------------------------
    #  Password change
    # ------------------------------------------------------------------
    def change_password(self, old_password: SecureMemory, new_password: SecureMemory) -> None:
        temp_enc_key, _ = self.crypto.derive_keys(old_password, self.header.salt)
        try:
            with TimedExposure(self._enc_ko) as ek:
                if not CryptoEngine.constant_time_compare(temp_enc_key, ek.get_bytes()):
                    raise ValueError("Current password is incorrect")
        finally:
            ba = bytearray(temp_enc_key)
            for i in range(len(ba)):
                ba[i] = 0

        new_salt = secrets.token_bytes(SALT_SIZE)
        enc_key, hmac_key = self.crypto.derive_keys(new_password, new_salt)
        try:
            self._enc_ko.clear()
            self._hmac_ko.clear()
            self._enc_ko = KeyObfuscator(SecureMemory(enc_key))
            self._enc_ko.obfuscate()
            self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key))
            self._hmac_ko.obfuscate()

            self.header.salt = new_salt
            self.header.kdf_time_cost = self.crypto.time_cost
            self.header.kdf_memory_cost = self.crypto.memory_cost
            self.header.kdf_parallelism = self.crypto.parallelism

            self._save()
            self.storage.cleanup_old_backups()
            logger.info("Master password changed")
        finally:
            ba = bytearray(enc_key)
            for i in range(len(ba)):
                ba[i] = 0
            ba2 = bytearray(hmac_key)
            for i in range(len(ba2)):
                ba2[i] = 0

    # ------------------------------------------------------------------
    #  Close / cleanup
    # ------------------------------------------------------------------
    def close(self) -> None:
        try:
            for entry in self.entries.values():
                entry._pw_ko.clear()
            self._clear_keys()
        except Exception as exc:
            logger.error("Error closing vault: %s", exc)
        finally:
            self.entries.clear()
            self.entry_order.clear()
            self._enc_ko = None
            self._hmac_ko = None
            self._modified = False

    def _clear_keys(self) -> None:
        if self._enc_ko:
            self._enc_ko.clear()
        if self._hmac_ko:
            self._hmac_ko.clear()
