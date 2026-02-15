"""Tests for StorageBackend — atomic write, backup, restore, permissions."""

from __future__ import annotations

import os
import platform
from pathlib import Path

import pytest

from keyguard.crypto.formats import (
    HMAC_SIZE,
    MAGIC_V4,
    HEADER_V4_SIZE,
    PROTOCOL_VERSION_V4,
    SALT_SIZE,
    VaultHeaderV4,
    KDF_ARGON2ID,
    KDF_VERSION_19,
)
from keyguard.storage.backend import StorageBackend


@pytest.fixture
def backend(tmp_path):
    vault_path = tmp_path / "test_vault" / "vault.kg3"
    return StorageBackend(vault_path)


class TestAtomicWrite:
    def test_write_and_read(self, backend):
        data = b"hello world"
        backend.write_atomic(data)
        assert backend.read() == data

    def test_creates_backup_on_overwrite(self, backend):
        backend.write_atomic(b"first")
        backend.write_atomic(b"second")
        assert backend.backup_path.exists()
        assert backend.backup_path.read_bytes() == b"first"

    def test_exists(self, backend):
        assert not backend.exists()
        backend.write_atomic(b"data")
        assert backend.exists()

    def test_permissions_unix(self, backend):
        if platform.system() == "Windows":
            pytest.skip("Unix-only test")
        backend.write_atomic(b"data")
        mode = oct(backend.vault_path.stat().st_mode & 0o777)
        assert mode == "0o600"


class TestBackup:
    def _write_valid_v4(self, backend):
        """Write a minimal valid v4 vault blob."""
        import secrets
        import struct
        from keyguard.crypto.formats import HEADER_V4_FMT

        salt = secrets.token_bytes(SALT_SIZE)
        hdr_bytes = struct.pack(
            HEADER_V4_FMT,
            PROTOCOL_VERSION_V4,
            1,
            salt,
            0,
            0.0,
            KDF_ARGON2ID,
            KDF_VERSION_19,
            3,
            65536,
            2,
            32,
            0,
        )
        hmac_val = b"\x00" * HMAC_SIZE
        blob = MAGIC_V4 + hdr_bytes + hmac_val + b"\x00" * 20
        backend.write_atomic(blob)
        return blob

    def test_restore_backup(self, backend):
        blob = self._write_valid_v4(backend)
        # Overwrite vault
        backend.write_atomic(b"corrupted")
        assert backend.verify_backup_integrity()
        assert backend.restore_backup()
        assert backend.read() == blob

    def test_no_backup_returns_false(self, backend):
        assert not backend.verify_backup_integrity()
        assert not backend.restore_backup()

    def test_corrupted_backup_rejected(self, backend):
        backend.write_atomic(b"data")
        # backup now has b"data" which is not a valid vault
        assert not backend.verify_backup_integrity()
