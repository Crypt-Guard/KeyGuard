"""Tests for v3→v4 vault migration."""

from __future__ import annotations

from pathlib import Path

import pytest

from keyguard.crypto.engine import CryptoEngine
from keyguard.crypto.formats import MAGIC_V4, is_legacy_vault
from keyguard.storage.backend import StorageBackend
from keyguard.util.memory import SecureMemory
from keyguard.vault.manager import VaultManager
from tests.conftest import build_v3_vault

COMPAT_KDF = {"time_cost": 3, "memory_cost": 65_536, "parallelism": 2}
PASSWORD = "MyStr0ng!Pass#99"


class TestV3ToV4Migration:
    def test_open_v3_migrates_to_v4(self, tmp_path):
        vault_path = tmp_path / "mig" / "vault.kg3"
        build_v3_vault(PASSWORD, {"github": "secret123!"}, vault_path)
        assert is_legacy_vault(vault_path.read_bytes())

        storage = StorageBackend(vault_path)
        crypto = CryptoEngine(COMPAT_KDF)
        vm = VaultManager(storage, crypto)
        vm.open(SecureMemory(PASSWORD))

        # Entry should be intact
        assert "github" in vm.entries
        assert vm.entries["github"].get_password() == "secret123!"

        # File should now be v4
        assert vault_path.read_bytes()[:3] == MAGIC_V4
        vm.close()

    def test_v3_backup_created(self, tmp_path):
        vault_path = tmp_path / "mig2" / "vault.kg3"
        build_v3_vault(PASSWORD, {"test": "pw!"}, vault_path)

        storage = StorageBackend(vault_path)
        crypto = CryptoEngine(COMPAT_KDF)
        vm = VaultManager(storage, crypto)
        vm.open(SecureMemory(PASSWORD))

        # Check v3 backup was created
        backups = list(vault_path.parent.glob("*.v3backup-*"))
        assert len(backups) == 1
        assert is_legacy_vault(backups[0].read_bytes())
        vm.close()

    def test_migrated_vault_reopens(self, tmp_path):
        vault_path = tmp_path / "mig3" / "vault.kg3"
        build_v3_vault(
            PASSWORD,
            {"a": "pass_a!", "b": "pass_b!"},
            vault_path,
        )

        storage = StorageBackend(vault_path)
        crypto = CryptoEngine(COMPAT_KDF)
        vm = VaultManager(storage, crypto)
        vm.open(SecureMemory(PASSWORD))
        vm.close()
        # Release lock so we can reopen
        storage._release_lock()

        # Reopen the now-v4 vault
        storage2 = StorageBackend(vault_path)
        crypto2 = CryptoEngine(COMPAT_KDF)
        vm2 = VaultManager(storage2, crypto2)
        vm2.open(SecureMemory(PASSWORD))
        assert set(vm2.entries.keys()) == {"a", "b"}
        assert vm2.entries["a"].get_password() == "pass_a!"
        assert vm2.entries["b"].get_password() == "pass_b!"
        vm2.close()
        storage2._release_lock()
