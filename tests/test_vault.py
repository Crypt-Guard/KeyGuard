"""Tests for VaultManager — roundtrip, tamper, CRUD, entry order."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import pytest

from keyguard.crypto.engine import CryptoEngine
from keyguard.crypto.formats import HMAC_SIZE, KEY_SIZE, MAGIC_V4, SALT_SIZE
from keyguard.storage.backend import StorageBackend
from keyguard.util.memory import SecureMemory
from keyguard.vault.manager import VaultManager


COMPAT_KDF = {"time_cost": 3, "memory_cost": 65_536, "parallelism": 2}
GOOD_PASSWORD = "MyStr0ng!Pass#99"


@pytest.fixture
def vault_env(tmp_path):
    """Return (storage, crypto, vault_path)."""
    vault_path = tmp_path / "vdata" / "vault.kg3"
    storage = StorageBackend(vault_path)
    crypto = CryptoEngine(COMPAT_KDF)
    return storage, crypto, vault_path


class TestRoundtrip:
    def test_create_save_open_validate(self, vault_env):
        storage, crypto, _ = vault_env
        pw = SecureMemory(GOOD_PASSWORD)

        vm = VaultManager(storage, crypto)
        vm.create_new(pw)
        vm.add_entry("github", "gh_secret_123!")
        vm.add_entry("gitlab", "gl_secret_456!")
        vm.close()

        # Re-open
        vm2 = VaultManager(storage, crypto)
        vm2.open(SecureMemory(GOOD_PASSWORD))
        assert set(vm2.entries.keys()) == {"github", "gitlab"}
        assert vm2.entries["github"].get_password() == "gh_secret_123!"
        assert vm2.entries["gitlab"].get_password() == "gl_secret_456!"
        vm2.close()

    def test_wrong_password_fails(self, vault_env):
        storage, crypto, _ = vault_env
        vm = VaultManager(storage, crypto)
        vm.create_new(SecureMemory(GOOD_PASSWORD))
        vm.close()

        vm2 = VaultManager(storage, crypto)
        with pytest.raises(ValueError):
            vm2.open(SecureMemory("WrongP@ss123!"))


class TestTamper:
    def test_altered_bytes_fails(self, vault_env):
        storage, crypto, vault_path = vault_env
        vm = VaultManager(storage, crypto)
        vm.create_new(SecureMemory(GOOD_PASSWORD))
        vm.add_entry("test", "password123!")
        vm.close()

        # Tamper with the vault file
        data = bytearray(vault_path.read_bytes())
        # Flip a byte in the ciphertext area (well past the header)
        idx = min(len(data) - 1, 150)
        data[idx] ^= 0xFF
        vault_path.write_bytes(bytes(data))

        vm2 = VaultManager(storage, crypto)
        with pytest.raises((ValueError, Exception)):
            vm2.open(SecureMemory(GOOD_PASSWORD))


class TestCRUD:
    def test_add_and_delete(self, vault_env):
        storage, crypto, _ = vault_env
        vm = VaultManager(storage, crypto)
        vm.create_new(SecureMemory(GOOD_PASSWORD))
        vm.add_entry("a", "pass_a!")
        vm.add_entry("b", "pass_b!")
        assert "a" in vm.entries
        vm.delete_entry("a")
        assert "a" not in vm.entries
        assert "b" in vm.entries
        vm.close()

    def test_update_entry(self, vault_env):
        storage, crypto, _ = vault_env
        vm = VaultManager(storage, crypto)
        vm.create_new(SecureMemory(GOOD_PASSWORD))
        vm.add_entry("x", "old_pass!")
        vm.update_entry("x", password="new_pass!")
        assert vm.entries["x"].get_password() == "new_pass!"
        vm.close()

    def test_duplicate_add_raises(self, vault_env):
        storage, crypto, _ = vault_env
        vm = VaultManager(storage, crypto)
        vm.create_new(SecureMemory(GOOD_PASSWORD))
        vm.add_entry("dup", "pass!")
        with pytest.raises(ValueError, match="already exists"):
            vm.add_entry("dup", "pass2!")
        vm.close()


class TestEntryOrder:
    def test_list_entries_preserves_order(self, vault_env):
        storage, crypto, _ = vault_env
        vm = VaultManager(storage, crypto)
        vm.create_new(SecureMemory(GOOD_PASSWORD))
        vm.add_entry("c", "p1!")
        vm.add_entry("a", "p2!")
        vm.add_entry("b", "p3!")
        assert vm.list_entries() == ["c", "a", "b"]
        vm.close()

    def test_list_entries_does_not_mutate(self, vault_env):
        storage, crypto, _ = vault_env
        vm = VaultManager(storage, crypto)
        vm.create_new(SecureMemory(GOOD_PASSWORD))
        vm.add_entry("x", "p!")
        order_before = vm.entry_order.copy()
        # Call list_entries many times
        for _ in range(10):
            vm.list_entries()
        assert vm.entry_order == order_before
        vm.close()
