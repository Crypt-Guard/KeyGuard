"""Tests for CryptoEngine — KDF roundtrip, encrypt/decrypt."""

from __future__ import annotations

import secrets

import pytest

from keyguard.crypto.engine import CryptoEngine
from keyguard.crypto.formats import KEY_SIZE, SALT_SIZE
from keyguard.util.memory import SecureMemory


@pytest.fixture
def engine():
    # Use compat profile for fast tests
    return CryptoEngine({"time_cost": 3, "memory_cost": 65_536, "parallelism": 2})


class TestDeriveKeys:
    def test_roundtrip(self, engine):
        pw = SecureMemory("TestP@ssw0rd!")
        salt = secrets.token_bytes(SALT_SIZE)
        enc_key, hmac_key = engine.derive_keys(pw, salt)
        assert len(enc_key) == KEY_SIZE
        assert len(hmac_key) == KEY_SIZE
        assert enc_key != hmac_key

    def test_deterministic(self, engine):
        pw = SecureMemory("TestP@ssw0rd!")
        salt = secrets.token_bytes(SALT_SIZE)
        k1 = engine.derive_keys(SecureMemory("TestP@ssw0rd!"), salt)
        k2 = engine.derive_keys(SecureMemory("TestP@ssw0rd!"), salt)
        assert k1[0] == k2[0]
        assert k1[1] == k2[1]

    def test_different_salt_gives_different_keys(self, engine):
        pw = SecureMemory("TestP@ssw0rd!")
        k1 = engine.derive_keys(SecureMemory("TestP@ssw0rd!"), secrets.token_bytes(SALT_SIZE))
        k2 = engine.derive_keys(SecureMemory("TestP@ssw0rd!"), secrets.token_bytes(SALT_SIZE))
        assert k1[0] != k2[0]

    def test_empty_password_raises(self, engine):
        with pytest.raises(ValueError, match="Empty password"):
            engine.derive_keys(SecureMemory(b""), secrets.token_bytes(SALT_SIZE))


class TestEncryptDecrypt:
    def test_roundtrip(self, engine):
        key = secrets.token_bytes(KEY_SIZE)
        plaintext = b"hello world secrets"
        nonce, ct = engine.encrypt_data(key, plaintext)
        result = engine.decrypt_data(key, nonce, ct)
        assert result == plaintext

    def test_with_ad(self, engine):
        key = secrets.token_bytes(KEY_SIZE)
        plaintext = b"data"
        ad = b"associated"
        nonce, ct = engine.encrypt_data(key, plaintext, ad)
        assert engine.decrypt_data(key, nonce, ct, ad) == plaintext

    def test_tampered_ciphertext_fails(self, engine):
        from cryptography.exceptions import InvalidTag

        key = secrets.token_bytes(KEY_SIZE)
        nonce, ct = engine.encrypt_data(key, b"secret")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            engine.decrypt_data(key, nonce, bytes(tampered))

    def test_wrong_key_fails(self, engine):
        from cryptography.exceptions import InvalidTag

        key1 = secrets.token_bytes(KEY_SIZE)
        key2 = secrets.token_bytes(KEY_SIZE)
        nonce, ct = engine.encrypt_data(key1, b"secret")
        with pytest.raises(InvalidTag):
            engine.decrypt_data(key2, nonce, ct)


class TestHMAC:
    def test_verify(self, engine):
        key = secrets.token_bytes(KEY_SIZE)
        data = b"message"
        mac = engine.compute_hmac(key, data)
        assert engine.verify_hmac(key, data, mac)

    def test_wrong_mac_fails(self, engine):
        key = secrets.token_bytes(KEY_SIZE)
        data = b"message"
        mac = engine.compute_hmac(key, data)
        bad = bytearray(mac)
        bad[0] ^= 0xFF
        assert not engine.verify_hmac(key, data, bytes(bad))
