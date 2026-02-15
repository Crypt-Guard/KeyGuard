"""Tests for vault header serialisation (v3 and v4)."""

from __future__ import annotations

import secrets
import struct
import time

import pytest

from keyguard.crypto.formats import (
    HEADER_V3_FMT,
    HEADER_V3_SIZE,
    HEADER_V4_FMT,
    HEADER_V4_SIZE,
    HMAC_SIZE,
    KDF_ARGON2ID,
    KDF_VERSION_19,
    MAGIC_V3,
    MAGIC_V4,
    PROTOCOL_VERSION_V3,
    PROTOCOL_VERSION_V4,
    SALT_SIZE,
    VaultHeaderV3,
    VaultHeaderV4,
    is_legacy_vault,
    parse_vault_header,
)


class TestVaultHeaderV3:
    def _make(self):
        return VaultHeaderV3(
            version=PROTOCOL_VERSION_V3,
            counter=5,
            salt=secrets.token_bytes(SALT_SIZE),
            created=time.time(),
            modified=time.time(),
            hmac=secrets.token_bytes(HMAC_SIZE),
        )

    def test_roundtrip(self):
        hdr = self._make()
        raw = hdr.to_bytes()
        assert len(raw) == HEADER_V3_SIZE + HMAC_SIZE
        hdr2 = VaultHeaderV3.from_bytes(raw)
        assert hdr2.version == hdr.version
        assert hdr2.counter == hdr.counter
        assert hdr2.salt == hdr.salt
        assert hdr2.hmac == hdr.hmac

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            VaultHeaderV3.from_bytes(b"\x00" * 10)


class TestVaultHeaderV4:
    def _make(self):
        return VaultHeaderV4(
            version=PROTOCOL_VERSION_V4,
            counter=1,
            salt=secrets.token_bytes(SALT_SIZE),
            created=time.time(),
            modified=time.time(),
            kdf_algorithm=KDF_ARGON2ID,
            kdf_version=KDF_VERSION_19,
            kdf_time_cost=3,
            kdf_memory_cost=65_536,
            kdf_parallelism=2,
            kdf_hash_len=32,
            reserved=0,
            hmac=secrets.token_bytes(HMAC_SIZE),
        )

    def test_roundtrip(self):
        hdr = self._make()
        raw = hdr.to_bytes()
        assert len(raw) == HEADER_V4_SIZE + HMAC_SIZE
        hdr2 = VaultHeaderV4.from_bytes(raw)
        assert hdr2.version == PROTOCOL_VERSION_V4
        assert hdr2.kdf_time_cost == 3
        assert hdr2.kdf_memory_cost == 65_536
        assert hdr2.kdf_parallelism == 2
        assert hdr2.kdf_hash_len == 32

    def test_get_kdf_params(self):
        hdr = self._make()
        params = hdr.get_kdf_params()
        assert params["time_cost"] == 3
        assert params["memory_cost"] == 65_536
        assert params["parallelism"] == 2

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            VaultHeaderV4.from_bytes(b"\x00" * 10)


class TestParseVaultHeader:
    def test_detect_v3(self):
        hdr = VaultHeaderV3(
            version=PROTOCOL_VERSION_V3,
            counter=0,
            salt=b"\x00" * SALT_SIZE,
            created=0,
            modified=0,
            hmac=b"\x00" * HMAC_SIZE,
        )
        raw = MAGIC_V3 + hdr.to_bytes()
        parsed = parse_vault_header(raw)
        assert isinstance(parsed, VaultHeaderV3)

    def test_detect_v4(self):
        hdr = VaultHeaderV4(
            version=PROTOCOL_VERSION_V4,
            counter=0,
            salt=b"\x00" * SALT_SIZE,
            created=0,
            modified=0,
            kdf_algorithm=0,
            kdf_version=0x13,
            kdf_time_cost=3,
            kdf_memory_cost=65536,
            kdf_parallelism=2,
            kdf_hash_len=32,
            reserved=0,
            hmac=b"\x00" * HMAC_SIZE,
        )
        raw = MAGIC_V4 + hdr.to_bytes()
        parsed = parse_vault_header(raw)
        assert isinstance(parsed, VaultHeaderV4)

    def test_unknown_magic_raises(self):
        with pytest.raises(ValueError, match="Unrecognised"):
            parse_vault_header(b"XXX" + b"\x00" * 200)


class TestIsLegacyVault:
    def test_v3_is_legacy(self):
        assert is_legacy_vault(MAGIC_V3 + b"\x00" * 200)

    def test_v4_is_not_legacy(self):
        assert not is_legacy_vault(MAGIC_V4 + b"\x00" * 200)
