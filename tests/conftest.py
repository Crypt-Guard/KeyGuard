"""Shared test fixtures."""

from __future__ import annotations

import secrets
import struct
import json
import time
import tempfile
from pathlib import Path

import pytest

from keyguard.crypto.formats import (
    HEADER_V3_FMT,
    HEADER_V3_SIZE,
    HMAC_SIZE,
    KEY_SIZE,
    MAGIC_V3,
    NONCE_SIZE,
    PROTOCOL_VERSION_V3,
    SALT_SIZE,
)


@pytest.fixture
def tmp_dir(tmp_path):
    """A temporary directory for vault files."""
    return tmp_path


@pytest.fixture
def sample_password():
    """A valid master password that meets complexity requirements."""
    return "MyStr0ng!Pass#99"


@pytest.fixture
def weak_password():
    """A password that does NOT meet complexity requirements."""
    return "weak"


@pytest.fixture
def vault_dir(tmp_dir):
    """A directory with proper structure for vault operations."""
    vault_dir = tmp_dir / "vault_test"
    vault_dir.mkdir()
    return vault_dir


def build_v3_vault(password: str, entries: dict, vault_path: Path) -> None:
    """Helper: create a v3-format vault file for migration tests.

    *entries* is ``{name: password_str}``.
    """
    import argon2
    import argon2.low_level
    import hashlib
    import hmac as hmac_mod
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    salt = secrets.token_bytes(SALT_SIZE)
    now = time.time()

    # Default KDF params (compat profile for speed in tests)
    time_cost = 3
    memory_cost = 65_536
    parallelism = 2

    master_key = argon2.low_level.hash_secret_raw(
        password.encode(),
        salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_SIZE,
        type=argon2.Type.ID,
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=None,
        info=b"KeyGuard-3.0.1 key-split",
    )
    expanded = hkdf.derive(master_key)
    enc_key = expanded[:KEY_SIZE]
    hmac_key = expanded[KEY_SIZE:]

    header_bytes = struct.pack(
        HEADER_V3_FMT,
        PROTOCOL_VERSION_V3,
        1,  # counter
        salt,
        int(now),
        now,
    )

    header_hmac = hmac_mod.new(hmac_key, MAGIC_V3 + header_bytes, hashlib.sha256).digest()

    vault_data = {
        "entries": {
            name: {
                "name": name,
                "password": pwd,
                "metadata": {},
                "created": now,
                "modified": now,
            }
            for name, pwd in entries.items()
        },
        "order": list(entries.keys()),
    }
    plaintext = json.dumps(vault_data).encode("utf-8")

    ad = MAGIC_V3 + header_bytes + header_hmac
    cipher = ChaCha20Poly1305(enc_key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = cipher.encrypt(nonce, plaintext, ad)

    blob = MAGIC_V3 + header_bytes + header_hmac + nonce + ciphertext
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.write_bytes(blob)
