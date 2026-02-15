"""CryptoEngine (KDF, AEAD, HMAC) and PasswordGenerator."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
import math
import secrets
import string
from typing import Tuple

import argon2
import argon2.low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from keyguard.crypto.formats import KEY_SIZE, NONCE_SIZE
from keyguard.util.memory import SecureMemory

logger = logging.getLogger("keyguard.crypto")


# ============================================================================
#  CryptoEngine
# ============================================================================
class CryptoEngine:
    """Argon2id KDF + ChaCha20-Poly1305 AEAD + HMAC-SHA256."""

    def __init__(self, kdf_params: dict | None = None):
        if kdf_params is None:
            from keyguard.config import Config

            kdf_params = Config.get_kdf_params()

        self.time_cost = kdf_params["time_cost"]
        self.memory_cost = kdf_params["memory_cost"]
        self.parallelism = kdf_params["parallelism"]

        logger.info(
            "CryptoEngine: Argon2id(t=%d, m=%d KiB, p=%d)",
            self.time_cost,
            self.memory_cost,
            self.parallelism,
        )

    # ------------------------------------------------------------------
    # HKDF info constants for different vault versions
    HKDF_INFO_V3 = b"KeyGuard-3.0.1 key-split"
    HKDF_INFO_V4 = b"KeyGuard-4.0 key-split"

    def derive_keys(
        self,
        password: SecureMemory,
        salt: bytes,
        hkdf_info: bytes | None = None,
    ) -> Tuple[bytes, bytes]:
        if len(password) == 0:
            raise ValueError("Empty password")

        if hkdf_info is None:
            hkdf_info = self.HKDF_INFO_V4

        try:
            master_key = argon2.low_level.hash_secret_raw(
                password.get_bytes(),
                salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=KEY_SIZE,
                type=argon2.Type.ID,
            )

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=KEY_SIZE * 2,
                salt=None,
                info=hkdf_info,
            )
            expanded = hkdf.derive(master_key)

            enc_key = expanded[:KEY_SIZE]
            hmac_key = expanded[KEY_SIZE:]
            return enc_key, hmac_key

        except MemoryError:
            raise RuntimeError(
                f"Not enough RAM for KDF ({self.memory_cost // 1024} MiB required). "
                "Try a lower KDF profile."
            )
        finally:
            if "master_key" in locals():
                ba = bytearray(master_key)
                for i in range(len(ba)):
                    ba[i] = 0
            if "expanded" in locals():
                ba2 = bytearray(expanded)
                for i in range(len(ba2)):
                    ba2[i] = 0

    # ------------------------------------------------------------------
    def encrypt_data(
        self, key: bytes, plaintext: bytes, associated_data: bytes = b""
    ) -> Tuple[bytes, bytes]:
        cipher = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt_data(
        self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b""
    ) -> bytes:
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, associated_data)

    # ------------------------------------------------------------------
    def compute_hmac(self, key: bytes, data: bytes) -> bytes:
        h = hmac_mod.new(key, data, hashlib.sha256)
        return h.digest()

    def verify_hmac(self, key: bytes, data: bytes, expected: bytes) -> bool:
        actual = self.compute_hmac(key, data)
        return hmac_mod.compare_digest(actual, expected)

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        return hmac_mod.compare_digest(a, b)


# ============================================================================
#  PasswordGenerator
# ============================================================================
class PasswordGenerator:
    """Secure random password generation with quality checks."""

    _entropy_cache: dict = {}

    @staticmethod
    def generate(length: int, charset: str) -> str:
        if length < 1:
            raise ValueError("Length must be at least 1")
        if not charset:
            raise ValueError("Empty charset")

        charset = "".join(sorted(set(charset)))

        while True:
            password = "".join(secrets.choice(charset) for _ in range(length))
            if PasswordGenerator._check_quality(password, charset):
                return password

    @staticmethod
    def _check_quality(password: str, charset: str) -> bool:
        if PasswordGenerator._has_patterns(password):
            return False

        if len(password) >= 8:
            char_types = {
                "lower": string.ascii_lowercase,
                "upper": string.ascii_uppercase,
                "digit": string.digits,
                "special": string.punctuation,
            }
            present_types = []
            for type_name, type_chars in char_types.items():
                if any(c in type_chars for c in charset):
                    if any(c in type_chars for c in password):
                        present_types.append(type_name)

            available_types = sum(
                1 for _, chars in char_types.items() if any(c in chars for c in charset)
            )
            if available_types >= 2 and len(present_types) < 2:
                return False

        return True

    @staticmethod
    def _has_patterns(password: str) -> bool:
        pwd_lower = password.lower()
        sequences = [
            "qwerty",
            "asdfgh",
            "zxcvbn",
            "123456",
            "654321",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
        ]
        for seq in sequences:
            if seq in pwd_lower or seq[::-1] in pwd_lower:
                return True

        for i in range(len(password) - 2):
            if password[i] == password[i + 1] == password[i + 2]:
                return True

        for i in range(len(password) - 2):
            chars = password[i : i + 3]
            if chars.isdigit():
                nums = [int(c) for c in chars]
                if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                    return True
                if nums[1] == nums[0] - 1 and nums[2] == nums[1] - 1:
                    return True
            if chars.isalpha():
                ords = [ord(c.lower()) for c in chars]
                if ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1:
                    return True
                if ords[1] == ords[0] - 1 and ords[2] == ords[1] - 1:
                    return True

        return False

    @staticmethod
    def calculate_entropy(password: str, charset: str) -> float:
        if not password or not charset:
            return 0.0

        cache_key = (len(password), len(set(charset)))
        if cache_key in PasswordGenerator._entropy_cache:
            return PasswordGenerator._entropy_cache[cache_key]

        charset_size = len(set(charset))
        entropy = len(password) * math.log2(charset_size)

        if len(PasswordGenerator._entropy_cache) > 100:
            PasswordGenerator._entropy_cache.clear()

        PasswordGenerator._entropy_cache[cache_key] = entropy
        return entropy
