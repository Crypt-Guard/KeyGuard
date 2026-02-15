"""Vault header formats (v3 legacy, v4 current), protocol constants, and migration helpers."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Union

# ============================================================================
#  Protocol constants
# ============================================================================
MAGIC_V3 = b"KG3"
MAGIC_V4 = b"KG4"
MAGIC_LEN = 3

SALT_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits (ChaCha20-Poly1305)
KEY_SIZE = 32  # 256 bits
HMAC_SIZE = 32  # 256 bits

# -- v3 header layout -------------------------------------------------------
#  version(2) + counter(2) + salt(32) + created(8) + modified(8) = 52 bytes
HEADER_V3_FMT = ">HH32sQd"
HEADER_V3_SIZE = struct.calcsize(HEADER_V3_FMT)  # 52
PROTOCOL_VERSION_V3 = 3

# -- v4 header layout -------------------------------------------------------
#  version(2) + counter(2) + salt(32) + created(8) + modified(8)
#  + kdf_algo(1) + kdf_ver(1) + kdf_time(4) + kdf_mem(4) + kdf_par(1)
#  + kdf_hashlen(1) + reserved(2)  = 69 bytes
HEADER_V4_FMT = ">HH32sQdBBIIBBH"
HEADER_V4_SIZE = struct.calcsize(HEADER_V4_FMT)  # 69
PROTOCOL_VERSION_V4 = 4

# KDF algorithm IDs
KDF_ARGON2ID = 0
KDF_VERSION_19 = 0x13  # Argon2 v19 (current)


# ============================================================================
#  VaultHeaderV3 (legacy, read-only)
# ============================================================================
@dataclass
class VaultHeaderV3:
    version: int
    counter: int
    salt: bytes
    created: float
    modified: float
    hmac: bytes

    def to_bytes(self) -> bytes:
        data = struct.pack(
            HEADER_V3_FMT,
            self.version,
            self.counter,
            self.salt,
            int(self.created),
            self.modified,
        )
        return data + self.hmac

    @classmethod
    def from_bytes(cls, data: bytes) -> VaultHeaderV3:
        if len(data) < HEADER_V3_SIZE + HMAC_SIZE:
            raise ValueError("Invalid v3 header")
        version, counter, salt, created, modified = struct.unpack(
            HEADER_V3_FMT, data[:HEADER_V3_SIZE]
        )
        hmac_val = data[HEADER_V3_SIZE : HEADER_V3_SIZE + HMAC_SIZE]
        return cls(
            version=version,
            counter=counter,
            salt=salt,
            created=float(created),
            modified=modified,
            hmac=hmac_val,
        )


# ============================================================================
#  VaultHeaderV4 (current, self-descriptive)
# ============================================================================
@dataclass
class VaultHeaderV4:
    version: int
    counter: int
    salt: bytes
    created: float
    modified: float
    kdf_algorithm: int  # KDF_ARGON2ID
    kdf_version: int  # KDF_VERSION_19
    kdf_time_cost: int
    kdf_memory_cost: int  # KiB
    kdf_parallelism: int
    kdf_hash_len: int  # 32
    reserved: int  # 0
    hmac: bytes

    def to_bytes(self) -> bytes:
        data = struct.pack(
            HEADER_V4_FMT,
            self.version,
            self.counter,
            self.salt,
            int(self.created),
            self.modified,
            self.kdf_algorithm,
            self.kdf_version,
            self.kdf_time_cost,
            self.kdf_memory_cost,
            self.kdf_parallelism,
            self.kdf_hash_len,
            self.reserved,
        )
        return data + self.hmac

    @classmethod
    def from_bytes(cls, data: bytes) -> VaultHeaderV4:
        if len(data) < HEADER_V4_SIZE + HMAC_SIZE:
            raise ValueError("Invalid v4 header")
        (
            version,
            counter,
            salt,
            created,
            modified,
            kdf_algo,
            kdf_ver,
            kdf_time,
            kdf_mem,
            kdf_par,
            kdf_hashlen,
            reserved,
        ) = struct.unpack(HEADER_V4_FMT, data[:HEADER_V4_SIZE])
        hmac_val = data[HEADER_V4_SIZE : HEADER_V4_SIZE + HMAC_SIZE]
        return cls(
            version=version,
            counter=counter,
            salt=salt,
            created=float(created),
            modified=modified,
            kdf_algorithm=kdf_algo,
            kdf_version=kdf_ver,
            kdf_time_cost=kdf_time,
            kdf_memory_cost=kdf_mem,
            kdf_parallelism=kdf_par,
            kdf_hash_len=kdf_hashlen,
            reserved=reserved,
            hmac=hmac_val,
        )

    def get_kdf_params(self) -> dict:
        """Extract KDF parameters from header for key derivation."""
        return {
            "time_cost": self.kdf_time_cost,
            "memory_cost": self.kdf_memory_cost,
            "parallelism": self.kdf_parallelism,
        }


# ============================================================================
#  Factory / detection
# ============================================================================
def parse_vault_header(data: bytes) -> Union[VaultHeaderV3, VaultHeaderV4]:
    """Parse the vault header from raw bytes (including the 3-byte magic)."""
    if len(data) < MAGIC_LEN:
        raise ValueError("Data too short to be a vault")

    magic = data[:MAGIC_LEN]
    payload = data[MAGIC_LEN:]

    if magic == MAGIC_V3:
        return VaultHeaderV3.from_bytes(payload)
    elif magic == MAGIC_V4:
        return VaultHeaderV4.from_bytes(payload)
    else:
        raise ValueError(f"Unrecognised vault magic: {magic!r}")


def is_legacy_vault(data: bytes) -> bool:
    """Quick check whether data starts with the v3 magic."""
    return data[:MAGIC_LEN] == MAGIC_V3
