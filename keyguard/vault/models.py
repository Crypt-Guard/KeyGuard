"""VaultEntry — single password entry with obfuscated in-memory storage."""

from __future__ import annotations

import time
from typing import Dict, Optional

from keyguard.util.memory import KeyObfuscator, SecureMemory, TimedExposure


class VaultEntry:
    """A vault entry whose password is always kept in obfuscated SecureMemory."""

    def __init__(self, name: str, password: str, metadata: Optional[Dict] = None):
        self.name = name
        self.metadata = metadata or {}
        self.created = time.time()
        self.modified = time.time()

        sm = SecureMemory(password.encode())
        self._pw_ko = KeyObfuscator(sm)
        self._pw_ko.obfuscate()

    def get_password(self) -> str:
        with TimedExposure(self._pw_ko) as sm:
            return sm.get_bytes().decode()

    def set_password(self, new_pwd: str) -> None:
        sm_new = SecureMemory(new_pwd.encode())
        if self._pw_ko:
            self._pw_ko.clear()
        self._pw_ko = KeyObfuscator(sm_new)
        self._pw_ko.obfuscate()
        self.modified = time.time()

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "password": self.get_password(),
            "metadata": self.metadata,
            "created": self.created,
            "modified": self.modified,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> VaultEntry:
        entry = cls(data["name"], data["password"], data.get("metadata", {}))
        entry.created = data.get("created", time.time())
        entry.modified = data.get("modified", time.time())
        return entry
