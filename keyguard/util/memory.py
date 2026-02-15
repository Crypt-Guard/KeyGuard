"""Secure memory management: SecureMemory, FragmentedSecret, KeyObfuscator,
TimedExposure, PasswordTimeout."""

from __future__ import annotations

import ctypes
import logging
import platform
import secrets
import threading
import time
from typing import Optional, Union

logger = logging.getLogger("keyguard.memory")


# ---------------------------------------------------------------------------
#  SecureMemory
# ---------------------------------------------------------------------------
class SecureMemory:
    """Manages a bytearray in locked (non-swappable) memory with multi-pass wipe."""

    def __init__(self, data: Union[bytes, bytearray, str]):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._size = len(data)
        self._data = bytearray(data)
        self._locked = False
        self._protect_memory()

    # -- memory protection --------------------------------------------------
    def _protect_memory(self) -> None:
        if self._size == 0:
            return
        try:
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
            if platform.system() == "Windows":
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                if kernel32.VirtualLock(
                    ctypes.c_void_p(address), ctypes.c_size_t(self._size)
                ):
                    self._locked = True
                handle = kernel32.GetCurrentProcess()
                kernel32.SetProcessWorkingSetSize(handle, -1, -1)
            else:
                libc = ctypes.CDLL(None)
                if (
                    libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size))
                    == 0
                ):
                    self._locked = True
        except Exception as exc:
            logger.debug("Memory protection unavailable: %s", exc)

    # -- public API ---------------------------------------------------------
    def get_bytes(self) -> bytes:
        if not self._data:
            raise ValueError("Memory already cleared")
        return bytes(self._data)

    def clear(self) -> None:
        if not self._data:
            return
        try:
            patterns = [
                bytes([0xFF] * self._size),
                bytes([0x00] * self._size),
                bytes([0x55] * self._size),
                bytes([0xAA] * self._size),
                secrets.token_bytes(self._size),
                secrets.token_bytes(self._size),
                bytes([0x00] * self._size),
            ]
            for pat in patterns:
                self._data[:] = pat

            if self._locked:
                try:
                    address = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
                    if platform.system() == "Windows":
                        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                        k32.VirtualUnlock(
                            ctypes.c_void_p(address), ctypes.c_size_t(self._size)
                        )
                    else:
                        libc = ctypes.CDLL(None)
                        libc.munlock(
                            ctypes.c_void_p(address), ctypes.c_size_t(self._size)
                        )
                except Exception:
                    pass
        finally:
            self._data = bytearray()
            self._size = 0
            self._locked = False

    def __len__(self) -> int:
        return self._size

    def __del__(self):
        self.clear()

    @property
    def is_protected(self) -> bool:
        return self._locked


# ---------------------------------------------------------------------------
#  PasswordTimeout  (bug-fix: added threading.Lock)
# ---------------------------------------------------------------------------
class PasswordTimeout:
    """Wipes a SecureMemory after *timeout* seconds of inactivity."""

    def __init__(self, secure_memory: SecureMemory, timeout: int = 300):
        self._mem = secure_memory
        self._timeout = timeout
        self._timer: Optional[threading.Timer] = None
        self._destroyed = False
        self._lock = threading.Lock()
        self.reset()

    def _wipe(self):
        with self._lock:
            if not self._destroyed:
                self._mem.clear()
                self._destroyed = True
                logger.info("Master password destroyed by timeout")

    def reset(self):
        with self._lock:
            if self._destroyed:
                return
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(self._timeout, self._wipe)
            self._timer.daemon = True
            self._timer.start()

    def cancel(self):
        with self._lock:
            if self._timer:
                self._timer.cancel()
            if not self._destroyed:
                self._mem.clear()
                self._destroyed = True


# ---------------------------------------------------------------------------
#  FragmentedSecret
# ---------------------------------------------------------------------------
class FragmentedSecret:
    """Splits a secret into N XOR-masked fragments."""

    def __init__(self, data: Union[bytes, bytearray, str], parts: int = 3):
        b = data.encode() if isinstance(data, str) else bytes(data)
        ln = len(b)
        masks = [secrets.token_bytes(ln) for _ in range(parts - 1)]
        last = bytearray(b)
        for m in masks:
            for i in range(ln):
                last[i] ^= m[i]
        self._parts = [SecureMemory(m) for m in masks] + [SecureMemory(last)]

    def reconstruct(self) -> SecureMemory:
        ln = len(self._parts[-1])
        res = bytearray(self._parts[-1].get_bytes())
        for p in self._parts[:-1]:
            blk = p.get_bytes()
            for i in range(ln):
                res[i] ^= blk[i]
        return SecureMemory(res)

    def clear(self):
        for p in self._parts:
            p.clear()
        self._parts = []


# ---------------------------------------------------------------------------
#  KeyObfuscator  (bug-fix: added threading.Lock)
# ---------------------------------------------------------------------------
class KeyObfuscator:
    """Keeps derived key obfuscated; reveal only via TimedExposure."""

    def __init__(self, key: SecureMemory):
        self._key = key
        self._mask: Optional[SecureMemory] = None
        self._frags: Optional[FragmentedSecret] = None
        self._obfuscated = False
        self._lock = threading.Lock()

    def obfuscate(self):
        with self._lock:
            if self._key is None and self._obfuscated:
                return
            if self._obfuscated:
                plain_sm = self._deobfuscate_unlocked()
                if self._mask:
                    self._mask.clear()
                    self._mask = None
                if self._frags:
                    self._frags.clear()
                    self._frags = None
                self._key = plain_sm
                self._obfuscated = False

            if self._key is None or len(self._key) == 0:
                return

            kb = self._key.get_bytes()
            mask_b = secrets.token_bytes(len(kb))
            masked = bytearray(a ^ b for a, b in zip(kb, mask_b))
            self._mask = SecureMemory(mask_b)
            self._frags = FragmentedSecret(masked, 3)
            self._key.clear()
            self._obfuscated = True

    def deobfuscate(self) -> SecureMemory:
        with self._lock:
            return self._deobfuscate_unlocked()

    def _deobfuscate_unlocked(self) -> SecureMemory:
        if not self._obfuscated:
            return self._key
        masked_sb = self._frags.reconstruct()
        mask = self._mask.get_bytes()
        plain = bytearray(a ^ b for a, b in zip(masked_sb.get_bytes(), mask))
        masked_sb.clear()
        return SecureMemory(plain)

    def clear(self):
        with self._lock:
            if self._mask:
                self._mask.clear()
            if self._frags:
                self._frags.clear()
            if self._key:
                self._key.clear()
            self._obfuscated = False


# ---------------------------------------------------------------------------
#  TimedExposure  (bug-fix: added threading.Lock)
# ---------------------------------------------------------------------------
class TimedExposure:
    """Context manager that keeps a key in the clear only briefly."""

    def __init__(self, ko: KeyObfuscator, timeout: float = 0.5):
        self.ko = ko
        self.timeout = timeout
        self._plain: Optional[SecureMemory] = None
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def __enter__(self) -> SecureMemory:
        with self._lock:
            self._cancel_timer_unlocked()
            self._plain = self.ko.deobfuscate()
            return self._plain

    def _re_mask(self):
        with self._lock:
            if self._plain:
                self._plain.clear()
                self._plain = None
            try:
                self.ko.obfuscate()
            except (ValueError, AttributeError):
                pass

    def __exit__(self, exc_type, exc, tb):
        try:
            self._re_mask()
        finally:
            with self._lock:
                self._cancel_timer_unlocked()
                if self.timeout > 0 and exc_type is None:
                    self._timer = threading.Timer(self.timeout, self._re_mask)
                    self._timer.daemon = True
                    self._timer.start()

    def _cancel_timer_unlocked(self):
        if self._timer and self._timer.is_alive():
            self._timer.cancel()
            self._timer = None

    def cancel_timer(self):
        with self._lock:
            self._cancel_timer_unlocked()
