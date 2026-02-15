"""Tests for SecureMemory, KeyObfuscator, and related utilities."""

from __future__ import annotations

import threading
import time

import pytest

from keyguard.util.memory import (
    FragmentedSecret,
    KeyObfuscator,
    PasswordTimeout,
    SecureMemory,
    TimedExposure,
)


class TestSecureMemory:
    def test_store_and_retrieve(self):
        sm = SecureMemory(b"secret")
        assert sm.get_bytes() == b"secret"
        assert len(sm) == 6

    def test_clear(self):
        sm = SecureMemory(b"secret")
        sm.clear()
        assert len(sm) == 0
        with pytest.raises(ValueError):
            sm.get_bytes()

    def test_from_string(self):
        sm = SecureMemory("hello")
        assert sm.get_bytes() == b"hello"

    def test_double_clear_safe(self):
        sm = SecureMemory(b"x")
        sm.clear()
        sm.clear()  # Should not raise


class TestFragmentedSecret:
    def test_reconstruct(self):
        fs = FragmentedSecret(b"my secret data", parts=3)
        sm = fs.reconstruct()
        assert sm.get_bytes() == b"my secret data"
        sm.clear()

    def test_clear(self):
        fs = FragmentedSecret(b"data")
        fs.clear()
        assert fs._parts == []


class TestKeyObfuscator:
    def test_obfuscate_deobfuscate(self):
        key = SecureMemory(b"a" * 32)
        ko = KeyObfuscator(key)
        ko.obfuscate()
        recovered = ko.deobfuscate()
        assert recovered.get_bytes() == b"a" * 32
        recovered.clear()
        ko.clear()

    def test_double_obfuscate(self):
        key = SecureMemory(b"b" * 32)
        ko = KeyObfuscator(key)
        ko.obfuscate()
        ko.obfuscate()  # Re-obfuscate should work
        recovered = ko.deobfuscate()
        assert recovered.get_bytes() == b"b" * 32
        recovered.clear()
        ko.clear()


class TestTimedExposure:
    def test_context_manager(self):
        key = SecureMemory(b"c" * 32)
        ko = KeyObfuscator(key)
        ko.obfuscate()
        with TimedExposure(ko, timeout=5.0) as sm:
            assert sm.get_bytes() == b"c" * 32
        ko.clear()


class TestPasswordTimeout:
    def test_wipe_on_cancel(self):
        sm = SecureMemory(b"password")
        pt = PasswordTimeout(sm, timeout=9999)
        pt.cancel()
        assert len(sm) == 0

    def test_timeout_wipes(self):
        sm = SecureMemory(b"password")
        pt = PasswordTimeout(sm, timeout=0.1)
        time.sleep(0.4)
        assert len(sm) == 0
