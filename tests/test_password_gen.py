"""Tests for PasswordGenerator."""

from __future__ import annotations

import string

import pytest

from keyguard.crypto.engine import PasswordGenerator


class TestGenerate:
    def test_correct_length(self):
        pw = PasswordGenerator.generate(20, string.ascii_letters + string.digits)
        assert len(pw) == 20

    def test_only_charset_chars(self):
        charset = string.digits
        pw = PasswordGenerator.generate(50, charset)
        assert all(c in charset for c in pw)

    def test_empty_charset_raises(self):
        with pytest.raises(ValueError, match="Empty charset"):
            PasswordGenerator.generate(10, "")

    def test_zero_length_raises(self):
        with pytest.raises(ValueError, match="at least 1"):
            PasswordGenerator.generate(0, string.ascii_letters)


class TestEntropy:
    def test_positive_entropy(self):
        e = PasswordGenerator.calculate_entropy("abc", string.ascii_lowercase)
        assert e > 0

    def test_longer_is_more_entropy(self):
        e1 = PasswordGenerator.calculate_entropy("abc", string.ascii_lowercase)
        e2 = PasswordGenerator.calculate_entropy("abcdef", string.ascii_lowercase)
        assert e2 > e1

    def test_empty_returns_zero(self):
        assert PasswordGenerator.calculate_entropy("", string.ascii_letters) == 0.0


class TestPatterns:
    def test_keyboard_sequences_detected(self):
        assert PasswordGenerator._has_patterns("qwerty123")

    def test_triple_repeat_detected(self):
        assert PasswordGenerator._has_patterns("xxaaabbcc")

    def test_numeric_sequence_detected(self):
        assert PasswordGenerator._has_patterns("xx123yy")

    def test_clean_password_passes(self):
        assert not PasswordGenerator._has_patterns("Kx9!mP2@")
