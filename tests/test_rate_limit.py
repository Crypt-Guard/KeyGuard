"""Tests for RateLimiter."""

from __future__ import annotations

import pytest

from keyguard.util.rate_limit import RateLimiter


class TestRateLimiter:
    def test_allows_first_attempt(self):
        rl = RateLimiter(max_attempts=5, delay_base=1)
        rl.check()  # Should not raise
        assert rl.attempts == 1

    def test_exceeds_max_attempts(self):
        rl = RateLimiter(max_attempts=2, delay_base=1)
        rl.check()
        rl.check()
        with pytest.raises(ValueError, match="Exceeded"):
            rl.check()

    def test_reset(self):
        rl = RateLimiter(max_attempts=2, delay_base=1)
        rl.check()
        rl.check()
        rl.reset()
        assert rl.attempts == 0
        rl.check()  # Should work again
