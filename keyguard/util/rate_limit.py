"""Rate limiter with exponential backoff for brute-force protection."""

from __future__ import annotations

import logging
import time

logger = logging.getLogger("keyguard.rate_limit")

# Defaults (can be overridden by Config at import time)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_DELAY_BASE = 2  # seconds


class RateLimiter:
    """Exponential-backoff rate limiter against brute force."""

    def __init__(
        self,
        max_attempts: int = MAX_LOGIN_ATTEMPTS,
        delay_base: int = LOGIN_DELAY_BASE,
    ):
        self._max_attempts = max_attempts
        self._delay_base = delay_base
        self.attempts = 0
        self.last_attempt: float = 0

    def check(self):
        now = time.time()
        if self.attempts > 0:
            required_delay = self._delay_base**self.attempts
            elapsed = now - self.last_attempt
            if elapsed < required_delay:
                wait_time = required_delay - elapsed
                logger.warning("Rate limiting: waiting %.1fs", wait_time)
                time.sleep(wait_time)

        if self.attempts >= self._max_attempts:
            logger.error("Maximum of %d attempts exceeded", self._max_attempts)
            raise ValueError(
                f"Exceeded the limit of {self._max_attempts} attempts. "
                "Wait before trying again."
            )

        self.attempts += 1
        self.last_attempt = time.time()

    def reset(self):
        self.attempts = 0
        self.last_attempt = 0
