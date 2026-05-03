"""
Token-bucket rate limiter for the signaling server.

Provides per-IP and per-channel rate limiting to mitigate DDoS and spam (§8).
IP addresses are hashed with a daily rotating salt to prevent enumeration while
still providing effective per-IP limiting.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import OrderedDict

logger = logging.getLogger(__name__)

# Maximum number of distinct buckets held in memory (bounded cache, §14)
_MAX_BUCKETS = 2048

# Daily salt rotation window in seconds
_SALT_WINDOW = 86400


def _daily_salt() -> str:
    """Return a string that changes once per UTC day."""
    return str(int(time.time()) // _SALT_WINDOW)


def _hash_ip(ip: str) -> str:
    """One-way hash an IP with the daily rotating salt."""
    raw = f"{_daily_salt()}:{ip}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


class TokenBucket:
    """A single token-bucket rate-limit counter.

    Parameters
    ----------
    capacity:
        Maximum token count (burst size).
    refill_rate:
        Tokens added per second.
    """

    __slots__ = ("_capacity", "_refill_rate", "_tokens", "_last_refill")

    def __init__(self, capacity: float, refill_rate: float) -> None:
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        """Attempt to consume *tokens* from the bucket.

        Returns ``True`` if the request is allowed, ``False`` if rate-limited.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now

        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False


class RateLimiter:
    """Manages per-IP and per-channel token buckets.

    Parameters
    ----------
    ip_capacity:
        Burst capacity per IP address.
    ip_rate:
        Tokens per second per IP address.
    channel_capacity:
        Burst capacity per channel.
    channel_rate:
        Tokens per second per channel.
    """

    def __init__(
        self,
        ip_capacity: float = 20.0,
        ip_rate: float = 2.0,
        channel_capacity: float = 10.0,
        channel_rate: float = 1.0,
    ) -> None:
        self._ip_capacity = ip_capacity
        self._ip_rate = ip_rate
        self._channel_capacity = channel_capacity
        self._channel_rate = channel_rate
        # Ordered dicts act as LRU caches (bounded, §14)
        self._ip_buckets: OrderedDict[str, TokenBucket] = OrderedDict()
        self._channel_buckets: OrderedDict[str, TokenBucket] = OrderedDict()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> bool:
        """Return ``True`` if *ip* is within rate limits."""
        key = _hash_ip(ip)
        return self._consume(self._ip_buckets, key, self._ip_capacity, self._ip_rate)

    def check_channel(self, channel_id: str) -> bool:
        """Return ``True`` if *channel_id* is within rate limits."""
        return self._consume(
            self._channel_buckets,
            channel_id,
            self._channel_capacity,
            self._channel_rate,
        )

    def is_allowed(self, ip: str, channel_id: str | None = None) -> bool:
        """Combined check: return ``True`` only if both IP and channel pass."""
        if not self.check_ip(ip):
            logger.debug("IP %s rate-limited", ip)
            return False
        if channel_id is not None and not self.check_channel(channel_id):
            logger.debug("Channel %s rate-limited", channel_id)
            return False
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _consume(
        self,
        store: OrderedDict[str, TokenBucket],
        key: str,
        capacity: float,
        rate: float,
    ) -> bool:
        if key not in store:
            if len(store) >= _MAX_BUCKETS:
                # Evict the oldest entry (LRU eviction)
                store.popitem(last=False)
            store[key] = TokenBucket(capacity, rate)
        else:
            # Move to end to mark as recently used
            store.move_to_end(key)
        return store[key].consume()
