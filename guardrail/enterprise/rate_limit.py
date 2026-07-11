"""Token-bucket rate limiter + monthly quota tracking."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class Bucket:
    capacity: float
    tokens: float
    refill_per_sec: float
    updated: float = field(default_factory=time.monotonic)


class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Bucket] = {}
        self._quota_used: Dict[str, int] = {}

    def _bucket(self, key: str, rpm: int) -> Bucket:
        if key not in self._buckets:
            capacity = max(1.0, float(rpm))
            self._buckets[key] = Bucket(
                capacity=capacity,
                tokens=capacity,
                refill_per_sec=capacity / 60.0,
            )
        return self._buckets[key]

    def allow(self, key: str, rpm: int, cost: float = 1.0) -> Tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        if rpm <= 0:
            return True, 0.0
        with self._lock:
            b = self._bucket(key, rpm)
            now = time.monotonic()
            elapsed = now - b.updated
            b.tokens = min(b.capacity, b.tokens + elapsed * b.refill_per_sec)
            b.updated = now
            if b.tokens >= cost:
                b.tokens -= cost
                return True, 0.0
            need = cost - b.tokens
            retry = need / b.refill_per_sec if b.refill_per_sec else 60.0
            return False, max(0.1, retry)

    def check_quota(self, tenant_id: str, used: int, limit: int) -> Tuple[bool, int]:
        if limit <= 0:
            return True, used
        return used < limit, used

    def increment_quota(self, tenant_id: str, n: int = 1) -> int:
        with self._lock:
            self._quota_used[tenant_id] = self._quota_used.get(tenant_id, 0) + n
            return self._quota_used[tenant_id]

    def get_quota_used(self, tenant_id: str) -> int:
        with self._lock:
            return self._quota_used.get(tenant_id, 0)


limiter = RateLimiter()
