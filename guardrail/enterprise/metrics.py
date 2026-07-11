"""In-process metrics for enterprise health endpoints."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = time.time()
        self.tool_calls = 0
        self.tool_errors = 0
        self.auth_failures = 0
        self.rate_limited = 0
        self.policy_denies = 0
        self.by_tool: Dict[str, int] = {}
        self.latency_ms_sum = 0.0
        self.latency_ms_count = 0

    def record_call(self, tool: str, latency_ms: float, *, error: bool = False) -> None:
        with self._lock:
            self.tool_calls += 1
            if error:
                self.tool_errors += 1
            self.by_tool[tool] = self.by_tool.get(tool, 0) + 1
            self.latency_ms_sum += latency_ms
            self.latency_ms_count += 1

    def inc_auth_fail(self) -> None:
        with self._lock:
            self.auth_failures += 1

    def inc_rate_limit(self) -> None:
        with self._lock:
            self.rate_limited += 1

    def inc_policy_deny(self) -> None:
        with self._lock:
            self.policy_denies += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            avg = (
                self.latency_ms_sum / self.latency_ms_count if self.latency_ms_count else 0.0
            )
            return {
                "uptime_seconds": int(time.time() - self.started),
                "tool_calls": self.tool_calls,
                "tool_errors": self.tool_errors,
                "auth_failures": self.auth_failures,
                "rate_limited": self.rate_limited,
                "policy_denies": self.policy_denies,
                "avg_latency_ms": round(avg, 2),
                "by_tool": dict(self.by_tool),
            }


metrics = Metrics()
