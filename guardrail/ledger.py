"""Thread-safe tenant credit ledger (demo / single-process)."""

from __future__ import annotations

import os
import threading
from copy import deepcopy
from typing import Any, Dict, Optional, Tuple


# Local free tier: no tenant_id required when GUARDRAIL_REQUIRE_TENANT is unset/false
DEFAULT_LEDGER: Dict[str, Dict[str, Any]] = {
    "free_dev_tier": {"tier": "free", "credits": 50},
    "enterprise_client_99": {"tier": "premium", "credits": 99_999},
}


class TenantLedger:
    """In-memory ledger. Replace with Redis/DB for multi-process production."""

    def __init__(self, initial: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self._lock = threading.Lock()
        self._accounts: Dict[str, Dict[str, Any]] = deepcopy(initial or DEFAULT_LEDGER)
        self.require_tenant = os.environ.get("GUARDRAIL_REQUIRE_TENANT", "").lower() in {
            "1",
            "true",
            "yes",
        }
        # Unlimited local mode unless SaaS flag is on
        self.local_unlimited = not self.require_tenant

    def snapshot(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            acc = self._accounts.get(tenant_id)
            return deepcopy(acc) if acc else None

    def authorize_and_charge(
        self, tenant_id: Optional[str], cost: int = 1
    ) -> Tuple[bool, Optional[int], Optional[str], str]:
        """
        Returns (ok, credits_remaining, error_reason, mode).
        mode is "local" or "tenant".
        """
        if not self.require_tenant and (not tenant_id or tenant_id in ("", "local", "free")):
            return True, None, None, "local"

        if not tenant_id:
            return (
                False,
                None,
                "tenant_id is required when GUARDRAIL_REQUIRE_TENANT is enabled.",
                "tenant",
            )

        with self._lock:
            account = self._accounts.get(tenant_id)
            if not account:
                return (
                    False,
                    None,
                    "Unknown tenant_id. Use a provisioned token or run in local mode.",
                    "tenant",
                )
            if account["credits"] < cost:
                return (
                    False,
                    account["credits"],
                    "Depleted query credits for this tenant.",
                    "tenant",
                )
            account["credits"] -= cost
            return True, account["credits"], None, "tenant"

    def refund(self, tenant_id: str, amount: int = 1) -> None:
        if not tenant_id:
            return
        with self._lock:
            account = self._accounts.get(tenant_id)
            if account:
                account["credits"] += amount


# Process-wide default ledger
ledger = TenantLedger()
