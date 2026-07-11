"""Enterprise control-plane tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

# Force load of dev enterprise.json
ROOT = Path(__file__).resolve().parents[1]
os.environ["GUARDRAIL_ENTERPRISE"] = "1"
os.environ["GUARDRAIL_ENTERPRISE_CONFIG"] = str(ROOT / "config" / "enterprise.json")
os.environ.pop("GUARDRAIL_REQUIRE_TENANT", None)


class EnterpriseAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from guardrail.enterprise.config import registry

        registry.reload(str(ROOT / "config" / "enterprise.json"))

    def test_api_key_auth(self):
        from guardrail.enterprise.auth import authenticate
        from guardrail.enterprise.config import registry

        cfg = registry.get()
        p, err = authenticate(cfg, api_key="gr_demo_enterprise_key_change_me", transport="http")
        self.assertIsNone(err)
        assert p is not None
        self.assertEqual(p.role, "admin")
        self.assertEqual(p.tenant_id, "default")

    def test_invalid_key(self):
        from guardrail.enterprise.auth import authenticate
        from guardrail.enterprise.config import registry

        cfg = registry.get()
        cfg.require_auth = True
        cfg.allow_local_unauthenticated = False
        p, err = authenticate(cfg, api_key="nope", transport="http")
        self.assertIsNone(p)
        self.assertIn("Invalid", err or "")

    def test_jwt_roundtrip(self):
        from guardrail.enterprise.auth import issue_jwt, verify_jwt
        from guardrail.enterprise.config import registry

        cfg = registry.get()
        tok = issue_jwt(
            secret=cfg.jwt_secret,
            subject="alice",
            tenant_id="default",
            role="scanner",
            issuer=cfg.jwt_issuer,
            audience=cfg.jwt_audience,
            ttl_seconds=60,
        )
        claims = verify_jwt(
            tok, secret=cfg.jwt_secret, issuer=cfg.jwt_issuer, audience=cfg.jwt_audience
        )
        self.assertEqual(claims["sub"], "alice")
        self.assertEqual(claims["role"], "scanner")


class EnterpriseGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from guardrail.enterprise.config import registry

        registry.reload(str(ROOT / "config" / "enterprise.json"))

    def test_viewer_forbidden_scan(self):
        from guardrail.tools_catalog import call_tool_gated

        res = call_tool_gated(
            "audit_code_safety",
            {"source_code": "print(1)"},
            api_key="gr_viewer_key",
            transport="http",
        )
        self.assertEqual(res["status"], "FORBIDDEN")

    def test_admin_scan_with_policy(self):
        from guardrail.tools_catalog import call_tool_gated

        res = call_tool_gated(
            "audit_code_safety",
            {"source_code": "eval(input())\npassword = \"SuperSecretPass123\"\n"},
            api_key="gr_demo_enterprise_key_change_me",
            transport="http",
        )
        self.assertEqual(res["status"], "OK")
        self.assertIn("policy", res)
        self.assertEqual(res.get("policy_decision"), "DENY")
        self.assertEqual(res.get("security_verdict"), "REJECTED")
        self.assertIn("correlation_id", res)
        self.assertIn("enterprise", res)

    def test_clean_code_allow(self):
        from guardrail.tools_catalog import call_tool_gated

        res = call_tool_gated(
            "audit_code_safety",
            {"source_code": "def add(a,b):\n    return a+b\n"},
            api_key="gr_demo_enterprise_key_change_me",
            transport="http",
        )
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res.get("policy_decision"), "ALLOW")

    def test_sandbox_denies_outside_root(self):
        from guardrail.enterprise.config import TenantConfig, registry
        from guardrail.tools_catalog import call_tool_gated

        cfg = registry.get()
        # temporarily set roots
        t = cfg.tenants["default"]
        old_roots = list(t.allowed_roots)
        old_global = list(cfg.global_allowed_roots)
        try:
            t.allowed_roots = [str(ROOT / "fixtures")]
            cfg.global_allowed_roots = [str(ROOT / "fixtures")]
            cfg.enabled = True
            res = call_tool_gated(
                "scan_repository",
                {"path": str(ROOT / "examples")},
                api_key="gr_demo_enterprise_key_change_me",
                transport="http",
            )
            self.assertEqual(res["status"], "SANDBOX_DENIED")
        finally:
            t.allowed_roots = old_roots
            cfg.global_allowed_roots = old_global

    def test_enterprise_health(self):
        from guardrail.tools_catalog import call_tool_gated

        res = call_tool_gated(
            "enterprise_health",
            {},
            api_key="gr_demo_enterprise_key_change_me",
            transport="http",
        )
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res.get("edition"), "enterprise")

    def test_list_tools_includes_enterprise(self):
        from guardrail.tools_catalog import list_tools

        names = {t["name"] for t in list_tools()}
        self.assertIn("enterprise_health", names)
        self.assertIn("compliance_report", names)
        self.assertIn("issue_access_token", names)

    def test_mcp_dispatch_uses_gateway(self):
        from guardrail.mcp_stdio import dispatch

        resp = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "enterprise_health",
                    "arguments": {"api_key": "gr_demo_enterprise_key_change_me"},
                },
            }
        )
        assert resp is not None
        text = resp["result"]["content"][0]["text"]
        self.assertIn("enterprise", text)


class PolicyTests(unittest.TestCase):
    def test_evaluate_deny(self):
        from guardrail.enterprise.policy import evaluate_policy

        result = {
            "status": "OK",
            "risk_score": 80,
            "issues": [{"rule_id": "X", "severity": "CRITICAL", "line": 1}],
        }
        out = evaluate_policy(
            result,
            policy_pack={"fail_on_severity": ["CRITICAL"], "max_risk_score": 10},
        )
        self.assertEqual(out["policy"]["decision"], "DENY")
        self.assertFalse(out["policy"]["passed"])


class RateLimitTests(unittest.TestCase):
    def test_bucket(self):
        from guardrail.enterprise.rate_limit import RateLimiter

        lim = RateLimiter()
        # 2 per minute capacity
        ok1, _ = lim.allow("t1", rpm=2, cost=1)
        ok2, _ = lim.allow("t1", rpm=2, cost=1)
        ok3, retry = lim.allow("t1", rpm=2, cost=1)
        self.assertTrue(ok1 and ok2)
        self.assertFalse(ok3)
        self.assertGreater(retry, 0)


if __name__ == "__main__":
    unittest.main()
