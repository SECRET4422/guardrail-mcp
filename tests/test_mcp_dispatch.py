"""JSON-RPC dispatch tests (no real STDIO pipes)."""

from __future__ import annotations

import os
import unittest

os.environ.pop("GUARDRAIL_REQUIRE_TENANT", None)

from guardrail.mcp_stdio import dispatch


class DispatchTests(unittest.TestCase):
    def test_initialize(self):
        resp = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
            }
        )
        self.assertIsNotNone(resp)
        assert resp is not None
        self.assertEqual(resp["id"], 1)
        self.assertIn("serverInfo", resp["result"])
        self.assertIn("capabilities", resp["result"])

    def test_initialized_notification_no_response(self):
        resp = dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(resp)

    def test_tools_list(self):
        resp = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert resp is not None
        names = {t["name"] for t in resp["result"]["tools"]}
        for required in (
            "audit_code_safety",
            "audit_cloud_cost",
            "audit_infra_security",
            "scan_repository",
            "scan_git_diff",
            "scan_dependencies",
            "export_sarif",
            "generate_sbom",
            "suggest_fixes",
            "full_pipeline",
            "enterprise_health",
        ):
            self.assertIn(required, names)

    def test_tools_call_infra(self):
        resp = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "audit_infra_security",
                    "arguments": {
                        "infrastructure_content": "USER root\n0.0.0.0/0\n",
                        "cloud_provider": "aws",
                        "budget_limit_usd": 500,
                    },
                },
            }
        )
        assert resp is not None
        text = resp["result"]["content"][0]["text"]
        self.assertIn("PRIVILEGED_DOCKER_USER", text)


    def test_tools_call_safety(self):
        resp = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "audit_code_safety",
                    "arguments": {"source_code": "print('hi')"},
                },
            }
        )
        assert resp is not None
        content = resp["result"]["content"][0]["text"]
        self.assertIn("OK", content)

    def test_tools_call_cost(self):
        resp = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "audit_cloud_cost",
                    "arguments": {
                        "infrastructure_content": 'instance_type = "t3.micro"',
                        "cloud_provider": "aws",
                    },
                },
            }
        )
        assert resp is not None
        self.assertIn("t3.micro", resp["result"]["content"][0]["text"])

    def test_unknown_method(self):
        resp = dispatch({"jsonrpc": "2.0", "id": 9, "method": "nope/thing"})
        assert resp is not None
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_ping(self):
        resp = dispatch({"jsonrpc": "2.0", "id": 5, "method": "ping"})
        assert resp is not None
        self.assertEqual(resp["result"], {})


if __name__ == "__main__":
    unittest.main()
