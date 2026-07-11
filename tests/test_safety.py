"""Unit tests for the safety audit core."""

from __future__ import annotations

import os
import unittest

# Ensure local unlimited mode for tests
os.environ.pop("GUARDRAIL_REQUIRE_TENANT", None)

from guardrail.ledger import TenantLedger
from guardrail.safety import run_core_safety_audit


CLEAN_CODE = '''
def add(a, b):
    return a + b

def main():
    print(add(1, 2))
'''

DIRTY_CODE = '''
import os
import subprocess
import pickle
import yaml

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
password = "SuperSecretPassw0rd!"

def bad_sql(cur, user):
    cur.execute(f"SELECT * FROM users WHERE name = '{user}'")

def worse():
    eval(input("cmd> "))
    os.system("rm -rf /tmp/x")
    subprocess.run("ls " + input(), shell=True)
    pickle.loads(b"cos\\nsystem\\n(S'echo pwned'\\ntR.")
    yaml.load(open("cfg.yaml"))

# fake private key
PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFwO
-----END RSA PRIVATE KEY-----"""
'''


class SafetyAuditTests(unittest.TestCase):
    def test_clean_code_low_risk(self):
        res = run_core_safety_audit(CLEAN_CODE)
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["mode"], "local")
        self.assertEqual(res["issue_count"], 0)
        self.assertEqual(res["risk_level"], "NONE")

    def test_dirty_code_finds_criticals(self):
        res = run_core_safety_audit(DIRTY_CODE, filename="evil.py")
        self.assertEqual(res["status"], "OK")
        self.assertGreaterEqual(res["issue_count"], 5)
        self.assertIn(res["risk_level"], ("HIGH", "CRITICAL"))
        ids = {i["rule_id"] for i in res["issues"]}
        self.assertTrue(any(x.startswith("GR-SEC-001") for x in ids))
        # eval may surface as GR-SEC-003 or preferred GR-AST-003 after dedupe
        self.assertTrue(
            any(x.startswith("GR-SEC-003") or x.startswith("GR-AST-003") for x in ids)
        )
        # Excerpts must not contain full raw AWS example secret
        blob = " ".join(i["excerpt_redacted"] for i in res["issues"])
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", blob)
        self.assertTrue(all("line" in i and i["line"] >= 1 for i in res["issues"]))
        self.assertIn("ast", res.get("engines", []))

    def test_safe_subprocess_not_flagged(self):
        code = 'import subprocess\nsubprocess.run(["ls", "-la"], check=True)\n'
        res = run_core_safety_audit(code)
        ids = {i["rule_id"] for i in res["issues"]}
        self.assertNotIn("GR-SEC-005", ids)
        self.assertNotIn("GR-SEC-005b", ids)
        self.assertNotIn("GR-AST-005", ids)

    def test_shell_true_flagged(self):
        code = 'import subprocess\nsubprocess.run("echo hi", shell=True)\n'
        res = run_core_safety_audit(code)
        ids = {i["rule_id"] for i in res["issues"]}
        self.assertTrue(
            "GR-SEC-005" in ids or "GR-AST-005" in ids,
            f"expected shell finding, got {ids}",
        )

    def test_truncation(self):
        huge = "x = 1\n" + ("a" * 600_000)
        res = run_core_safety_audit(huge)
        self.assertTrue(res["truncated"])
        self.assertEqual(res["status"], "OK")

    def test_tenant_denied(self):
        # Isolate ledger with require_tenant
        from guardrail import safety as safety_mod

        original = safety_mod.ledger
        try:
            safety_mod.ledger = TenantLedger(
                {"paid": {"tier": "free", "credits": 0}}
            )
            safety_mod.ledger.require_tenant = True
            safety_mod.ledger.local_unlimited = False
            res = run_core_safety_audit("print(1)", tenant_id="paid")
            self.assertEqual(res["status"], "ACCESS_DENIED")
        finally:
            safety_mod.ledger = original

    def test_redaction_masks_token_prefix(self):
        code = 'token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n'
        res = run_core_safety_audit(code)
        self.assertGreaterEqual(res["issue_count"], 1)
        for issue in res["issues"]:
            self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123456789", issue["excerpt_redacted"])


if __name__ == "__main__":
    unittest.main()
