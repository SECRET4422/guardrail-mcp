"""AST taint / semantic engine tests."""

from __future__ import annotations

import os
import unittest

os.environ.pop("GUARDRAIL_REQUIRE_TENANT", None)

from guardrail.ast_engine import analyze_python_ast
from guardrail.safety import run_core_safety_audit


TAINTED_SQL = '''
def handler(request):
    user = request.args.get("name")
    db.execute(f"SELECT * FROM users WHERE name = '{user}'")
'''

ALIASED_EVAL = '''
cmd = eval
payload = input("x")
cmd(payload)
'''

SAFE_SUBPROCESS = '''
import subprocess
subprocess.run(["echo", "hi"], check=True)
'''

SHELL_TRUE = '''
import subprocess
subprocess.run("ls -la", shell=True)
'''

TAINTED_SUBPROCESS = '''
import subprocess
cmd = input("cmd")
subprocess.run(cmd, shell=True)
'''


class ASTEngineTests(unittest.TestCase):
    def test_tainted_sql(self):
        res = analyze_python_ast(TAINTED_SQL)
        ids = {f.rule_id for f in res.findings}
        self.assertIn("GR-AST-004", ids)

    def test_aliased_eval(self):
        res = analyze_python_ast(ALIASED_EVAL)
        ids = {f.rule_id for f in res.findings}
        self.assertTrue(any(i.startswith("GR-AST-003") for i in ids))

    def test_safe_subprocess_clean(self):
        res = analyze_python_ast(SAFE_SUBPROCESS)
        ids = {f.rule_id for f in res.findings}
        self.assertNotIn("GR-AST-005", ids)

    def test_shell_true(self):
        res = analyze_python_ast(SHELL_TRUE)
        ids = {f.rule_id for f in res.findings}
        self.assertIn("GR-AST-005", ids)

    def test_tainted_subprocess(self):
        res = analyze_python_ast(TAINTED_SUBPROCESS)
        ids = {f.rule_id for f in res.findings}
        self.assertTrue("GR-AST-005t" in ids or "GR-AST-005" in ids)

    def test_hybrid_pipeline_includes_engines(self):
        out = run_core_safety_audit(TAINTED_SQL + '\npassword = "supersecretvalue"\n')
        self.assertEqual(out["status"], "OK")
        self.assertIn("ast", out.get("engines", []))
        self.assertIn(out["security_verdict"], ("APPROVED", "REJECTED"))
        self.assertGreaterEqual(out["issue_count"], 2)

    def test_non_python_still_regex(self):
        js = 'const api_key = "sk-abcdefghijklmnopqrstuvwxyz";\neval(x)'
        out = run_core_safety_audit(js, filename="x.js")
        self.assertEqual(out["status"], "OK")
        # may not parse as Python; secrets regex should still fire
        self.assertGreaterEqual(out["issue_count"], 1)


if __name__ == "__main__":
    unittest.main()
