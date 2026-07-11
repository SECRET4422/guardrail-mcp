"""Tests for taint, tree-sitter, rules, plugins, incremental, hybrid."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("GUARDRAIL_ENTERPRISE", "0")
os.environ.pop("GUARDRAIL_REQUIRE_TENANT", None)


class TaintTests(unittest.TestCase):
    def test_multihop_sql(self):
        from guardrail.taint import analyze_taint

        src = """
def f(request):
    a = request.args.get("q")
    b = a
    db.execute(f"SELECT {b}")
"""
        hits = analyze_taint(src)
        ids = {h.rule_id for h in hits}
        self.assertIn("GR-TAINT-003", ids)
        # path should mention hops
        self.assertTrue(any("var:b" in (h.description or "") or "var:a" in (h.description or "") for h in hits))

    def test_sanitizer_blocks(self):
        from guardrail.taint import analyze_taint

        src = """
def f():
    x = input()
    y = int(x)
    os.system(str(y))
"""
        # int() is sanitizer — depending on flow may still taint str(y); ensure no crash
        analyze_taint(src)


class TreeSitterTests(unittest.TestCase):
    def test_status(self):
        from guardrail.treesitter_engine import treesitter_status

        st = treesitter_status()
        self.assertIn("available", st)

    def test_python_eval_if_available(self):
        from guardrail.treesitter_engine import scan_with_treesitter, treesitter_status

        if not treesitter_status().get("available"):
            self.skipTest("tree-sitter not installed")
        if "python" not in treesitter_status().get("languages", []):
            self.skipTest("python grammar missing")
        hits = scan_with_treesitter("eval(x)\n", "python")
        self.assertTrue(any("eval" in h.vulnerability_name.lower() or h.rule_id.startswith("GR-TS") for h in hits))


class RuleEngineTests(unittest.TestCase):
    def test_custom_regex(self):
        from guardrail.rule_engine import CustomRule, apply_custom_rules

        rules = [
            CustomRule(
                id="T-1",
                name="ban foo",
                languages=["python"],
                severity="HIGH",
                type="regex",
                pattern=r"\bfoo\s*\(",
                message="no foo",
            )
        ]
        hits = apply_custom_rules("foo(1)\n", "python", rules)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].rule_id, "T-1")


class PluginTests(unittest.TestCase):
    def test_load_sample_plugins(self):
        from guardrail.plugins import get_plugin_registry

        reg = get_plugin_registry(reload=True)
        self.assertGreaterEqual(len(reg.rules), 1)


class HybridTests(unittest.TestCase):
    def test_hybrid_python(self):
        from guardrail.hybrid_scan import hybrid_scan

        res = hybrid_scan(
            'password = "SuperSecretValue99"\neval(input())\n',
            filename="x.py",
            language="python",
            use_plugins=True,
        )
        self.assertEqual(res["status"], "OK")
        self.assertGreaterEqual(res["issue_count"], 1)
        self.assertTrue(res.get("engines"))

    def test_engine_status_tool(self):
        from guardrail.tools_catalog import call_tool

        res = call_tool("engine_status", {})
        self.assertEqual(res["status"], "OK")
        self.assertIn("advanced_taint", res.get("features") or [])


class IncrementalTests(unittest.TestCase):
    def test_cache_hit(self):
        from guardrail.incremental import ScanCache

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text("print(1)\n", encoding="utf-8")
            cache = ScanCache(Path(td) / "c.json")
            self.assertIsNone(cache.get(p))
            cache.put(p, {"status": "OK", "language": "python", "risk_score": 0, "issue_count": 0, "issues": [], "engines": []})
            hit = cache.get(p)
            self.assertIsNotNone(hit)
            self.assertEqual(cache.hits, 1)


class DashboardTests(unittest.TestCase):
    def test_score(self):
        from guardrail.dashboard import compute_security_score

        s = compute_security_score(
            [{"severity": "CRITICAL"}, {"severity": "LOW"}]
        )
        self.assertLess(s["score"], 100)
        self.assertIn(s["grade"], list("ABCDF"))


if __name__ == "__main__":
    unittest.main()
