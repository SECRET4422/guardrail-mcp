"""Tests for multi-language, repo, sarif, sbom, fixes, pipeline."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.pop("GUARDRAIL_REQUIRE_TENANT", None)

ROOT = Path(__file__).resolve().parents[1]


class LanguageTests(unittest.TestCase):
    def test_js_eval(self):
        from guardrail.languages import scan_language

        src = Path(ROOT / "examples/multilang/app.js").read_text()
        findings = scan_language(src, "javascript")
        ids = {f.rule_id for f in findings}
        self.assertIn("GR-JS-001", ids)

    def test_go_sql(self):
        from guardrail.languages import scan_language

        src = Path(ROOT / "examples/multilang/main.go").read_text()
        findings = scan_language(src, "go")
        ids = {f.rule_id for f in findings}
        self.assertIn("GR-GO-002", ids)

    def test_c_strcpy(self):
        from guardrail.languages import scan_language

        src = Path(ROOT / "examples/multilang/danger.c").read_text()
        findings = scan_language(src, "c")
        ids = {f.rule_id for f in findings}
        self.assertIn("GR-C-001", ids)
        self.assertIn("GR-C-002", ids)


class RepoScanTests(unittest.TestCase):
    def test_scan_examples_tree(self):
        from guardrail.repo_scan import scan_repository

        res = scan_repository(ROOT / "examples", workers=4, max_files=100)
        self.assertEqual(res["status"], "OK")
        self.assertGreaterEqual(res["files_scanned"], 3)
        self.assertGreaterEqual(res["issue_count"], 1)


class SarifSbomFixTests(unittest.TestCase):
    def test_sarif_shape(self):
        from guardrail.sarif_export import findings_to_sarif

        issues = [
            {
                "rule_id": "GR-SEC-003",
                "vulnerability_name": "eval",
                "severity": "CRITICAL",
                "description": "eval used",
                "remediation": "remove",
                "line": 2,
                "column": 1,
                "excerpt_redacted": "eval(x)",
                "path": "a.py",
            }
        ]
        sarif = findings_to_sarif(issues)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    def test_sbom_from_project(self):
        from guardrail.sbom import generate_cyclonedx, generate_spdx

        cdx = generate_cyclonedx(ROOT)
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertGreaterEqual(len(cdx["components"]), 1)
        spdx = generate_spdx(ROOT)
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")

    def test_fixes(self):
        from guardrail.fixes import generate_fix_draft

        draft = generate_fix_draft(
            {"rule_id": "GR-AST-004", "line": 10, "excerpt_redacted": "execute(f)..."}
        )
        self.assertIn("Parameterize", draft["title"])
        self.assertIn("agent_prompt", draft)


class ToolsCatalogTests(unittest.TestCase):
    def test_list_and_call(self):
        from guardrail.tools_catalog import TOOLS, call_tool

        names = {t["name"] for t in TOOLS}
        self.assertIn("scan_repository", names)
        self.assertIn("export_sarif", names)
        res = call_tool(
            "audit_code_safety",
            {"source_code": "eval(1)", "filename": "x.py"},
        )
        self.assertEqual(res["status"], "OK")
        res2 = call_tool(
            "audit_code_safety",
            {"source_code": "eval(user)", "filename": "x.js", "language": "javascript"},
        )
        self.assertGreaterEqual(res2.get("issue_count", 0), 1)

    def test_container(self):
        from guardrail.tools_catalog import call_tool

        df = Path(ROOT / "examples/multilang/Dockerfile").read_text()
        res = call_tool("audit_container_config", {"content": df, "filename": "Dockerfile"})
        self.assertEqual(res["status"], "OK")
        self.assertGreaterEqual(res["issue_count"], 1)

    def test_pipeline_repo(self):
        from guardrail.tools_catalog import call_tool

        res = call_tool(
            "full_pipeline",
            {
                "path": str(ROOT / "examples"),
                "mode": "repo",
                "include_deps": True,
                "use_network": False,
                "include_fixes": True,
                "sbom_format": "cyclonedx",
            },
        )
        self.assertIn(res.get("status"), ("OK", "ERROR"))
        # examples may not be git root — repo mode should work
        self.assertGreaterEqual(res.get("issue_count", 0), 1)
        self.assertTrue(res.get("fixes"))


class DepsOfflineTests(unittest.TestCase):
    def test_inventory_no_network(self):
        from guardrail.deps import scan_dependencies

        res = scan_dependencies(ROOT, use_network=False)
        self.assertEqual(res["status"], "OK")
        self.assertGreaterEqual(res["packages_discovered"], 1)


if __name__ == "__main__":
    unittest.main()
