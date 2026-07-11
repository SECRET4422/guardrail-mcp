"""
Unified hybrid scanner — regex + AST + advanced taint + tree-sitter + custom rules + plugins.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from .ast_engine import analyze_python_ast
from .languages import detect_language, scan_language, score_findings
from .models import Finding, Severity, SEVERITY_WEIGHT, risk_level_from_score
from .plugins import get_plugin_registry, run_post_scan_hooks, run_pre_scan_hooks
from .rule_engine import apply_custom_rules
from .safety import run_core_safety_audit
from .taint import analyze_taint
from .treesitter_engine import scan_with_treesitter, treesitter_status


def _finding_dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [f.to_dict() for f in findings]


def _score_issue_dicts(issues: List[Dict[str, Any]]) -> int:
    total = 0
    for iss in issues:
        try:
            sev = Severity(str(iss.get("severity") or "MEDIUM"))
        except ValueError:
            sev = Severity.MEDIUM
        total += SEVERITY_WEIGHT.get(sev, 10)
    return min(total, 999)


def hybrid_scan(
    source_code: str,
    *,
    filename: Optional[str] = None,
    language: Optional[str] = None,
    tenant_id: Optional[str] = None,
    use_ast: bool = True,
    use_taint: bool = True,
    use_treesitter: bool = True,
    use_plugins: bool = True,
    custom_rules_dir: Optional[str] = None,
) -> Dict[str, Any]:
    src = source_code or ""
    lang = (language or detect_language(filename, src) or "unknown").lower()
    engines: List[str] = []
    issues: List[Dict[str, Any]] = []
    notes: List[str] = []

    ctx = {"filename": filename, "language": lang, "tenant_id": tenant_id}
    if use_plugins:
        run_pre_scan_hooks(src, lang, ctx)

    # Base secret/regex pipeline (always)
    base = run_core_safety_audit(
        src,
        tenant_id,
        filename=filename,
        use_ast=bool(use_ast and lang == "python"),
    )
    engines.extend(base.get("engines") or ["regex"])
    issues.extend(base.get("issues") or [])
    notes.extend(base.get("notes") or [])

    # Language regex grids (non-duplicative for python already covered)
    if lang not in {"python"}:
        lang_hits = scan_language(src, lang, filename=filename)
        if lang_hits:
            engines.append(f"lang:{lang}")
            issues.extend(_finding_dicts(lang_hits))

    # Advanced taint (python)
    if use_taint and lang == "python":
        taint_hits = analyze_taint(src)
        if taint_hits:
            engines.append("taint")
            issues.extend(_finding_dicts(taint_hits))

    # Extra AST pass notes already in base; ensure engines tag
    if use_ast and lang == "python" and "ast" not in engines:
        engines.append("ast")

    # Tree-sitter
    if use_treesitter:
        ts_hits = scan_with_treesitter(src, lang)
        if ts_hits:
            engines.append("treesitter")
            issues.extend(_finding_dicts(ts_hits))
        elif not treesitter_status().get("available"):
            notes.append("tree-sitter not installed; structural pass skipped")

    # Custom rules + plugins
    custom_rules = []
    if use_plugins:
        reg = get_plugin_registry()
        custom_rules.extend(reg.rules)
    if custom_rules_dir or os.environ.get("GUARDRAIL_RULES_DIR"):
        from .rule_engine import load_rules_dir

        custom_rules.extend(load_rules_dir(custom_rules_dir or os.environ["GUARDRAIL_RULES_DIR"]))
    if custom_rules:
        cr = apply_custom_rules(src, lang, custom_rules)
        if cr:
            engines.append("custom_rules")
            issues.extend(_finding_dicts(cr))

    # Dedupe by rule_id+line+excerpt prefix
    dedup = {}
    for iss in issues:
        key = (
            iss.get("rule_id"),
            iss.get("line"),
            (iss.get("excerpt_redacted") or "")[:40],
        )
        dedup[key] = iss
    issues = list(dedup.values())

    if use_plugins:
        issues = run_post_scan_hooks(src, lang, issues, ctx)

    score = _score_issue_dicts(issues)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    issues.sort(key=lambda i: (order.get(str(i.get("severity")), 9), i.get("line") or 0))

    result = {
        "status": base.get("status") or "OK",
        "language": lang,
        "filename": filename,
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "issue_count": len(issues),
        "issues": issues,
        "engines": engines,
        "security_verdict": "REJECTED" if score >= 40 else "APPROVED",
        "notes": notes
        + [
            "Hybrid engines: regex secrets, language grids, Python AST/taint, tree-sitter, custom rules/plugins."
        ],
        "mode": base.get("mode"),
        "scanned_bytes": base.get("scanned_bytes"),
        "treesitter": treesitter_status(),
    }
    if base.get("status") != "OK":
        return base
    return result
