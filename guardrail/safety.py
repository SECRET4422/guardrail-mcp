"""Core safety audit pipeline — regex + optional AST taint engine."""

from __future__ import annotations

import os
import re
from typing import List, Optional, Set, Tuple

from .ast_engine import analyze_python_ast
from .ledger import ledger
from .models import (
    SEVERITY_WEIGHT,
    Finding,
    SafetyAuditResult,
    Severity,
    risk_level_from_score,
)
from .redaction import redact_excerpt, sanitize_for_log
from .rules import get_rules

# Hard limits to avoid memory / ReDoS blowups on agent-fed megablobs
MAX_SOURCE_BYTES = int(os.environ.get("GUARDRAIL_MAX_SOURCE_BYTES", str(512_000)))
MAX_FINDINGS = 100
MAX_LINE_LEN = 8_000

# Family prefixes used to dedupe regex+AST double hits on the same line
_DEDUP_FAMILIES = (
    ("GR-SEC-003", "GR-AST-003"),
    ("GR-SEC-004", "GR-AST-004"),
    ("GR-SEC-005", "GR-AST-005"),
    ("GR-SEC-006", "GR-AST-006"),
    ("GR-SEC-009", "GR-AST-009"),
    ("GR-SEC-010", "GR-AST-010"),
)


def _line_col_at(text: str, index: int) -> Tuple[int, int]:
    """1-based line and column for absolute index."""
    if index <= 0:
        return 1, 1
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index + 1 if last_nl < 0 else index - last_nl
    return line, col


def _line_text_at(text: str, index: int) -> Tuple[str, int]:
    """Return (line_content, offset_of_line_start)."""
    last_nl = text.rfind("\n", 0, index)
    start = 0 if last_nl < 0 else last_nl + 1
    next_nl = text.find("\n", index)
    end = len(text) if next_nl < 0 else next_nl
    return text[start:end], start


def _compile_rules():
    compiled = []
    for rule in get_rules():
        flags = re.MULTILINE
        if "multiline_span" in rule.flags:
            flags |= re.DOTALL
        try:
            cre = re.compile(rule.pattern, flags)
        except re.error:
            continue
        ctx = re.compile(rule.context_pattern) if rule.context_pattern else None
        compiled.append((rule, cre, ctx))
    return compiled


_COMPILED = _compile_rules()


def _family_key(rule_id: str) -> str:
    for a, b in _DEDUP_FAMILIES:
        if rule_id.startswith(a) or rule_id.startswith(b):
            return a
    return rule_id


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """
    Prefer AST findings over regex when both hit the same family on the same line.
    Secrets (GR-SEC-001/002/011…) are never dropped.
    """
    # Index AST-backed families by (family, line)
    ast_lines: Set[Tuple[str, int]] = set()
    for f in findings:
        if f.rule_id.startswith("GR-AST-"):
            ast_lines.add((_family_key(f.rule_id), f.line))

    out: List[Finding] = []
    seen: Set[Tuple[str, int, str]] = set()
    for f in findings:
        fam = _family_key(f.rule_id)
        # Drop regex twin if AST already covers the line for that family
        if (
            f.rule_id.startswith("GR-SEC-")
            and fam.startswith("GR-SEC-00")  # behavioral sinks, not secrets 001/002
            and fam in {a for a, _ in _DEDUP_FAMILIES}
            and (fam, f.line) in ast_lines
            and not f.rule_id.startswith(("GR-SEC-001", "GR-SEC-002", "GR-SEC-011", "GR-SEC-012"))
        ):
            # Only dedupe behavioral rules 003-010
            if any(f.rule_id.startswith(p) for p, _ in _DEDUP_FAMILIES):
                continue

        key = (fam, f.line, f.severity)
        if key in seen and f.rule_id.startswith("GR-SEC-"):
            # secondary exact family+line collapse for remaining regex dupes
            if any(f.rule_id.startswith(p) for p, _ in _DEDUP_FAMILIES):
                continue
        seen.add(key)
        out.append(f)
    return out


def run_core_safety_audit(
    source_code: str,
    tenant_id: Optional[str] = None,
    *,
    filename: Optional[str] = None,
    use_ast: bool = True,
) -> dict:
    """
    Scan source_code with heuristic regex rules + Python AST taint analysis.

    Returns a JSON-serializable dict (SafetyAuditResult.to_dict()).
    """
    if source_code is None:
        source_code = ""

    truncated = False
    raw = source_code if isinstance(source_code, str) else str(source_code)
    scanned_bytes = len(raw.encode("utf-8", errors="replace"))
    if scanned_bytes > MAX_SOURCE_BYTES:
        raw = raw.encode("utf-8", errors="replace")[:MAX_SOURCE_BYTES].decode(
            "utf-8", errors="ignore"
        )
        truncated = True
        scanned_bytes = MAX_SOURCE_BYTES

    ok, credits_left, err, mode = ledger.authorize_and_charge(tenant_id, cost=1)
    if not ok:
        return SafetyAuditResult(
            status="ACCESS_DENIED",
            reason=err or "Access denied",
            action_required=(
                "Set tenant_id to a provisioned token, or unset GUARDRAIL_REQUIRE_TENANT "
                "for unlimited local mode."
            ),
            mode=mode,
            scanned_bytes=scanned_bytes,
            truncated=truncated,
            credits_remaining=credits_left,
        ).to_dict()

    findings: List[Finding] = []
    score = 0
    notes: List[str] = [
        "Hybrid scan: regex secret/sink grid + Python AST taint (when parseable).",
        "Heuristic guardrail — not a full commercial SAST or CVE dependency audit.",
        "Secrets are redacted in excerpts; rotate any real credentials that were scanned.",
    ]
    if filename:
        notes.append(f"filename_hint={filename}")
    if truncated:
        notes.append(f"Input truncated to {MAX_SOURCE_BYTES} bytes before scan.")

    engines_used = ["regex"]

    try:
        # --- Pass 1: regex grid ---
        for rule, cre, ctx_re in _COMPILED:
            if len(findings) >= MAX_FINDINGS:
                notes.append(f"Stopped early after {MAX_FINDINGS} findings.")
                break

            for m in cre.finditer(raw):
                if len(findings) >= MAX_FINDINGS:
                    break

                if rule.require_context and ctx_re is not None:
                    window_start = max(0, m.start() - 80)
                    window_end = min(len(raw), m.end() + 80)
                    if not ctx_re.search(raw[window_start:window_end]):
                        continue

                if m.lastindex:
                    gstart, gend = m.start(m.lastindex), m.end(m.lastindex)
                else:
                    gstart, gend = m.start(), m.end()

                line_no, col = _line_col_at(raw, gstart)
                line_text, line_start = _line_text_at(raw, gstart)
                if len(line_text) > MAX_LINE_LEN:
                    line_text = line_text[:MAX_LINE_LEN]

                rel_start = gstart - line_start
                rel_end = gend - line_start
                is_secret_rule = rule.id.startswith(
                    ("GR-SEC-001", "GR-SEC-002", "GR-SEC-010", "GR-SEC-011", "GR-SEC-012")
                )
                if is_secret_rule:
                    excerpt = redact_excerpt(
                        line_text, rel_start, min(rel_end, len(line_text))
                    )
                else:
                    clipped = line_text.strip()
                    if len(clipped) > 160:
                        clipped = clipped[:157] + "…"
                    excerpt = redact_excerpt(clipped, 0, 0)

                weight = SEVERITY_WEIGHT.get(rule.severity, 10)
                score += weight

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        vulnerability_name=rule.name,
                        severity=rule.severity.value
                        if isinstance(rule.severity, Severity)
                        else str(rule.severity),
                        description=rule.description,
                        remediation=rule.remediation,
                        line=line_no,
                        column=col,
                        excerpt_redacted=excerpt,
                        match_length=max(0, gend - gstart),
                    )
                )

        # --- Pass 2: AST semantic / taint ---
        if use_ast and len(findings) < MAX_FINDINGS:
            ast_res = analyze_python_ast(raw)
            engines_used.append("ast")
            notes.extend(ast_res.notes)
            for f in ast_res.findings:
                if len(findings) >= MAX_FINDINGS:
                    break
                findings.append(f)
                score += SEVERITY_WEIGHT.get(
                    Severity(f.severity) if f.severity in Severity.__members__ else Severity.MEDIUM,
                    10,
                )

        findings = _dedupe_findings(findings)
        # Recompute score after dedupe for honesty
        score = 0
        for f in findings:
            try:
                sev = Severity(f.severity)
            except ValueError:
                sev = Severity.MEDIUM
            score += SEVERITY_WEIGHT.get(sev, 10)

    except Exception as exc:  # noqa: BLE001
        if mode == "tenant" and tenant_id:
            ledger.refund(tenant_id, 1)
        return SafetyAuditResult(
            status="ERROR",
            reason=sanitize_for_log(f"Scanner failure: {exc}"),
            mode=mode,
            scanned_bytes=scanned_bytes,
            truncated=truncated,
            credits_remaining=credits_left,
            notes=notes,
        ).to_dict()

    display_score = min(score, 999)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.line, f.rule_id))

    risk_level = risk_level_from_score(display_score)
    # Agent-friendly gate (optional consumers)
    security_verdict = "APPROVED" if display_score < 40 else "REJECTED"
    notes.append(f"engines={'+'.join(engines_used)}")
    notes.append(f"security_verdict={security_verdict} (threshold score>=40 → REJECTED)")

    result = SafetyAuditResult(
        status="OK",
        risk_score=display_score,
        risk_level=risk_level,
        issue_count=len(findings),
        issues=findings,
        credits_remaining=credits_left,
        scanned_bytes=scanned_bytes,
        truncated=truncated,
        mode=mode,
        notes=notes,
    ).to_dict()
    result["security_verdict"] = security_verdict
    result["engines"] = engines_used
    return result
