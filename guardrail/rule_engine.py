"""
Custom rule engine — load YAML/JSON rules from disk or plugins.

Rule schema (YAML):
  id: CUSTOM-001
  name: Disallow foo()
  languages: [python, javascript]
  severity: HIGH
  type: regex | treesitter | ast_message
  pattern: "\\bfoo\\s*\\("
  message: "foo is banned"
  remediation: "Use bar instead"
  enabled: true
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .models import Finding, Severity
from .redaction import redact_excerpt


@dataclass
class CustomRule:
    id: str
    name: str
    languages: List[str]
    severity: str
    type: str  # regex | treesitter
    pattern: str
    message: str
    remediation: str = ""
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


def _sev(s: str) -> str:
    u = (s or "MEDIUM").upper()
    return u if u in Severity.__members__ else "MEDIUM"


def load_rules_from_mapping(data: Any) -> List[CustomRule]:
    rules_raw = data
    if isinstance(data, dict):
        rules_raw = data.get("rules") or data.get("custom_rules") or []
    out: List[CustomRule] = []
    for r in rules_raw or []:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip()
        if not rid:
            continue
        out.append(
            CustomRule(
                id=rid,
                name=str(r.get("name") or rid),
                languages=[str(x).lower() for x in (r.get("languages") or ["*"])],
                severity=_sev(str(r.get("severity") or "MEDIUM")),
                type=str(r.get("type") or "regex").lower(),
                pattern=str(r.get("pattern") or r.get("query") or ""),
                message=str(r.get("message") or r.get("description") or r.get("name") or rid),
                remediation=str(r.get("remediation") or ""),
                enabled=bool(r.get("enabled", True)),
                metadata=dict(r.get("metadata") or {}),
            )
        )
    return out


def load_rules_file(path: str | Path) -> List[CustomRule]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml

            data = yaml.safe_load(text)
        except ImportError:
            data = json.loads(text)
    else:
        data = json.loads(text)
    return load_rules_from_mapping(data)


def load_rules_dir(directory: str | Path) -> List[CustomRule]:
    d = Path(directory)
    if not d.is_dir():
        return []
    rules: List[CustomRule] = []
    for p in sorted(d.rglob("*")):
        if p.suffix.lower() in {".yaml", ".yml", ".json"} and p.is_file():
            try:
                rules.extend(load_rules_file(p))
            except Exception:
                continue
    return rules


def apply_custom_rules(
    source: str,
    language: str,
    rules: Sequence[CustomRule],
    *,
    max_findings: int = 100,
) -> List[Finding]:
    if not source:
        return []
    lang = (language or "unknown").lower()
    findings: List[Finding] = []
    for rule in rules:
        if not rule.enabled or not rule.pattern:
            continue
        if rule.languages and "*" not in rule.languages and lang not in rule.languages:
            continue
        if rule.type not in {"regex", "regexp", "pattern"}:
            # treesitter custom queries handled separately if type==treesitter
            if rule.type == "treesitter":
                findings.extend(
                    _apply_ts_rule(source, lang, rule, max_findings - len(findings))
                )
            continue
        try:
            cre = re.compile(rule.pattern, re.MULTILINE)
        except re.error:
            continue
        for m in cre.finditer(source):
            if len(findings) >= max_findings:
                return findings
            line = source.count("\n", 0, m.start()) + 1
            last = source.rfind("\n", 0, m.start())
            col = m.start() + 1 if last < 0 else m.start() - last
            ls = last + 1
            le = source.find("\n", m.start())
            if le < 0:
                le = len(source)
            line_text = source[ls:le]
            rel_s = m.start() - ls
            rel_e = m.end() - ls
            findings.append(
                Finding(
                    rule_id=rule.id,
                    vulnerability_name=rule.name,
                    severity=rule.severity,
                    description=rule.message,
                    remediation=rule.remediation or "Follow org coding standards.",
                    line=line,
                    column=col,
                    excerpt_redacted=redact_excerpt(line_text, rel_s, min(rel_e, len(line_text))),
                    match_length=m.end() - m.start(),
                )
            )
    return findings


def _apply_ts_rule(source: str, lang: str, rule: CustomRule, limit: int) -> List[Finding]:
    if limit <= 0:
        return []
    try:
        from .treesitter_engine import _load_language, _parser_for, HAS_TS
        from tree_sitter import Query, QueryCursor
    except Exception:
        return []
    if not HAS_TS:
        return []
    parser = _parser_for(lang if lang != "typescript" else "javascript")
    language = _load_language(lang if lang != "typescript" else "javascript")
    if not parser or not language:
        return []
    src_b = source.encode("utf-8", errors="replace")
    tree = parser.parse(src_b)
    try:
        query = Query(language, rule.pattern)
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)
    except Exception:
        return []
    out: List[Finding] = []
    for _pat, caps in matches:
        for nodes in caps.values():
            for node in nodes:
                if len(out) >= limit:
                    return out
                pre = src_b[: node.start_byte]
                line = pre.count(b"\n") + 1
                last = pre.rfind(b"\n")
                col = node.start_byte + 1 if last < 0 else node.start_byte - last
                lines = source.splitlines()
                lt = lines[line - 1] if 1 <= line <= len(lines) else ""
                out.append(
                    Finding(
                        rule_id=rule.id,
                        vulnerability_name=rule.name,
                        severity=rule.severity,
                        description=rule.message,
                        remediation=rule.remediation or "Follow org coding standards.",
                        line=line,
                        column=col,
                        excerpt_redacted=redact_excerpt(lt, 0, min(len(lt), 80)),
                        match_length=max(0, node.end_byte - node.start_byte),
                    )
                )
    return out
