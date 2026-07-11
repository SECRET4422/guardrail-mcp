"""SARIF 2.1.0 export for GitHub code scanning & other consumers."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import __version__

_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _rule_index_map(issues: List[Dict[str, Any]]) -> Dict[str, int]:
    order: List[str] = []
    for i in issues:
        rid = i.get("rule_id") or "GR-UNKNOWN"
        if rid not in order:
            order.append(rid)
    return {rid: idx for idx, rid in enumerate(order)}


def findings_to_sarif(
    issues: List[Dict[str, Any]],
    *,
    tool_name: str = "guardrail-mcp",
    tool_version: str = __version__,
    default_uri: str = "file",
) -> Dict[str, Any]:
    """
    Convert GuardRail issue dicts to a SARIF 2.1.0 log.
    Each issue may include: rule_id, vulnerability_name, severity, description,
    remediation, line, column, excerpt_redacted, path/uri.
    """
    idx_map = _rule_index_map(issues)
    rules = []
    seen = set()
    for issue in issues:
        rid = issue.get("rule_id") or "GR-UNKNOWN"
        if rid in seen:
            continue
        seen.add(rid)
        rules.append(
            {
                "id": rid,
                "name": issue.get("vulnerability_name") or rid,
                "shortDescription": {"text": issue.get("vulnerability_name") or rid},
                "fullDescription": {
                    "text": issue.get("description") or issue.get("vulnerability_name") or rid
                },
                "help": {
                    "text": issue.get("remediation") or "Review and remediate.",
                    "markdown": issue.get("remediation") or "Review and remediate.",
                },
                "defaultConfiguration": {
                    "level": _LEVEL.get(str(issue.get("severity", "MEDIUM")).upper(), "warning")
                },
                "properties": {
                    "security-severity": {
                        "CRITICAL": "9.0",
                        "HIGH": "7.0",
                        "MEDIUM": "5.0",
                        "LOW": "3.0",
                        "INFO": "1.0",
                    }.get(str(issue.get("severity", "MEDIUM")).upper(), "5.0")
                },
            }
        )

    results = []
    for issue in issues:
        rid = issue.get("rule_id") or "GR-UNKNOWN"
        path = issue.get("path") or issue.get("uri") or default_uri
        line = int(issue.get("line") or 1)
        col = int(issue.get("column") or 1)
        msg = issue.get("description") or issue.get("vulnerability_name") or rid
        excerpt = issue.get("excerpt_redacted") or ""
        if excerpt:
            msg = f"{msg} | excerpt: {excerpt}"
        level = _LEVEL.get(str(issue.get("severity", "MEDIUM")).upper(), "warning")
        # stable partial fingerprint
        fp_src = f"{rid}|{path}|{line}|{excerpt}"
        partial = hashlib.sha256(fp_src.encode()).hexdigest()[:16]
        results.append(
            {
                "ruleId": rid,
                "ruleIndex": idx_map.get(rid, 0),
                "level": level,
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": path.replace("\\", "/")},
                            "region": {
                                "startLine": max(1, line),
                                "startColumn": max(1, col),
                                "snippet": {"text": excerpt} if excerpt else undefined_omit(),
                            },
                        }
                    }
                ],
                "partialFingerprints": {"guardrail/v1": partial},
                "fixes": undefined_omit(),
                "properties": {
                    "remediation": issue.get("remediation"),
                    "severity": issue.get("severity"),
                },
            }
        )

    # Clean undefined placeholders
    for r in results:
        region = r["locations"][0]["physicalLocation"]["region"]
        if region.get("snippet") is None:
            region.pop("snippet", None)
        r.pop("fixes", None)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/guardrail-mcp/guardrail-mcp",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
            }
        ],
    }


def undefined_omit() -> None:
    return None


def write_sarif(path: str, sarif: Dict[str, Any]) -> str:
    import json
    from pathlib import Path

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return str(p)
