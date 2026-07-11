"""Policy packs & post-scan gates."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def evaluate_policy(
    result: Dict[str, Any],
    *,
    policy_pack: Dict[str, Any],
    fail_on_severity: Optional[Sequence[str]] = None,
    max_risk_score: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Gate a scan/tool result. Non-destructive: adds policy block.
    """
    pack = policy_pack or {}
    fail_sevs = {
        s.upper()
        for s in (fail_on_severity or pack.get("fail_on_severity") or ["CRITICAL"])
    }
    max_score = int(
        max_risk_score
        if max_risk_score is not None
        else pack.get("max_risk_score", 10**9)
    )

    issues = list(result.get("issues") or [])
    # nested scan results
    if not issues and isinstance(result.get("scan"), dict):
        issues = list((result.get("scan") or {}).get("issues") or [])

    sevs_found = []
    blocking = []
    for iss in issues:
        sev = str(iss.get("severity") or "MEDIUM").upper()
        sevs_found.append(sev)
        if sev in fail_sevs:
            blocking.append(
                {
                    "rule_id": iss.get("rule_id"),
                    "severity": sev,
                    "path": iss.get("path"),
                    "line": iss.get("line"),
                }
            )

    risk = int(
        result.get("risk_score")
        or result.get("aggregate_risk_score")
        or (result.get("scan") or {}).get("aggregate_risk_score")
        or 0
    )

    reasons: List[str] = []
    if blocking:
        reasons.append(
            f"{len(blocking)} issue(s) at fail severity {sorted(fail_sevs)}"
        )
    if risk > max_score:
        reasons.append(f"risk_score {risk} exceeds max_risk_score {max_score}")

    # honor existing REJECTED
    existing = str(result.get("security_verdict") or "").upper()
    if existing == "REJECTED" and not reasons:
        reasons.append("upstream security_verdict=REJECTED")

    passed = not reasons
    decision = "ALLOW" if passed else "DENY"

    policy_out = {
        "decision": decision,
        "passed": passed,
        "policy_pack": pack.get("description") or pack.get("name") or "custom",
        "fail_on_severity": sorted(fail_sevs),
        "max_risk_score": max_score,
        "risk_score": risk,
        "blocking_findings": blocking[:50],
        "blocking_count": len(blocking),
        "reasons": reasons,
        "compliance_controls": pack.get("compliance_controls") or [],
        "notes": pack.get("extra_notes") or [],
    }

    # Mutate copy-friendly: caller may reassign
    out = dict(result)
    out["policy"] = policy_out
    if not passed:
        out["security_verdict"] = "REJECTED"
        out["policy_decision"] = "DENY"
    else:
        out.setdefault("security_verdict", result.get("security_verdict") or "APPROVED")
        out["policy_decision"] = "ALLOW"
    return out


def build_compliance_report(
    *,
    frameworks: Sequence[str],
    recent_decisions: Sequence[Dict[str, Any]],
    tenant_id: str,
    policy_pack_name: str,
    pack: Dict[str, Any],
) -> Dict[str, Any]:
    """Lightweight control-mapping report for auditors (not a certification)."""
    controls = pack.get("compliance_controls") or []
    denies = sum(1 for d in recent_decisions if d.get("decision") == "DENY")
    allows = sum(1 for d in recent_decisions if d.get("decision") == "ALLOW")
    return {
        "status": "OK",
        "disclaimer": (
            "Control mapping aid for engineering evidence — not a SOC2/ISO certification."
        ),
        "tenant_id": tenant_id,
        "frameworks": list(frameworks),
        "policy_pack": policy_pack_name,
        "mapped_controls": controls,
        "evidence": {
            "policy_enforced": True,
            "audit_logging": True,
            "secret_redaction": True,
            "path_sandboxing": True,
            "rbac": True,
            "recent_policy_allows": allows,
            "recent_policy_denies": denies,
        },
        "control_narratives": [
            {
                "control": c,
                "implementation": (
                    "GuardRail enterprise MCP enforces RBAC, path sandboxing, "
                    "policy packs, audit logs, and secret redaction on agent tool calls."
                ),
            }
            for c in controls
        ],
    }
