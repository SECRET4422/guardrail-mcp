"""Infrastructure-as-code security + budget checks (text heuristics)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from .cost import CLOUD_PRICING_CATALOG, run_core_cost_audit


DEFAULT_BUDGET_USD = 500.0


@dataclass
class InfraFinding:
    rule_id: str
    anomaly_id: str
    severity: str
    technical_breakdown: str
    remediation: str
    line: Optional[int] = None
    excerpt: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


# (pattern, rule_id, anomaly_id, severity, description, remediation)
# Patterns are simple substring or regex.
_INFRA_CHECKS: List[Tuple[str, bool, str, str, str, str, str]] = [
    (
        r"(?m)^\s*USER\s+root\s*$",
        True,
        "GR-INFRA-001",
        "PRIVILEGED_DOCKER_USER",
        "HIGH",
        "Dockerfile USER root — process runs as root inside the container.",
        "Create a non-root user and switch with USER; drop capabilities.",
    ),
    (
        r"0\.0\.0\.0/0",
        True,
        "GR-INFRA-002",
        "EXPOSED_ANY_INGRESS",
        "HIGH",
        "CIDR 0.0.0.0/0 allows unrestricted IPv4 ingress (common SG/NACL misconfig).",
        "Restrict CIDRs to known admin/VPN ranges; prefer private subnets + bastion.",
    ),
    (
        r"::/0",
        True,
        "GR-INFRA-002b",
        "EXPOSED_ANY_INGRESS_V6",
        "HIGH",
        "IPv6 ::/0 allows unrestricted ingress.",
        "Restrict IPv6 source ranges similarly to IPv4.",
    ),
    (
        r"(?i)privileged\s*:\s*true",
        True,
        "GR-INFRA-003",
        "PRIVILEGED_CONTAINER_RUNTIME",
        "CRITICAL",
        "privileged: true grants host-level capabilities (container escape risk).",
        "Remove privileged mode; grant only required capabilities.",
    ),
    (
        r"(?i)host_network\s*=\s*true|hostNetwork\s*:\s*true",
        True,
        "GR-INFRA-004",
        "HOST_NETWORK_NAMESPACE",
        "HIGH",
        "Pod/container shares the host network namespace.",
        "Avoid hostNetwork unless required; use Services/Ingress instead.",
    ),
    (
        r"(?i)host_pid\s*=\s*true|hostPID\s*:\s*true",
        True,
        "GR-INFRA-005",
        "HOST_PID_NAMESPACE",
        "HIGH",
        "Pod shares host PID namespace — sensitive process visibility.",
        "Disable hostPID unless an operator agent truly needs it.",
    ),
    (
        r"(?i)acl\s*=\s*[\"']public-read[\"']|public-read-write",
        True,
        "GR-INFRA-006",
        "PUBLIC_OBJECT_STORAGE_ACL",
        "CRITICAL",
        "Object storage ACL appears world-readable/writable.",
        "Use private ACLs + CloudFront/signed URLs; block public access at account level.",
    ),
    (
        r"(?i)disable_api_termination\s*=\s*false",
        True,
        "GR-INFRA-007",
        "TERMINATION_PROTECTION_OFF",
        "MEDIUM",
        "API termination protection disabled on a resource that often should be protected.",
        "Enable termination protection for production stateful instances.",
    ),
    (
        r"(?i)encrypted\s*=\s*false",
        True,
        "GR-INFRA-008",
        "ENCRYPTION_DISABLED",
        "HIGH",
        "encrypted = false found — data-at-rest encryption disabled.",
        "Enable encryption with a managed KMS key for disks/buckets/queues.",
    ),
    (
        r"(?i)iam_instance_profile|aws_access_key_id\s*=",
        True,
        "GR-INFRA-009",
        "STATIC_CLOUD_CREDS_HINT",
        "MEDIUM",
        "Possible static cloud credentials or instance profile wiring — review least privilege.",
        "Prefer short-lived roles/OIDC; never commit long-lived access keys.",
    ),
]


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _line_excerpt(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    if end < 0:
        end = len(text)
    return text[start:end].strip()[:160]


def scan_infra_security(content: str) -> List[InfraFinding]:
    findings: List[InfraFinding] = []
    if not content:
        return findings

    for pattern, is_regex, rule_id, anomaly_id, severity, desc, rem in _INFRA_CHECKS:
        if is_regex:
            for m in re.finditer(pattern, content):
                findings.append(
                    InfraFinding(
                        rule_id=rule_id,
                        anomaly_id=anomaly_id,
                        severity=severity,
                        technical_breakdown=desc,
                        remediation=rem,
                        line=_line_of(content, m.start()),
                        excerpt=_line_excerpt(content, m.start()),
                    )
                )
        else:
            start = 0
            while True:
                idx = content.find(pattern, start)
                if idx < 0:
                    break
                findings.append(
                    InfraFinding(
                        rule_id=rule_id,
                        anomaly_id=anomaly_id,
                        severity=severity,
                        technical_breakdown=desc,
                        remediation=rem,
                        line=_line_of(content, idx),
                        excerpt=_line_excerpt(content, idx),
                    )
                )
                start = idx + len(pattern)
    return findings


def deep_analyze_infra(
    iac_content: str,
    provider: str = "aws",
    budget_limit_usd: float = DEFAULT_BUDGET_USD,
) -> Dict[str, Any]:
    """
    Combined cost estimate + infrastructure security heuristics.
    """
    cost = run_core_cost_audit(iac_content or "", provider)
    sec = scan_infra_security(iac_content or "")

    total = float(cost.get("estimated_monthly_usd") or 0.0)
    over = total > float(budget_limit_usd)

    # Severity rollup
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sec_sorted = sorted(sec, key=lambda f: (order.get(f.severity, 9), f.line or 0))

    verdict = "APPROVED"
    if any(f.severity == "CRITICAL" for f in sec_sorted) or over:
        verdict = "REJECTED"
    elif any(f.severity == "HIGH" for f in sec_sorted):
        verdict = "REVIEW_REQUIRED"

    return {
        "status": cost.get("status", "OK"),
        "security_verdict": verdict,
        "projected_monthly_burn_usd": round(total, 2),
        "projected_monthly_burn": f"${total:,.2f}",
        "budget_limit_usd": budget_limit_usd,
        "budget_limit_exceeded": over,
        "cloud_provider": cost.get("cloud_provider", provider),
        "cost": cost,
        "security_issues": [f.to_dict() for f in sec_sorted],
        "security_issue_count": len(sec_sorted),
        "notes": (cost.get("notes") or [])
        + [
            "Infra security checks are substring/regex heuristics on config text.",
            f"Budget gate default is ${budget_limit_usd:,.2f}/month estimated catalog burn.",
        ],
        "disclaimer": cost.get("disclaimer"),
    }
