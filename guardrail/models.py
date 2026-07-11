"""Shared data models for rules, findings, and audit responses."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_WEIGHT: Dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 1,
}


@dataclass(frozen=True)
class VulnerabilityRule:
    id: str
    name: str
    pattern: str
    severity: Severity
    description: str
    remediation: str
    # If True, only report when keyword context also matches nearby
    require_context: bool = False
    context_pattern: Optional[str] = None
    # Flags: "shell_true_only", "multiline", etc.
    flags: tuple = ()


@dataclass
class Finding:
    rule_id: str
    vulnerability_name: str
    severity: str
    description: str
    remediation: str
    line: int
    column: int
    excerpt_redacted: str
    match_length: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SafetyAuditResult:
    status: str
    risk_score: int = 0
    risk_level: str = "NONE"
    issue_count: int = 0
    issues: List[Finding] = field(default_factory=list)
    credits_remaining: Optional[int] = None
    scanned_bytes: int = 0
    truncated: bool = False
    mode: str = "local"
    notes: List[str] = field(default_factory=list)
    reason: Optional[str] = None
    action_required: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "status": self.status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "issue_count": self.issue_count,
            "issues": [i.to_dict() for i in self.issues],
            "scanned_bytes": self.scanned_bytes,
            "truncated": self.truncated,
            "mode": self.mode,
            "notes": self.notes,
        }
        if self.credits_remaining is not None:
            d["credits_remaining"] = self.credits_remaining
        if self.reason:
            d["reason"] = self.reason
        if self.action_required:
            d["action_required"] = self.action_required
        return d


@dataclass
class CostLineItem:
    resource: str
    provider: str
    unit_monthly_usd: float
    quantity: int
    estimated_monthly_usd: float
    evidence_line: int
    evidence_excerpt: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CostAuditResult:
    status: str
    cloud_provider: str
    estimated_monthly_usd: float = 0.0
    line_items: List[CostLineItem] = field(default_factory=list)
    unmatched_hints: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    disclaimer: str = (
        "Rough catalog estimate only — ignores region, reserved/spot pricing, "
        "storage growth, egress, and idle vs always-on usage."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "cloud_provider": self.cloud_provider,
            "estimated_monthly_usd": round(self.estimated_monthly_usd, 2),
            "line_items": [i.to_dict() for i in self.line_items],
            "unmatched_hints": self.unmatched_hints,
            "notes": self.notes,
            "disclaimer": self.disclaimer,
        }


def risk_level_from_score(score: int) -> str:
    if score <= 0:
        return "NONE"
    if score < 20:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 100:
        return "HIGH"
    return "CRITICAL"
