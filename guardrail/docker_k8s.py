"""
Deeper Docker & Kubernetes configuration analysis (text heuristics + structure).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .infra_security import InfraFinding, scan_infra_security


_DOCKER_RULES: List[Tuple[str, str, str, str, str, str]] = [
    # pattern, rule_id, anomaly, severity, desc, rem
    (
        r"(?i)^\s*FROM\s+[^\s]+(?:\s+AS\s+\w+)?\s*$",
        "GR-DKR-000",
        "BASE_IMAGE_SEEN",
        "INFO",
        "Base image declaration found — pin digests for production reproducibility.",
        "Prefer image@sha256:... digests over floating tags like :latest.",
    ),
    (
        r"(?i)^\s*FROM\s+\S*:latest\b",
        "GR-DKR-001",
        "FLOATING_LATEST_TAG",
        "MEDIUM",
        "FROM ...:latest is mutable and non-reproducible.",
        "Pin to a specific version tag or digest.",
    ),
    (
        r"(?i)^\s*RUN\s+.*\bcurl\b.*\|\s*(?:ba)?sh",
        "GR-DKR-002",
        "CURL_PIPE_SHELL",
        "CRITICAL",
        "RUN pipes remote content into a shell.",
        "Download, verify checksum, then RUN the script from a local path.",
    ),
    (
        r"(?i)^\s*ADD\s+https?://",
        "GR-DKR-003",
        "ADD_REMOTE_URL",
        "HIGH",
        "ADD from remote URL is discouraged (opaque fetch).",
        "Use curl/wget with checksum verification or COPY local artifacts.",
    ),
    (
        r"(?i)--privileged",
        "GR-DKR-004",
        "DOCKER_PRIVILEGED_FLAG",
        "CRITICAL",
        "Privileged docker flag present.",
        "Remove --privileged; grant minimal capabilities.",
    ),
    (
        r"(?i)^\s*USER\s+0\s*$",
        "GR-DKR-005",
        "USER_ROOT_UID",
        "HIGH",
        "Container user set to UID 0 (root).",
        "Use a non-zero UID non-root user.",
    ),
]

_K8S_RULES: List[Tuple[str, str, str, str, str, str]] = [
    (
        r"(?i)allowPrivilegeEscalation\s*:\s*true",
        "GR-K8S-001",
        "ALLOW_PRIV_ESC",
        "HIGH",
        "allowPrivilegeEscalation enabled.",
        "Set allowPrivilegeEscalation: false.",
    ),
    (
        r"(?i)runAsUser\s*:\s*0\b",
        "GR-K8S-002",
        "RUN_AS_ROOT",
        "HIGH",
        "runAsUser: 0 runs as root.",
        "Set runAsNonRoot: true and a non-zero runAsUser.",
    ),
    (
        r"(?i)readOnlyRootFilesystem\s*:\s*false",
        "GR-K8S-003",
        "WRITABLE_ROOTFS",
        "MEDIUM",
        "Root filesystem is writable.",
        "Set readOnlyRootFilesystem: true when possible.",
    ),
    (
        r"(?i)capabilities\s*:\s*\n(?:[^\n]*\n)*?\s*add\s*:\s*\[[^\]]*ALL[^\]]*\]",
        "GR-K8S-004",
        "CAP_ADD_ALL",
        "CRITICAL",
        "Linux capabilities add ALL.",
        "Drop ALL and add only required capabilities.",
    ),
    (
        r"(?i)hostPath\s*:",
        "GR-K8S-005",
        "HOST_PATH_VOLUME",
        "HIGH",
        "hostPath volume mounts host filesystem into the pod.",
        "Avoid hostPath; use PVCs or emptyDir with tight policies.",
    ),
    (
        r"(?i)kind\s*:\s*Pod\b",
        "GR-K8S-INFO",
        "NAKED_POD",
        "INFO",
        "Bare Pod manifest — prefer Deployment/StatefulSet for restarts.",
        "Use a workload controller unless this is a one-shot Job.",
    ),
]


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _excerpt(text: str, idx: int) -> str:
    s = text.rfind("\n", 0, idx) + 1
    e = text.find("\n", idx)
    if e < 0:
        e = len(text)
    return text[s:e].strip()[:160]


def _apply_rules(content: str, rules: List[Tuple[str, str, str, str, str, str]]) -> List[InfraFinding]:
    out: List[InfraFinding] = []
    for pattern, rule_id, anomaly, severity, desc, rem in rules:
        # Skip pure INFO base image spam except latest/curl rules
        if rule_id == "GR-DKR-000":
            continue
        try:
            cre = re.compile(pattern, re.MULTILINE)
        except re.error:
            continue
        for m in cre.finditer(content):
            out.append(
                InfraFinding(
                    rule_id=rule_id,
                    anomaly_id=anomaly,
                    severity=severity,
                    technical_breakdown=desc,
                    remediation=rem,
                    line=_line_of(content, m.start()),
                    excerpt=_excerpt(content, m.start()),
                )
            )
    return out


def analyze_dockerfile(content: str) -> Dict[str, Any]:
    findings = _apply_rules(content, _DOCKER_RULES)
    # also general infra (USER root etc.)
    findings.extend(scan_infra_security(content))
    # de-dupe by (rule_id, line)
    seen = set()
    uniq = []
    for f in findings:
        k = (f.rule_id, f.line)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    return {
        "status": "OK",
        "kind": "dockerfile",
        "issue_count": len(uniq),
        "issues": [f.to_dict() for f in uniq],
    }


def analyze_kubernetes(content: str) -> Dict[str, Any]:
    findings = _apply_rules(content, _K8S_RULES)
    findings.extend(scan_infra_security(content))
    seen = set()
    uniq = []
    for f in findings:
        k = (f.rule_id, f.line, f.anomaly_id)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    return {
        "status": "OK",
        "kind": "kubernetes",
        "issue_count": len(uniq),
        "issues": [f.to_dict() for f in uniq],
    }


def analyze_container_config(content: str, *, filename: Optional[str] = None) -> Dict[str, Any]:
    """Auto-detect Dockerfile vs K8s vs generic compose."""
    name = (filename or "").lower()
    head = content[:500].lower()
    if "dockerfile" in name or re.search(r"(?m)^\s*FROM\s+\S+", content):
        r = analyze_dockerfile(content)
    elif "kind:" in head or "apiversion:" in head:
        r = analyze_kubernetes(content)
    else:
        # both
        d = analyze_dockerfile(content)
        k = analyze_kubernetes(content)
        issues = d["issues"] + k["issues"]
        r = {
            "status": "OK",
            "kind": "mixed",
            "issue_count": len(issues),
            "issues": issues,
        }
    return r
