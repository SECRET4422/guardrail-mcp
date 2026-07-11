"""Enterprise configuration loader (YAML/JSON/env)."""

from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class TenantConfig:
    tenant_id: str
    name: str = ""
    tier: str = "standard"  # free | standard | enterprise
    api_keys: List[str] = field(default_factory=list)
    roles: Dict[str, str] = field(default_factory=dict)  # api_key_hash_or_id -> role
    allowed_tools: List[str] = field(default_factory=list)  # empty = all permitted by role
    denied_tools: List[str] = field(default_factory=list)
    allowed_roots: List[str] = field(default_factory=list)  # path sandbox
    max_source_bytes: int = 512_000
    max_files_per_scan: int = 2000
    max_workers: int = 16
    requests_per_minute: int = 120
    monthly_scan_quota: int = 50_000
    scans_used: int = 0
    budget_limit_usd: float = 500.0
    fail_on_severity: List[str] = field(default_factory=lambda: ["CRITICAL"])
    max_risk_score: int = 100
    policy_pack: str = "default"
    enabled: bool = True


@dataclass
class EnterpriseConfig:
    enabled: bool = False
    require_auth: bool = False
    jwt_secret: str = ""
    jwt_issuer: str = "guardrail-mcp"
    jwt_audience: str = "guardrail"
    jwt_ttl_seconds: int = 3600
    admin_api_keys: List[str] = field(default_factory=list)
    default_role: str = "scanner"
    audit_log_path: str = ""
    audit_stdout: bool = True
    metrics_enabled: bool = True
    allow_local_unauthenticated: bool = True
    global_allowed_roots: List[str] = field(default_factory=list)
    blocked_tools_global: List[str] = field(default_factory=list)
    policy_packs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tenants: Dict[str, TenantConfig] = field(default_factory=dict)
    rate_limit_enabled: bool = True
    correlation_header: str = "X-Request-Id"
    data_residency: str = "local"
    retention_days: int = 90
    compliance_frameworks: List[str] = field(
        default_factory=lambda: ["SOC2", "ISO27001", "OWASP-ASVS"]
    )

    def to_public_dict(self) -> Dict[str, Any]:
        """Non-secret config snapshot for health/admin."""
        return {
            "enabled": self.enabled,
            "require_auth": self.require_auth,
            "allow_local_unauthenticated": self.allow_local_unauthenticated,
            "metrics_enabled": self.metrics_enabled,
            "rate_limit_enabled": self.rate_limit_enabled,
            "data_residency": self.data_residency,
            "retention_days": self.retention_days,
            "compliance_frameworks": list(self.compliance_frameworks),
            "tenant_count": len(self.tenants),
            "policy_packs": list(self.policy_packs.keys()),
            "global_allowed_roots": list(self.global_allowed_roots),
            "blocked_tools_global": list(self.blocked_tools_global),
            "audit_stdout": self.audit_stdout,
            "audit_log_configured": bool(self.audit_log_path),
            "jwt_configured": bool(self.jwt_secret),
        }


_DEFAULT_POLICY_PACKS: Dict[str, Dict[str, Any]] = {
    "default": {
        "description": "Balanced agent guardrail",
        "fail_on_severity": ["CRITICAL"],
        "max_risk_score": 100,
        "block_tools_on_reject": False,
        "required_engines": ["regex"],
        "compliance_controls": ["CC6.1", "CC7.1"],
    },
    "strict": {
        "description": "Enterprise gate — fail on HIGH+",
        "fail_on_severity": ["CRITICAL", "HIGH"],
        "max_risk_score": 40,
        "block_tools_on_reject": True,
        "required_engines": ["regex", "ast"],
        "compliance_controls": ["CC6.1", "CC6.6", "CC7.1", "CC7.2"],
    },
    "soc2": {
        "description": "SOC2-oriented change control scanning",
        "fail_on_severity": ["CRITICAL", "HIGH"],
        "max_risk_score": 50,
        "block_tools_on_reject": True,
        "require_sarif_on_repo_scan": True,
        "compliance_controls": ["CC6.1", "CC6.8", "CC8.1"],
    },
    "pci": {
        "description": "Heightened secret + crypto posture",
        "fail_on_severity": ["CRITICAL", "HIGH"],
        "max_risk_score": 25,
        "block_tools_on_reject": True,
        "extra_notes": ["Treat any secret finding as release-blocking."],
        "compliance_controls": ["PCI-DSS-6.5", "PCI-DSS-8.3"],
    },
}


def _parse_tenant(tid: str, raw: Dict[str, Any]) -> TenantConfig:
    return TenantConfig(
        tenant_id=tid,
        name=str(raw.get("name") or tid),
        tier=str(raw.get("tier") or "standard"),
        api_keys=[str(k) for k in (raw.get("api_keys") or [])],
        roles={str(k): str(v) for k, v in (raw.get("roles") or {}).items()},
        allowed_tools=[str(x) for x in (raw.get("allowed_tools") or [])],
        denied_tools=[str(x) for x in (raw.get("denied_tools") or [])],
        allowed_roots=[str(x) for x in (raw.get("allowed_roots") or [])],
        max_source_bytes=int(raw.get("max_source_bytes") or 512_000),
        max_files_per_scan=int(raw.get("max_files_per_scan") or 2000),
        max_workers=int(raw.get("max_workers") or 16),
        requests_per_minute=int(raw.get("requests_per_minute") or 120),
        monthly_scan_quota=int(raw.get("monthly_scan_quota") or 50_000),
        scans_used=int(raw.get("scans_used") or 0),
        budget_limit_usd=float(raw.get("budget_limit_usd") or 500),
        fail_on_severity=[str(x).upper() for x in (raw.get("fail_on_severity") or ["CRITICAL"])],
        max_risk_score=int(raw.get("max_risk_score") or 100),
        policy_pack=str(raw.get("policy_pack") or "default"),
        enabled=bool(raw.get("enabled", True)),
    )


def _from_mapping(data: Dict[str, Any]) -> EnterpriseConfig:
    packs = deepcopy(_DEFAULT_POLICY_PACKS)
    packs.update(data.get("policy_packs") or {})
    tenants_raw = data.get("tenants") or {}
    tenants = {tid: _parse_tenant(tid, cfg or {}) for tid, cfg in tenants_raw.items()}
    return EnterpriseConfig(
        enabled=bool(data.get("enabled", False)),
        require_auth=bool(data.get("require_auth", False)),
        jwt_secret=str(data.get("jwt_secret") or os.environ.get("GUARDRAIL_JWT_SECRET") or ""),
        jwt_issuer=str(data.get("jwt_issuer") or "guardrail-mcp"),
        jwt_audience=str(data.get("jwt_audience") or "guardrail"),
        jwt_ttl_seconds=int(data.get("jwt_ttl_seconds") or 3600),
        admin_api_keys=[str(k) for k in (data.get("admin_api_keys") or [])],
        default_role=str(data.get("default_role") or "scanner"),
        audit_log_path=str(data.get("audit_log_path") or os.environ.get("GUARDRAIL_AUDIT_LOG", "")),
        audit_stdout=bool(data.get("audit_stdout", True)),
        metrics_enabled=bool(data.get("metrics_enabled", True)),
        allow_local_unauthenticated=bool(data.get("allow_local_unauthenticated", True)),
        global_allowed_roots=[str(x) for x in (data.get("global_allowed_roots") or [])],
        blocked_tools_global=[str(x) for x in (data.get("blocked_tools_global") or [])],
        policy_packs=packs,
        tenants=tenants,
        rate_limit_enabled=bool(data.get("rate_limit_enabled", True)),
        correlation_header=str(data.get("correlation_header") or "X-Request-Id"),
        data_residency=str(data.get("data_residency") or "local"),
        retention_days=int(data.get("retention_days") or 90),
        compliance_frameworks=[
            str(x) for x in (data.get("compliance_frameworks") or ["SOC2", "ISO27001", "OWASP-ASVS"])
        ],
    )


def _load_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError:
            # minimal YAML subset via JSON if file is JSON-compatible; else key: value
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "PyYAML not installed and config is not JSON. "
                    "pip install pyyaml  OR use enterprise.json"
                ) from exc
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("Enterprise config root must be a mapping")
        return data
    return json.loads(text)


def load_enterprise_config(path: Optional[str] = None) -> EnterpriseConfig:
    """
    Load enterprise config from:
      1. explicit path
      2. GUARDRAIL_ENTERPRISE_CONFIG env
      3. ./config/enterprise.yaml|json
      4. env-only defaults (enterprise off unless GUARDRAIL_ENTERPRISE=1)
    """
    candidates: List[Path] = []
    if path:
        candidates.append(Path(path))
    env_path = os.environ.get("GUARDRAIL_ENTERPRISE_CONFIG")
    if env_path:
        candidates.append(Path(env_path))
    candidates.extend(
        [
            Path("config/enterprise.yaml"),
            Path("config/enterprise.yml"),
            Path("config/enterprise.json"),
            Path("/etc/guardrail/enterprise.yaml"),
        ]
    )

    data: Dict[str, Any] = {}
    for p in candidates:
        if p.is_file():
            data = _load_file(p)
            break

    cfg = _from_mapping(data)

    # Env overrides
    if _env_bool("GUARDRAIL_ENTERPRISE", cfg.enabled):
        cfg.enabled = True
    if _env_bool("GUARDRAIL_REQUIRE_AUTH", cfg.require_auth):
        cfg.require_auth = True
    if os.environ.get("GUARDRAIL_JWT_SECRET"):
        cfg.jwt_secret = os.environ["GUARDRAIL_JWT_SECRET"]
    if os.environ.get("GUARDRAIL_AUDIT_LOG"):
        cfg.audit_log_path = os.environ["GUARDRAIL_AUDIT_LOG"]
    admin = os.environ.get("GUARDRAIL_ADMIN_API_KEY")
    if admin and admin not in cfg.admin_api_keys:
        cfg.admin_api_keys.append(admin)
    roots = os.environ.get("GUARDRAIL_ALLOWED_ROOTS")
    if roots:
        cfg.global_allowed_roots = [r.strip() for r in roots.split(os.pathsep) if r.strip()]

    # Bootstrap demo tenant when enterprise on but empty
    if cfg.enabled and not cfg.tenants:
        demo_key = os.environ.get("GUARDRAIL_DEMO_API_KEY", "gr_demo_enterprise_key_change_me")
        cfg.tenants["default"] = TenantConfig(
            tenant_id="default",
            name="Default Enterprise Tenant",
            tier="enterprise",
            api_keys=[demo_key],
            roles={demo_key: "admin"},
            policy_pack="strict",
            allowed_roots=list(cfg.global_allowed_roots),
        )

    # Ensure default packs always present
    for k, v in _DEFAULT_POLICY_PACKS.items():
        cfg.policy_packs.setdefault(k, deepcopy(v))

    return cfg


class ConfigRegistry:
    """Process-wide reloadable enterprise config."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cfg = load_enterprise_config()

    def get(self) -> EnterpriseConfig:
        with self._lock:
            return self._cfg

    def reload(self, path: Optional[str] = None) -> EnterpriseConfig:
        with self._lock:
            self._cfg = load_enterprise_config(path)
            return self._cfg

    def replace(self, cfg: EnterpriseConfig) -> None:
        with self._lock:
            self._cfg = cfg


registry = ConfigRegistry()
