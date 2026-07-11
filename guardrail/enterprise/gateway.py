"""
Enterprise gateway: authz → rate limit → sandbox → tool → policy → audit.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from .. import __version__
from ..tools_catalog import TOOLS as BASE_TOOLS
from ..tools_catalog import call_tool as base_call_tool
from .audit import get_audit_logger, redact_args_for_audit
from .auth import Principal, authenticate, issue_jwt
from .config import TenantConfig, registry
from .context import RequestContext, reset_context, set_context
from .metrics import metrics
from .policy import build_compliance_report, evaluate_policy
from .rate_limit import limiter
from .rbac import authorize_tool
from .sandbox import merge_roots, validate_path

# Tools that accept filesystem paths
_PATH_TOOLS = {
    "scan_repository",
    "scan_git_diff",
    "scan_dependencies",
    "generate_sbom",
    "full_pipeline",
}

# Tools that should run policy packs on output
_POLICY_TOOLS = {
    "audit_code_safety",
    "audit_infra_security",
    "audit_container_config",
    "scan_repository",
    "scan_git_diff",
    "full_pipeline",
}


def _tenant(cfg, tenant_id: str) -> Optional[TenantConfig]:
    return cfg.tenants.get(tenant_id)


def _enterprise_tools() -> list:
    return [
        {
            "name": "enterprise_health",
            "description": "Enterprise health, metrics, and non-secret config status.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "enterprise_policy_status",
            "description": "Show active policy pack and gate thresholds for the caller tenant.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "evaluate_policy",
            "description": "Run policy pack evaluation against a prior scan result object.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "result": {"type": "object"},
                    "policy_pack": {"type": "string"},
                },
                "required": ["result"],
            },
        },
        {
            "name": "compliance_report",
            "description": "Generate a lightweight compliance evidence report for auditors.",
            "inputSchema": {
                "type": "object",
                "properties": {"frameworks": {"type": "array", "items": {"type": "string"}}},
            },
        },
        {
            "name": "list_audit_events",
            "description": "List recent in-memory audit events (operator+).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 50},
                    "tool": {"type": "string"},
                },
            },
        },
        {
            "name": "issue_access_token",
            "description": "Issue a short-lived JWT (admin). Requires GUARDRAIL_JWT_SECRET.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "role": {"type": "string", "enum": ["viewer", "scanner", "operator", "admin"]},
                    "ttl_seconds": {"type": "integer", "default": 3600},
                },
                "required": ["subject", "tenant_id", "role"],
            },
        },
        {
            "name": "reload_enterprise_config",
            "description": "Reload enterprise YAML/JSON from disk (admin).",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
        {
            "name": "manage_tenant",
            "description": "Inspect or update in-memory tenant quota counters (admin).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["get", "list", "reset_quota"],
                    },
                    "tenant_id": {"type": "string"},
                },
                "required": ["action"],
            },
        },
    ]


def list_all_tools() -> list:
    # de-dupe by name
    seen = set()
    out = []
    for t in list(BASE_TOOLS) + _enterprise_tools():
        if t["name"] in seen:
            continue
        seen.add(t["name"])
        out.append(t)
    return out


def _handle_enterprise_tool(
    name: str,
    args: Dict[str, Any],
    principal: Principal,
    cfg,
) -> Dict[str, Any]:
    tenant = _tenant(cfg, principal.tenant_id)
    pack_name = (tenant.policy_pack if tenant else None) or "default"
    pack = cfg.policy_packs.get(pack_name) or {}

    if name == "enterprise_health":
        return {
            "status": "OK",
            "version": __version__,
            "edition": "enterprise",
            "enterprise": cfg.to_public_dict(),
            "metrics": metrics.snapshot() if cfg.metrics_enabled else {},
            "principal": {
                "subject": principal.subject,
                "tenant_id": principal.tenant_id,
                "role": principal.role,
                "auth_method": principal.auth_method,
            },
        }

    if name == "enterprise_policy_status":
        return {
            "status": "OK",
            "tenant_id": principal.tenant_id,
            "policy_pack": pack_name,
            "pack": pack,
            "fail_on_severity": (tenant.fail_on_severity if tenant else pack.get("fail_on_severity")),
            "max_risk_score": (tenant.max_risk_score if tenant else pack.get("max_risk_score")),
        }

    if name == "evaluate_policy":
        pname = args.get("policy_pack") or pack_name
        p = cfg.policy_packs.get(pname) or pack
        return evaluate_policy(
            args.get("result") or {},
            policy_pack=p,
            fail_on_severity=tenant.fail_on_severity if tenant else None,
            max_risk_score=tenant.max_risk_score if tenant else None,
        )

    if name == "compliance_report":
        audit = get_audit_logger(cfg.audit_log_path, cfg.audit_stdout)
        recent = audit.recent(limit=100, tenant_id=principal.tenant_id)
        decisions = [
            {"decision": (e.get("policy_decision") or e.get("decision"))}
            for e in recent
            if e.get("policy_decision") or e.get("decision")
        ]
        frameworks = args.get("frameworks") or cfg.compliance_frameworks
        return build_compliance_report(
            frameworks=frameworks,
            recent_decisions=decisions,
            tenant_id=principal.tenant_id,
            policy_pack_name=pack_name,
            pack=pack,
        )

    if name == "list_audit_events":
        audit = get_audit_logger(cfg.audit_log_path, cfg.audit_stdout)
        return {
            "status": "OK",
            "events": audit.recent(
                limit=int(args.get("limit") or 50),
                tenant_id=None if principal.role == "admin" else principal.tenant_id,
                tool=args.get("tool"),
            ),
        }

    if name == "issue_access_token":
        if not cfg.jwt_secret:
            return {
                "status": "ERROR",
                "reason": "GUARDRAIL_JWT_SECRET / jwt_secret not configured",
            }
        tok = issue_jwt(
            secret=cfg.jwt_secret,
            subject=str(args.get("subject")),
            tenant_id=str(args.get("tenant_id")),
            role=str(args.get("role") or "scanner"),
            issuer=cfg.jwt_issuer,
            audience=cfg.jwt_audience,
            ttl_seconds=int(args.get("ttl_seconds") or cfg.jwt_ttl_seconds),
        )
        return {
            "status": "OK",
            "token_type": "Bearer",
            "access_token": tok,
            "expires_in": int(args.get("ttl_seconds") or cfg.jwt_ttl_seconds),
        }

    if name == "reload_enterprise_config":
        new_cfg = registry.reload(args.get("path"))
        return {"status": "OK", "config": new_cfg.to_public_dict()}

    if name == "manage_tenant":
        action = args.get("action")
        if action == "list":
            return {
                "status": "OK",
                "tenants": [
                    {
                        "tenant_id": t.tenant_id,
                        "name": t.name,
                        "tier": t.tier,
                        "enabled": t.enabled,
                        "policy_pack": t.policy_pack,
                        "monthly_scan_quota": t.monthly_scan_quota,
                        "scans_used": t.scans_used + limiter.get_quota_used(t.tenant_id),
                        "requests_per_minute": t.requests_per_minute,
                    }
                    for t in cfg.tenants.values()
                ],
            }
        tid = str(args.get("tenant_id") or "")
        t = cfg.tenants.get(tid)
        if not t:
            return {"status": "ERROR", "reason": f"Unknown tenant {tid}"}
        if action == "get":
            return {
                "status": "OK",
                "tenant": {
                    "tenant_id": t.tenant_id,
                    "name": t.name,
                    "tier": t.tier,
                    "enabled": t.enabled,
                    "policy_pack": t.policy_pack,
                    "allowed_roots": t.allowed_roots,
                    "denied_tools": t.denied_tools,
                    "monthly_scan_quota": t.monthly_scan_quota,
                    "scans_used": t.scans_used + limiter.get_quota_used(t.tenant_id),
                },
            }
        if action == "reset_quota":
            limiter._quota_used[tid] = 0  # noqa: SLF001 — intentional admin op
            t.scans_used = 0
            return {"status": "OK", "tenant_id": tid, "scans_used": 0}
        return {"status": "ERROR", "reason": f"Unknown action {action}"}

    return {"status": "ERROR", "reason": f"Unknown enterprise tool {name}"}


def enterprise_call_tool(
    name: str,
    arguments: Optional[Dict[str, Any]] = None,
    *,
    authorization: Optional[str] = None,
    api_key: Optional[str] = None,
    transport: str = "stdio",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    args = dict(arguments or {})
    cfg = registry.get()
    cid = correlation_id or str(uuid.uuid4())
    started = time.perf_counter()

    principal, err = authenticate(
        cfg,
        authorization=authorization or args.pop("authorization", None),
        api_key=api_key or args.pop("api_key", None),
        tenant_id_hint=args.get("tenant_id"),
        transport=transport,
    )
    if err or principal is None:
        metrics.inc_auth_fail()
        audit = get_audit_logger(cfg.audit_log_path, cfg.audit_stdout)
        audit.emit(
            {
                "type": "auth_failure",
                "tool": name,
                "reason": err,
                "correlation_id": cid,
                "transport": transport,
            }
        )
        return {
            "status": "AUTH_FAILED",
            "reason": err or "Unauthorized",
            "correlation_id": cid,
        }

    ctx = RequestContext(
        principal=principal,
        correlation_id=cid,
        transport=transport,
        enterprise_enabled=cfg.enabled,
    )
    token = set_context(ctx)
    audit = get_audit_logger(cfg.audit_log_path, cfg.audit_stdout)

    try:
        tenant = _tenant(cfg, principal.tenant_id)

        # RBAC
        ok, why = authorize_tool(
            principal.role,
            name,
            tenant_allowed=tenant.allowed_tools if tenant else None,
            tenant_denied=tenant.denied_tools if tenant else None,
            global_blocked=cfg.blocked_tools_global,
        )
        if not ok:
            audit.emit(
                {
                    "type": "authz_denied",
                    "tool": name,
                    "reason": why,
                    "tenant_id": principal.tenant_id,
                    "subject": principal.subject,
                    "role": principal.role,
                    "correlation_id": cid,
                }
            )
            return {
                "status": "FORBIDDEN",
                "reason": why,
                "correlation_id": cid,
                "role": principal.role,
            }

        # Rate limit + quota
        if cfg.enabled and cfg.rate_limit_enabled and tenant:
            allowed, retry = limiter.allow(
                f"{principal.tenant_id}:{principal.subject}",
                tenant.requests_per_minute,
            )
            if not allowed:
                metrics.inc_rate_limit()
                return {
                    "status": "RATE_LIMITED",
                    "reason": "Requests per minute exceeded",
                    "retry_after_seconds": round(retry, 2),
                    "correlation_id": cid,
                }
            used = tenant.scans_used + limiter.get_quota_used(principal.tenant_id)
            q_ok, _ = limiter.check_quota(
                principal.tenant_id, used, tenant.monthly_scan_quota
            )
            if not q_ok and name in _POLICY_TOOLS | _PATH_TOOLS:
                return {
                    "status": "QUOTA_EXCEEDED",
                    "reason": "Monthly scan quota exceeded",
                    "scans_used": used,
                    "monthly_scan_quota": tenant.monthly_scan_quota,
                    "correlation_id": cid,
                }

        # Path sandbox
        if name in _PATH_TOOLS and "path" in args:
            roots = merge_roots(
                cfg.global_allowed_roots,
                tenant.allowed_roots if tenant else [],
            )
            if cfg.enabled and roots:
                ok_p, msg, resolved = validate_path(str(args["path"]), roots)
                if not ok_p:
                    return {
                        "status": "SANDBOX_DENIED",
                        "reason": msg,
                        "correlation_id": cid,
                    }
                args["path"] = resolved

        # Enforce tenant max_files / workers if present
        if tenant:
            if "max_files" in args and args["max_files"]:
                args["max_files"] = min(int(args["max_files"]), tenant.max_files_per_scan)
            if "workers" in args and args["workers"]:
                args["workers"] = min(int(args["workers"]), tenant.max_workers)

        # Dispatch
        if name in {t["name"] for t in _enterprise_tools()}:
            result = _handle_enterprise_tool(name, args, principal, cfg)
        else:
            result = base_call_tool(name, args)

        # Policy gate
        if name in _POLICY_TOOLS and isinstance(result, dict) and result.get("status") == "OK":
            pack_name = (tenant.policy_pack if tenant else None) or "default"
            pack = cfg.policy_packs.get(pack_name) or {}
            result = evaluate_policy(
                result,
                policy_pack=pack,
                fail_on_severity=tenant.fail_on_severity if tenant else None,
                max_risk_score=tenant.max_risk_score if tenant else None,
            )
            if result.get("policy_decision") == "DENY":
                metrics.inc_policy_deny()

        # Quota consume on successful scans
        if (
            cfg.enabled
            and tenant
            and isinstance(result, dict)
            and result.get("status") == "OK"
            and name in _POLICY_TOOLS | _PATH_TOOLS
        ):
            limiter.increment_quota(principal.tenant_id, 1)

        # Envelope
        if isinstance(result, dict):
            result.setdefault("correlation_id", cid)
            result.setdefault(
                "enterprise",
                {
                    "edition": "enterprise" if cfg.enabled else "community",
                    "tenant_id": principal.tenant_id,
                    "role": principal.role,
                    "version": __version__,
                },
            )

        latency = (time.perf_counter() - started) * 1000
        metrics.record_call(
            name, latency, error=isinstance(result, dict) and result.get("status") not in ("OK", None)
            and not str(result.get("status", "OK")).startswith("2")
            and result.get("status")
            in {
                "ERROR",
                "AUTH_FAILED",
                "FORBIDDEN",
                "RATE_LIMITED",
                "QUOTA_EXCEEDED",
                "SANDBOX_DENIED",
                "ACCESS_DENIED",
            },
        )

        audit.emit(
            {
                "type": "tool_call",
                "tool": name,
                "tenant_id": principal.tenant_id,
                "subject": principal.subject,
                "role": principal.role,
                "auth_method": principal.auth_method,
                "correlation_id": cid,
                "transport": transport,
                "latency_ms": round(latency, 2),
                "status": result.get("status") if isinstance(result, dict) else "OK",
                "policy_decision": (
                    result.get("policy_decision") if isinstance(result, dict) else None
                ),
                "args": redact_args_for_audit(name, args),
            }
        )
        return result
    finally:
        reset_context(token)
