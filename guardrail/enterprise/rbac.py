"""Role-based access control for MCP tools."""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Set

# Roles: escalating privileges
ROLES = ("viewer", "scanner", "operator", "admin")

# Tool permissions by role (inherited upward)
_ROLE_TOOLS: Dict[str, FrozenSet[str]] = {
    "viewer": frozenset(
        {
            "export_sarif",
            "generate_sbom",
            "enterprise_health",
            "enterprise_policy_status",
        }
    ),
    "scanner": frozenset(
        {
            "audit_code_safety",
            "audit_cloud_cost",
            "audit_infra_security",
            "audit_container_config",
            "scan_repository",
            "scan_git_diff",
            "scan_dependencies",
            "suggest_fixes",
            "full_pipeline",
            "evaluate_policy",
            "export_sarif",
            "generate_sbom",
            "enterprise_health",
            "enterprise_policy_status",
            "list_plugins",
            "engine_status",
            "security_score",
            "scan_history",
        }
    ),
    "operator": frozenset(
        {
            "compliance_report",
            "list_audit_events",
        }
    ),
    "admin": frozenset(
        {
            "manage_tenant",
            "reload_enterprise_config",
            "issue_access_token",
        }
    ),
}


def effective_tools(role: str) -> Set[str]:
    role = (role or "scanner").lower()
    if role not in ROLES:
        role = "scanner"
    allowed: Set[str] = set()
    for r in ROLES:
        allowed |= set(_ROLE_TOOLS.get(r, frozenset()))
        if r == role:
            break
    # admin gets everything in matrix
    if role == "admin":
        for s in _ROLE_TOOLS.values():
            allowed |= set(s)
    return allowed


def authorize_tool(
    role: str,
    tool: str,
    *,
    tenant_allowed: Optional[list] = None,
    tenant_denied: Optional[list] = None,
    global_blocked: Optional[list] = None,
) -> tuple[bool, str]:
    if tool in (global_blocked or []):
        return False, f"Tool '{tool}' is globally blocked by enterprise policy"

    if tenant_denied and tool in tenant_denied:
        return False, f"Tool '{tool}' is denied for this tenant"

    if tenant_allowed:
        if tool not in tenant_allowed:
            return False, f"Tool '{tool}' is not in tenant allow-list"

    allowed = effective_tools(role)
    # Unknown tools: only admin
    if tool not in allowed:
        # allow any tool for admin via wildcard behavior
        if (role or "").lower() == "admin":
            return True, "ok"
        return False, f"Role '{role}' is not permitted to call '{tool}'"
    return True, "ok"
