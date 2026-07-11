"""Shared MCP/HTTP tool descriptors and dispatch helpers."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .autofix_ai import batch_ai_fixes, generate_ai_fix
from .cost import run_core_cost_audit
from .dashboard import compute_security_score, history, record_scan, record_score, score_history
from .deps import scan_dependencies
from .docker_k8s import analyze_container_config
from .fixes import generate_fixes_for_issues
from .git_scan import scan_git_diff
from .hybrid_scan import hybrid_scan
from .infra_security import deep_analyze_infra
from .languages import detect_language, scan_language
from .pipeline import run_full_pipeline
from .plugins import get_plugin_registry
from .repo_scan import scan_repository
from .safety import run_core_safety_audit
from .sarif_export import findings_to_sarif
from .sbom import generate_cyclonedx, generate_spdx
from .treesitter_engine import treesitter_status

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "audit_code_safety",
        "description": (
            "Hybrid multi-engine scan: secrets regex, Python AST + advanced multi-hop taint, "
            "tree-sitter structural sinks, language grids, custom rules/plugins. "
            "Returns redacted issues, engines used, risk score, security_verdict."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {"type": "string"},
                "tenant_id": {"type": "string"},
                "filename": {"type": "string"},
                "language": {"type": "string"},
                "use_ast": {"type": "boolean", "default": True},
                "use_taint": {"type": "boolean", "default": True},
                "use_treesitter": {"type": "boolean", "default": True},
                "use_plugins": {"type": "boolean", "default": True},
                "hybrid": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use full hybrid engine (recommended).",
                },
            },
            "required": ["source_code"],
        },
    },
    {
        "name": "audit_cloud_cost",
        "description": "Rough AWS/GCP monthly SKU catalog estimate from IaC text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "infrastructure_content": {"type": "string"},
                "cloud_provider": {"type": "string", "enum": ["aws", "gcp"]},
            },
            "required": ["infrastructure_content", "cloud_provider"],
        },
    },
    {
        "name": "audit_infra_security",
        "description": "IaC misconfigs + budget gate on estimated monthly burn.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "infrastructure_content": {"type": "string"},
                "cloud_provider": {"type": "string", "enum": ["aws", "gcp"], "default": "aws"},
                "budget_limit_usd": {"type": "number", "default": 500},
            },
            "required": ["infrastructure_content"],
        },
    },
    {
        "name": "scan_repository",
        "description": "Parallel recursive repo scan with optional incremental cache.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "workers": {"type": "integer"},
                "max_files": {"type": "integer", "default": 2000},
                "use_ast": {"type": "boolean", "default": True},
                "incremental": {"type": "boolean", "default": True},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_git_diff",
        "description": "Scan only files changed in a git range (PR/diff) or staged changes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "base": {"type": "string", "default": "HEAD~1"},
                "head": {"type": "string", "default": "HEAD"},
                "staged": {"type": "boolean", "default": False},
                "use_ast": {"type": "boolean", "default": True},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_dependencies",
        "description": "Dependency inventory + optional OSV CVE query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "use_network": {"type": "boolean", "default": False},
                "run_pip_audit": {"type": "boolean", "default": False},
                "run_npm_audit": {"type": "boolean", "default": False},
            },
            "required": ["path"],
        },
    },
    {
        "name": "export_sarif",
        "description": "Convert issues to SARIF 2.1.0 JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {"issues": {"type": "array", "items": {"type": "object"}}},
            "required": ["issues"],
        },
    },
    {
        "name": "generate_sbom",
        "description": "Generate CycloneDX and/or SPDX SBOM JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "format": {
                    "type": "string",
                    "enum": ["cyclonedx", "spdx", "both"],
                    "default": "cyclonedx",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "suggest_fixes",
        "description": "Template or LLM-assisted fix drafts for findings (never auto-applied).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "issues": {"type": "array", "items": {"type": "object"}},
                "path": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "use_llm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Requires GUARDRAIL_LLM_API_KEY",
                },
            },
            "required": ["issues"],
        },
    },
    {
        "name": "audit_container_config",
        "description": "Dockerfile / Kubernetes security heuristics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string"},
                "filename": {"type": "string"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "full_pipeline",
        "description": "Repo/diff scan + deps + fixes + SARIF + SBOM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "mode": {"type": "string", "enum": ["repo", "diff", "staged"], "default": "repo"},
                "base": {"type": "string", "default": "HEAD~1"},
                "head": {"type": "string", "default": "HEAD"},
                "include_deps": {"type": "boolean", "default": True},
                "use_network": {"type": "boolean", "default": False},
                "include_fixes": {"type": "boolean", "default": True},
                "sbom_format": {"type": "string", "enum": ["cyclonedx", "spdx", "both"]},
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_plugins",
        "description": "List loaded plugins and custom rule counts.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "engine_status",
        "description": "Report hybrid engine capabilities (tree-sitter langs, plugins, etc.).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "security_score",
        "description": "Compute security score/grade from an issues list and optionally record history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "issues": {"type": "array", "items": {"type": "object"}},
                "tenant_id": {"type": "string"},
                "record": {"type": "boolean", "default": True},
            },
            "required": ["issues"],
        },
    },
    {
        "name": "scan_history",
        "description": "Return recent dashboard scan history from local SQLite.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 50},
                "tenant_id": {"type": "string"},
            },
        },
    },
]


def call_tool(name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    args = arguments or {}

    if name == "audit_code_safety":
        hybrid = args.get("hybrid", True)
        if isinstance(hybrid, str):
            hybrid = hybrid.lower() not in {"0", "false", "no"}
        if hybrid:
            res = hybrid_scan(
                args.get("source_code", ""),
                filename=args.get("filename"),
                language=args.get("language"),
                tenant_id=args.get("tenant_id"),
                use_ast=bool(args.get("use_ast", True)),
                use_taint=bool(args.get("use_taint", True)),
                use_treesitter=bool(args.get("use_treesitter", True)),
                use_plugins=bool(args.get("use_plugins", True)),
            )
        else:
            src = args.get("source_code", "")
            filename = args.get("filename")
            lang = args.get("language") or detect_language(filename, src)
            use_ast = args.get("use_ast", True)
            if isinstance(use_ast, str):
                use_ast = use_ast.lower() not in {"0", "false", "no"}
            if lang == "python" or (filename or "").endswith(".py"):
                res = run_core_safety_audit(
                    src, args.get("tenant_id"), filename=filename, use_ast=bool(use_ast)
                )
            else:
                res = run_core_safety_audit(
                    src, args.get("tenant_id"), filename=filename, use_ast=False
                )
                extra = scan_language(src, lang, filename=filename)
                if extra:
                    issues = list(res.get("issues") or [])
                    issues.extend(f.to_dict() for f in extra)
                    res["issues"] = issues
                    res["issue_count"] = len(issues)
            res["language"] = lang
        # dashboard scoring
        try:
            score_info = compute_security_score(res.get("issues") or [])
            res["security_score"] = score_info
            record_score(str(args.get("tenant_id") or "local"), score_info)
            record_scan(
                tenant_id=str(args.get("tenant_id") or "local"),
                tool="audit_code_safety",
                path=str(args.get("filename") or ""),
                risk_score=int(res.get("risk_score") or 0),
                issue_count=int(res.get("issue_count") or 0),
                verdict=str(res.get("security_verdict") or ""),
                policy_decision="",
                payload={"engines": res.get("engines")},
            )
        except Exception:
            pass
        return res

    if name == "audit_cloud_cost":
        return run_core_cost_audit(
            args.get("infrastructure_content", ""),
            args.get("cloud_provider", "aws"),
        )

    if name == "audit_infra_security":
        try:
            budget = float(args.get("budget_limit_usd", 500))
        except (TypeError, ValueError):
            budget = 500.0
        return deep_analyze_infra(
            args.get("infrastructure_content", ""),
            args.get("cloud_provider", "aws"),
            budget_limit_usd=budget,
        )

    if name == "scan_repository":
        res = scan_repository(
            args.get("path", "."),
            workers=args.get("workers"),
            max_files=int(args.get("max_files") or 2000),
            use_ast=bool(args.get("use_ast", True)),
            incremental=bool(args.get("incremental", True)),
        )
        try:
            score_info = compute_security_score(res.get("issues") or [])
            res["security_score"] = score_info
            record_score("local", score_info)
            record_scan(
                tenant_id="local",
                tool="scan_repository",
                path=str(args.get("path") or "."),
                risk_score=int(res.get("aggregate_risk_score") or 0),
                issue_count=int(res.get("issue_count") or 0),
                verdict=str(res.get("security_verdict") or ""),
                policy_decision="",
            )
        except Exception:
            pass
        return res

    if name == "scan_git_diff":
        return scan_git_diff(
            args.get("path", "."),
            base=args.get("base", "HEAD~1"),
            head=args.get("head", "HEAD"),
            staged=bool(args.get("staged", False)),
            use_ast=bool(args.get("use_ast", True)),
        )

    if name == "scan_dependencies":
        return scan_dependencies(
            args.get("path", "."),
            use_network=bool(args.get("use_network", False)),
            run_pip_audit=bool(args.get("run_pip_audit", False)),
            run_npm_audit=bool(args.get("run_npm_audit", False)),
        )

    if name == "export_sarif":
        return findings_to_sarif(args.get("issues") or [])

    if name == "generate_sbom":
        fmt = args.get("format") or "cyclonedx"
        path = args.get("path", ".")
        out: Dict[str, Any] = {"status": "OK", "path": path}
        if fmt in ("cyclonedx", "both"):
            out["cyclonedx"] = generate_cyclonedx(path)
        if fmt in ("spdx", "both"):
            out["spdx"] = generate_spdx(path)
        return out

    if name == "suggest_fixes":
        use_llm = bool(args.get("use_llm", False))
        return {
            "status": "OK",
            "fixes": batch_ai_fixes(
                args.get("issues") or [],
                path=args.get("path"),
                use_llm=use_llm,
                limit=int(args.get("limit") or 50),
            ),
        }

    if name == "audit_container_config":
        return analyze_container_config(
            args.get("content", ""),
            filename=args.get("filename"),
        )

    if name == "full_pipeline":
        return run_full_pipeline(
            args.get("path", "."),
            mode=args.get("mode") or "repo",
            base=args.get("base", "HEAD~1"),
            head=args.get("head", "HEAD"),
            include_deps=bool(args.get("include_deps", True)),
            use_network=bool(args.get("use_network", False)),
            include_fixes=bool(args.get("include_fixes", True)),
            sbom_format=args.get("sbom_format"),
        )

    if name == "list_plugins":
        reg = get_plugin_registry()
        return {
            "status": "OK",
            "plugins": [
                {
                    "name": i.name,
                    "version": i.version,
                    "path": i.path,
                    "rules": i.rules,
                    "hooks": i.hooks,
                }
                for i in reg.infos
            ],
            "custom_rules_loaded": len(reg.rules),
        }

    if name == "engine_status":
        return {
            "status": "OK",
            "treesitter": treesitter_status(),
            "plugins": len(get_plugin_registry().infos),
            "custom_rules": len(get_plugin_registry().rules),
            "llm_autofix_configured": bool(os.environ.get("GUARDRAIL_LLM_API_KEY")),
            "features": [
                "advanced_taint",
                "treesitter",
                "custom_rules",
                "plugins",
                "incremental_cache",
                "ai_autofix",
                "dashboard",
                "enterprise_gateway",
            ],
        }

    if name == "security_score":
        info = compute_security_score(args.get("issues") or [])
        if args.get("record", True):
            record_score(str(args.get("tenant_id") or "local"), info)
        return {"status": "OK", **info}

    if name == "scan_history":
        return {
            "status": "OK",
            "history": history(int(args.get("limit") or 50), args.get("tenant_id")),
            "scores": score_history(int(args.get("limit") or 50), args.get("tenant_id")),
        }

    return {"status": "ERROR", "reason": f"Unknown tool: {name}"}


def call_tool_gated(
    name: str,
    arguments: Optional[Dict[str, Any]] = None,
    *,
    authorization: Optional[str] = None,
    api_key: Optional[str] = None,
    transport: str = "stdio",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    from .enterprise.gateway import enterprise_call_tool

    return enterprise_call_tool(
        name,
        arguments,
        authorization=authorization,
        api_key=api_key,
        transport=transport,
        correlation_id=correlation_id,
    )


def list_tools() -> List[Dict[str, Any]]:
    from .enterprise.gateway import list_all_tools

    # merge new community tools that gateway base list may not include
    base = {t["name"]: t for t in TOOLS}
    all_t = list_all_tools()
    names = {t["name"] for t in all_t}
    for n, t in base.items():
        if n not in names:
            all_t.append(t)
    # ensure engine tools present
    for t in TOOLS:
        if t["name"] not in {x["name"] for x in all_t}:
            all_t.append(t)
    return all_t


def tool_result_text(payload: Any, is_error: bool = False) -> Dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, default=str)
    if len(text) > 400_000:
        text = text[:400_000] + "\n…[truncated]…"
    out: Dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        out["isError"] = True
    return out
