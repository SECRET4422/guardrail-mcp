"""Enterprise FastAPI surface — auth headers, gateway, metrics."""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from . import __version__
from .enterprise.config import registry
from .enterprise.metrics import metrics
from .redaction import sanitize_for_log
from .tools_catalog import call_tool_gated, list_tools

_CORS = [o.strip() for o in os.environ.get("GUARDRAIL_CORS_ORIGINS", "").split(",") if o.strip()]
_MAX_BODY = int(os.environ.get("GUARDRAIL_MAX_BODY_BYTES", "2000000"))


class ToolCallRequest(BaseModel):
    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


def create_app() -> FastAPI:
    app = FastAPI(
        title="GuardRail Enterprise MCP HTTP API",
        version=__version__,
        description=(
            "Enterprise MCP tool gateway with RBAC, policy packs, audit, quotas. "
            "Authenticate with Authorization: Bearer <api_key|jwt>."
        ),
    )

    if _CORS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=_CORS,
            allow_credentials=False,
            allow_methods=["POST", "GET"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id", "X-Api-Key"],
        )

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > _MAX_BODY:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        return await call_next(request)

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        cfg = registry.get()
        return {
            "status": "ok",
            "version": __version__,
            "edition": "enterprise" if cfg.enabled else "community",
            "tools": [t["name"] for t in list_tools()],
            "enterprise": cfg.to_public_dict() if cfg.enabled else {"enabled": False},
        }

    @app.get("/ready")
    async def ready() -> Dict[str, str]:
        return {"status": "ready"}

    @app.get("/metrics")
    async def prom_metrics() -> Response:
        snap = metrics.snapshot()
        lines = [
            "# HELP guardrail_tool_calls_total Total tool invocations",
            "# TYPE guardrail_tool_calls_total counter",
            f"guardrail_tool_calls_total {snap['tool_calls']}",
            "# HELP guardrail_tool_errors_total Tool errors",
            "# TYPE guardrail_tool_errors_total counter",
            f"guardrail_tool_errors_total {snap['tool_errors']}",
            "# HELP guardrail_auth_failures_total Auth failures",
            "# TYPE guardrail_auth_failures_total counter",
            f"guardrail_auth_failures_total {snap['auth_failures']}",
            "# HELP guardrail_rate_limited_total Rate limit hits",
            "# TYPE guardrail_rate_limited_total counter",
            f"guardrail_rate_limited_total {snap['rate_limited']}",
            "# HELP guardrail_policy_denies_total Policy DENY decisions",
            "# TYPE guardrail_policy_denies_total counter",
            f"guardrail_policy_denies_total {snap['policy_denies']}",
            "# HELP guardrail_avg_latency_ms Average tool latency",
            "# TYPE guardrail_avg_latency_ms gauge",
            f"guardrail_avg_latency_ms {snap['avg_latency_ms']}",
            "# HELP guardrail_uptime_seconds Process uptime",
            "# TYPE guardrail_uptime_seconds gauge",
            f"guardrail_uptime_seconds {snap['uptime_seconds']}",
        ]
        for tool, count in sorted(snap.get("by_tool") or {}.items()):
            safe = tool.replace("-", "_")
            lines.append(f'guardrail_tool_calls_by_tool{{tool="{safe}"}} {count}')
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    @app.get("/tools")
    async def tools(
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> Dict[str, Any]:
        # listing tools is allowed; still prefer auth when required
        cfg = registry.get()
        if cfg.enabled and cfg.require_auth and not (authorization or x_api_key):
            raise HTTPException(status_code=401, detail="Authentication required")
        return {"tools": list_tools()}

    @app.post("/v1/tools/call")
    async def tools_call(
        body: ToolCallRequest,
        request: Request,
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
        x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    ) -> Dict[str, Any]:
        cid = x_request_id or request.headers.get("x-request-id") or str(uuid.uuid4())
        try:
            result = call_tool_gated(
                body.name,
                body.arguments,
                authorization=authorization,
                api_key=x_api_key,
                transport="http",
                correlation_id=cid,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=sanitize_for_log(str(exc))) from exc

        status = result.get("status") if isinstance(result, dict) else "OK"
        if status == "AUTH_FAILED":
            raise HTTPException(status_code=401, detail=result)
        if status == "FORBIDDEN":
            raise HTTPException(status_code=403, detail=result)
        if status == "RATE_LIMITED":
            raise HTTPException(status_code=429, detail=result)
        if status in {"QUOTA_EXCEEDED", "SANDBOX_DENIED"}:
            raise HTTPException(status_code=403, detail=result)
        return result

    # REST aliases
    @app.post("/v1/audit/code-safety")
    async def audit_safety(
        body: Dict[str, Any],
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
        x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    ):
        return call_tool_gated(
            "audit_code_safety",
            body,
            authorization=authorization,
            api_key=x_api_key,
            transport="http",
            correlation_id=x_request_id,
        )

    @app.post("/v1/pipeline")
    async def pipeline(
        body: Dict[str, Any],
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
        x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    ):
        return call_tool_gated(
            "full_pipeline",
            body,
            authorization=authorization,
            api_key=x_api_key,
            transport="http",
            correlation_id=x_request_id,
        )

    @app.post("/v1/scan/repository")
    async def scan_repo(
        body: Dict[str, Any],
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
        x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    ):
        return call_tool_gated(
            "scan_repository",
            body,
            authorization=authorization,
            api_key=x_api_key,
            transport="http",
            correlation_id=x_request_id,
        )

    @app.get("/v1/enterprise/health")
    async def ent_health(
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ):
        return call_tool_gated(
            "enterprise_health",
            {},
            authorization=authorization,
            api_key=x_api_key,
            transport="http",
        )

    # --- Dashboard ---
    @app.get("/")
    async def dashboard_home():
        if os.environ.get("GUARDRAIL_DASHBOARD", "1").lower() in {"0", "false", "no"}:
            return {"status": "ok", "version": __version__, "dashboard": False}
        from fastapi.responses import HTMLResponse
        from .dashboard import dashboard_html

        return HTMLResponse(dashboard_html())

    @app.get("/dashboard")
    async def dashboard_page():
        from fastapi.responses import HTMLResponse
        from .dashboard import dashboard_html

        return HTMLResponse(dashboard_html())

    @app.get("/api/dashboard/history")
    async def dashboard_history(limit: int = 50, tenant_id: Optional[str] = None):
        from .dashboard import history, score_history

        return {
            "history": history(limit, tenant_id),
            "scores": score_history(limit, tenant_id),
        }

    return app


app = create_app()
