"""API key + HS256 JWT authentication."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .config import EnterpriseConfig, TenantConfig


@dataclass
class Principal:
    subject: str
    tenant_id: str
    role: str
    auth_method: str  # api_key | jwt | local | admin_key
    token_id: str = ""
    claims: Dict[str, Any] | None = None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def issue_jwt(
    *,
    secret: str,
    subject: str,
    tenant_id: str,
    role: str,
    issuer: str = "guardrail-mcp",
    audience: str = "guardrail",
    ttl_seconds: int = 3600,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    if not secret:
        raise ValueError("jwt secret required")
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload: Dict[str, Any] = {
        "sub": subject,
        "tid": tenant_id,
        "role": role,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + int(ttl_seconds),
        "jti": secrets.token_hex(8),
    }
    if extra:
        payload.update(extra)
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode("utf-8"), f"{h}.{p}".encode("utf-8"), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def verify_jwt(
    token: str,
    *,
    secret: str,
    issuer: str = "guardrail-mcp",
    audience: str = "guardrail",
) -> Dict[str, Any]:
    try:
        h, p, s = token.split(".")
    except ValueError as exc:
        raise ValueError("malformed jwt") from exc
    expected = hmac.new(secret.encode("utf-8"), f"{h}.{p}".encode("utf-8"), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url(expected), s):
        # compare raw
        if not hmac.compare_digest(expected, _b64url_decode(s)):
            raise ValueError("invalid jwt signature")
    payload = json.loads(_b64url_decode(p))
    now = int(time.time())
    if int(payload.get("exp", 0)) < now:
        raise ValueError("jwt expired")
    if payload.get("iss") != issuer:
        raise ValueError("jwt issuer mismatch")
    aud = payload.get("aud")
    if aud != audience and audience not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("jwt audience mismatch")
    return payload


def _find_tenant_by_api_key(cfg: EnterpriseConfig, api_key: str) -> Tuple[Optional[TenantConfig], str]:
    for tid, tenant in cfg.tenants.items():
        for k in tenant.api_keys:
            if secrets.compare_digest(str(k), str(api_key)):
                role = tenant.roles.get(k) or tenant.roles.get(hash_key(k)) or cfg.default_role
                return tenant, role
    return None, cfg.default_role


def authenticate(
    cfg: EnterpriseConfig,
    *,
    authorization: Optional[str] = None,
    api_key: Optional[str] = None,
    tenant_id_hint: Optional[str] = None,
    transport: str = "http",
) -> Tuple[Optional[Principal], Optional[str]]:
    """
    Returns (principal, error_message).
    When enterprise disabled or local unauthenticated allowed for stdio, returns local principal.
    """
    token = None
    if authorization:
        auth = authorization.strip()
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        elif auth.lower().startswith("apikey "):
            api_key = auth[7:].strip()
        else:
            token = auth
    if api_key is None and token and not token.count(".") == 2:
        # treat bare token as API key if not JWT-shaped
        api_key = token
        token = None

    # Admin key
    if api_key:
        for ak in cfg.admin_api_keys:
            if secrets.compare_digest(str(ak), str(api_key)):
                return (
                    Principal(
                        subject="admin",
                        tenant_id=tenant_id_hint or "admin",
                        role="admin",
                        auth_method="admin_key",
                        token_id=hash_key(api_key),
                    ),
                    None,
                )

    # Tenant API key
    if api_key:
        tenant, role = _find_tenant_by_api_key(cfg, api_key)
        if tenant is None:
            return None, "Invalid API key"
        if not tenant.enabled:
            return None, "Tenant disabled"
        return (
            Principal(
                subject=f"key:{hash_key(api_key)}",
                tenant_id=tenant.tenant_id,
                role=role,
                auth_method="api_key",
                token_id=hash_key(api_key),
            ),
            None,
        )

    # JWT
    if token and cfg.jwt_secret:
        try:
            claims = verify_jwt(
                token,
                secret=cfg.jwt_secret,
                issuer=cfg.jwt_issuer,
                audience=cfg.jwt_audience,
            )
        except ValueError as exc:
            return None, f"JWT validation failed: {exc}"
        tid = str(claims.get("tid") or tenant_id_hint or "default")
        tenant = cfg.tenants.get(tid)
        if cfg.tenants and tenant is None:
            return None, f"Unknown tenant in token: {tid}"
        if tenant and not tenant.enabled:
            return None, "Tenant disabled"
        return (
            Principal(
                subject=str(claims.get("sub") or "jwt-user"),
                tenant_id=tid,
                role=str(claims.get("role") or cfg.default_role),
                auth_method="jwt",
                token_id=str(claims.get("jti") or ""),
                claims=claims,
            ),
            None,
        )

    # Unauthenticated paths
    if not cfg.enabled:
        return (
            Principal(
                subject="local",
                tenant_id=tenant_id_hint or "local",
                role="admin",
                auth_method="local",
            ),
            None,
        )

    if not cfg.require_auth and cfg.allow_local_unauthenticated and transport == "stdio":
        return (
            Principal(
                subject="local-stdio",
                tenant_id=tenant_id_hint or "local",
                role=cfg.default_role if cfg.default_role != "admin" else "scanner",
                auth_method="local",
            ),
            None,
        )

    if not cfg.require_auth and cfg.allow_local_unauthenticated and transport == "http":
        # safer default for http: viewer-level local unless require_auth
        return (
            Principal(
                subject="local-http",
                tenant_id=tenant_id_hint or "local",
                role="scanner",
                auth_method="local",
            ),
            None,
        )

    return None, "Authentication required (Bearer API key or JWT)"
