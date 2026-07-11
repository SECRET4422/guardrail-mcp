"""Request-scoped context (contextvars)."""

from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .auth import Principal


@dataclass
class RequestContext:
    principal: Optional[Principal] = None
    correlation_id: str = ""
    transport: str = "stdio"
    enterprise_enabled: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


_CTX: contextvars.ContextVar[Optional[RequestContext]] = contextvars.ContextVar(
    "guardrail_request_ctx", default=None
)


def get_context() -> Optional[RequestContext]:
    return _CTX.get()


def set_context(ctx: RequestContext) -> contextvars.Token:
    return _CTX.set(ctx)


def reset_context(token: contextvars.Token) -> None:
    _CTX.reset(token)
