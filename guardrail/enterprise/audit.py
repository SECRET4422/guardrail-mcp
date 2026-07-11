"""Append-only structured audit logging."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("GuardRailMCP.audit")


class AuditLogger:
    def __init__(self, path: str = "", stdout: bool = True, memory_size: int = 500) -> None:
        self.path = path
        self.stdout = stdout
        self._lock = threading.Lock()
        self._memory: Deque[Dict[str, Any]] = deque(maxlen=memory_size)

    def emit(self, event: Dict[str, Any]) -> Dict[str, Any]:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_id": str(uuid.uuid4()),
            **event,
        }
        # never persist raw secrets from arguments
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            self._memory.appendleft(record)
            if self.path:
                try:
                    p = Path(self.path)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with p.open("a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                except OSError as exc:
                    logger.error("audit write failed: %s", exc)
        if self.stdout:
            logger.info("AUDIT %s", line)
        return record

    def recent(
        self,
        *,
        limit: int = 50,
        tenant_id: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._memory)
        out = []
        for e in items:
            if tenant_id and e.get("tenant_id") != tenant_id:
                continue
            if tool and e.get("tool") != tool:
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out


_audit: Optional[AuditLogger] = None
_audit_lock = threading.Lock()


def get_audit_logger(path: str = "", stdout: bool = True) -> AuditLogger:
    global _audit
    with _audit_lock:
        if _audit is None:
            _audit = AuditLogger(path=path or os.environ.get("GUARDRAIL_AUDIT_LOG", ""), stdout=stdout)
        elif path and _audit.path != path:
            _audit.path = path
        return _audit


def redact_args_for_audit(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Keep audit useful without storing source code or secrets."""
    safe: Dict[str, Any] = {}
    sensitive = {
        "source_code",
        "infrastructure_content",
        "content",
        "issues",
        "authorization",
        "api_key",
        "token",
    }
    for k, v in (args or {}).items():
        if k in sensitive:
            if isinstance(v, str):
                safe[k] = f"<redacted len={len(v)}>"
            elif isinstance(v, list):
                safe[k] = f"<redacted list n={len(v)}>"
            else:
                safe[k] = "<redacted>"
        elif k in {"path", "filename", "language", "cloud_provider", "mode", "base", "head"}:
            safe[k] = v
        else:
            # small scalars only
            if isinstance(v, (bool, int, float)) or (isinstance(v, str) and len(v) < 120):
                safe[k] = v
            else:
                safe[k] = type(v).__name__
    safe["_tool"] = tool
    return safe
