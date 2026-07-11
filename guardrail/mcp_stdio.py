"""MCP-compatible JSON-RPC over STDIO (enterprise gateway)."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict, Optional, Tuple

from . import __version__
from .redaction import sanitize_for_log
from .tools_catalog import call_tool_gated, list_tools, tool_result_text

logger = logging.getLogger("GuardRailMCP.stdio")

PROTOCOL_VERSION = "2024-11-05"
MAX_MESSAGE_BYTES = 2_000_000

SERVER_INFO = {
    "name": "guardrail-mcp",
    "version": __version__,
}


class _MISSING:
    pass


_MISSING = _MISSING()  # type: ignore


def dispatch(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = request.get("method")
    req_id = request.get("id", _MISSING)
    is_notification = req_id is _MISSING

    def reply_result(result: Any) -> Optional[Dict[str, Any]]:
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def reply_error(code: int, message: str, data: Any = None) -> Optional[Dict[str, Any]]:
        if is_notification:
            return None
        err: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": err}

    if not method:
        return reply_error(-32600, "Invalid Request: missing method")

    if method == "initialize":
        params = request.get("params") or {}
        client_ver = params.get("protocolVersion") or PROTOCOL_VERSION
        return reply_result(
            {
                "protocolVersion": client_ver,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": (
                    "GuardRail Enterprise MCP: multi-language safety, repo/diff scan, OSV, "
                    "SARIF/SBOM, policy packs, RBAC, audit logs. Pass api_key/authorization "
                    "in tool arguments when enterprise auth is required."
                ),
            }
        )

    if method == "notifications/initialized":
        logger.info("MCP client initialized")
        return None

    if method == "ping":
        return reply_result({})

    if method == "tools/list":
        return reply_result({"tools": list_tools()})

    if method == "tools/call":
        params = request.get("params") or {}
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        try:
            exec_res = call_tool_gated(tool_name, arguments, transport="stdio")
            is_err = isinstance(exec_res, dict) and exec_res.get("status") in {
                "ERROR",
                "ACCESS_DENIED",
                "AUTH_FAILED",
                "FORBIDDEN",
                "RATE_LIMITED",
                "QUOTA_EXCEEDED",
                "SANDBOX_DENIED",
            }
            return reply_result(tool_result_text(exec_res, is_error=is_err))
        except Exception as exc:  # noqa: BLE001
            logger.error("tools/call failed: %s", sanitize_for_log(str(exc)))
            return reply_result(
                tool_result_text(
                    f"Internal tool error: {sanitize_for_log(str(exc))}", is_error=True
                )
            )

    if method in (
        "resources/list",
        "prompts/list",
        "completion/complete",
        "logging/setLevel",
    ):
        if method.endswith("/list"):
            key = "resources" if "resources" in method else "prompts"
            return reply_result({key: []})
        return reply_result({})

    return reply_error(-32601, f"Method not found: {method}")


def _write_message(message: Dict[str, Any], use_content_length: bool) -> None:
    raw = json.dumps(message, ensure_ascii=False).encode("utf-8")
    out = sys.stdout.buffer
    if use_content_length:
        out.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii"))
        out.write(raw)
    else:
        out.write(raw)
        out.write(b"\n")
    out.flush()


def run_stdio_server() -> None:
    logger.info("GuardRail Enterprise MCP STDIO server v%s starting", __version__)
    stdin = sys.stdin.buffer
    framing_content_length: Optional[bool] = None

    while True:
        try:
            request = _read_one(stdin, framing_content_length)
            if request is None:
                break
            msg, detected_cl = request
            if framing_content_length is None:
                framing_content_length = detected_cl
            if not isinstance(msg, dict):
                continue
            response = dispatch(msg)
            if response is not None:
                _write_message(response, use_content_length=bool(framing_content_length))
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON: %s", exc)
            continue
        except Exception as exc:  # noqa: BLE001
            logger.error("STDIO loop error: %s", sanitize_for_log(str(exc)))
            continue
    logger.info("STDIO loop ended (EOF)")


def _read_one(
    stdin_buffer, framing_lock: Optional[bool]
) -> Optional[Tuple[Dict[str, Any], bool]]:
    first = stdin_buffer.readline()
    if not first:
        return None

    is_cl = first.lower().startswith(b"content-length:")
    if framing_lock is True or (framing_lock is None and is_cl):
        headers = first
        while True:
            line = stdin_buffer.readline()
            if not line:
                return None
            headers += line
            if line in (b"\r\n", b"\n"):
                break
        length = 0
        for hline in headers.split(b"\n"):
            hl = hline.strip()
            if hl.lower().startswith(b"content-length:"):
                try:
                    length = int(hl.split(b":", 1)[1].strip())
                except ValueError:
                    length = 0
        if length <= 0 or length > MAX_MESSAGE_BYTES:
            logger.error("Invalid Content-Length: %s", length)
            return None
        body = stdin_buffer.read(length)
        if not body or len(body) < length:
            return None
        return json.loads(body.decode("utf-8")), True

    line = first.strip()
    while not line:
        nxt = stdin_buffer.readline()
        if not nxt:
            return None
        line = nxt.strip()
    if len(line) > MAX_MESSAGE_BYTES:
        raise ValueError("message too large")
    return json.loads(line.decode("utf-8")), False
