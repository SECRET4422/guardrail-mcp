"""Official MCP Python SDK entrypoint with enterprise gateway."""

from __future__ import annotations

import json
import logging
from typing import Any

from . import __version__
from .redaction import sanitize_for_log
from .tools_catalog import call_tool_gated, list_tools

logger = logging.getLogger("GuardRailMCP.sdk")


def run_sdk_stdio_server() -> None:
    try:
        import anyio
        import mcp.types as types
        from mcp.server import NotificationOptions, Server
        from mcp.server.models import InitializationOptions
        from mcp.server.stdio import stdio_server
    except ImportError as exc:
        raise SystemExit(
            "Official MCP SDK not installed. Run: pip install mcp\n"
            "Or use: python -m guardrail --mode stdio"
        ) from exc

    server = Server("guardrail-mcp")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["inputSchema"],
            )
            for t in list_tools()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
        try:
            payload = call_tool_gated(name, arguments or {}, transport="stdio")
            text = json.dumps(payload, indent=2, default=str)
            if len(text) > 400_000:
                text = text[:400_000] + "\n…[truncated]…"
        except Exception as exc:  # noqa: BLE001
            logger.error("tool error: %s", sanitize_for_log(str(exc)))
            text = json.dumps({"error": sanitize_for_log(str(exc))})
        return [types.TextContent(type="text", text=text)]

    async def _amain() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="guardrail-mcp",
                    server_version=__version__,
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    anyio.run(_amain)
