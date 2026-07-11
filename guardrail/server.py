"""CLI entry: MCP transports, HTTP, and scan subcommands."""

from __future__ import annotations

import argparse
import logging
import os
import sys


def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
        force=True,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="guardrail-mcp",
        description="GuardRail multi-language security MCP & scanner",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command")

    # server modes as subcommands for clarity, keep --mode for back-compat
    p_serve = sub.add_parser("serve", help="Run MCP/HTTP server")
    p_serve.add_argument(
        "--mode",
        choices=("stdio", "stdio-sdk", "http"),
        default=os.environ.get("GUARDRAIL_MODE", "stdio"),
    )
    p_serve.add_argument("--host", default=os.environ.get("GUARDRAIL_HOST", "127.0.0.1"))
    p_serve.add_argument("--port", type=int, default=int(os.environ.get("GUARDRAIL_PORT", "8787")))

    from .cli_extra import add_scan_subcommands

    add_scan_subcommands(sub)

    # Back-compat: python -m guardrail --mode stdio
    parser.add_argument(
        "--mode",
        choices=("stdio", "stdio-sdk", "http"),
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--host", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=None, help=argparse.SUPPRESS)

    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    log = logging.getLogger("GuardRailMCP")

    # Legacy flags
    if args.command is None and args.mode:
        args.command = "serve"
        # synthesize
        class _S:
            pass

        s = _S()
        s.mode = args.mode
        s.host = args.host or "127.0.0.1"
        s.port = args.port or 8787
        return _run_serve(s, log)

    if args.command is None:
        # default stdio server (MCP host launch)
        class _S:
            mode = os.environ.get("GUARDRAIL_MODE", "stdio")
            host = "127.0.0.1"
            port = 8787

        return _run_serve(_S(), log)

    if args.command == "serve":
        return _run_serve(args, log)

    from .cli_extra import run_subcommand

    code = run_subcommand(args)
    raise SystemExit(code)


def _run_serve(args, log) -> None:
    mode = getattr(args, "mode", "stdio")
    if mode == "stdio":
        from .mcp_stdio import run_stdio_server

        run_stdio_server()
        return
    if mode == "stdio-sdk":
        from .mcp_sdk_server import run_sdk_stdio_server

        log.info("Starting official MCP SDK STDIO transport")
        run_sdk_stdio_server()
        return

    try:
        import uvicorn
    except ImportError:
        log.error("Missing uvicorn. Run: pip install uvicorn fastapi")
        sys.exit(1)
    from .http_api import app

    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 8787)
    log.info("Starting HTTP server on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
