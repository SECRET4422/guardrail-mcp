"""CLI subcommands for repo/diff/deps/sarif/sbom (used by server.main)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional


def add_scan_subcommands(sub: argparse._SubParsersAction) -> None:
    p_repo = sub.add_parser("scan-repo", help="Recursively scan a repository")
    p_repo.add_argument("path", nargs="?", default=".")
    p_repo.add_argument("--workers", type=int, default=None)
    p_repo.add_argument("--max-files", type=int, default=2000)
    p_repo.add_argument("--no-ast", action="store_true")
    p_repo.add_argument("--sarif", default=None, help="Write SARIF to path")
    p_repo.add_argument("--json-out", default=None)
    p_repo.add_argument("--fixes", action="store_true")
    p_repo.add_argument("--deps", action="store_true", help="Include dependency inventory")
    p_repo.add_argument("--osv", action="store_true", help="Query OSV (network)")
    p_repo.add_argument("--sbom", choices=("cyclonedx", "spdx", "both"), default=None)

    p_diff = sub.add_parser("scan-diff", help="Scan git changed files (PR mode)")
    p_diff.add_argument("path", nargs="?", default=".")
    p_diff.add_argument("--base", default="HEAD~1")
    p_diff.add_argument("--head", default="HEAD")
    p_diff.add_argument("--staged", action="store_true")
    p_diff.add_argument("--no-ast", action="store_true")
    p_diff.add_argument("--sarif", default=None)
    p_diff.add_argument("--json-out", default=None)
    p_diff.add_argument("--fixes", action="store_true")

    p_deps = sub.add_parser("scan-deps", help="Dependency inventory + optional OSV")
    p_deps.add_argument("path", nargs="?", default=".")
    p_deps.add_argument("--osv", action="store_true")
    p_deps.add_argument("--pip-audit", action="store_true")
    p_deps.add_argument("--npm-audit", action="store_true")
    p_deps.add_argument("--json-out", default=None)

    p_sbom = sub.add_parser("sbom", help="Generate SBOM (CycloneDX and/or SPDX)")
    p_sbom.add_argument("path", nargs="?", default=".")
    p_sbom.add_argument("--format", choices=("cyclonedx", "spdx", "both"), default="cyclonedx")
    p_sbom.add_argument("--out", default=None, help="Output file (json)")

    p_sarif = sub.add_parser("export-sarif", help="Scan path and write SARIF only")
    p_sarif.add_argument("path", nargs="?", default=".")
    p_sarif.add_argument("--out", default="guardrail.sarif")
    p_sarif.add_argument("--diff", action="store_true")
    p_sarif.add_argument("--base", default="HEAD~1")
    p_sarif.add_argument("--head", default="HEAD")


def _print(data: dict, json_out: Optional[str]) -> None:
    text = json.dumps(data, indent=2, default=str)
    if json_out:
        Path(json_out).write_text(text, encoding="utf-8")
        print(f"Wrote {json_out}", file=sys.stderr)
    print(text)


def run_subcommand(args: argparse.Namespace) -> int:
    from .deps import scan_dependencies
    from .fixes import generate_fixes_for_issues
    from .git_scan import scan_git_diff
    from .pipeline import run_full_pipeline
    from .repo_scan import scan_repository
    from .sarif_export import findings_to_sarif, write_sarif
    from .sbom import generate_cyclonedx, generate_spdx

    cmd = args.command

    if cmd == "scan-repo":
        report = run_full_pipeline(
            args.path,
            mode="repo",
            workers=args.workers,
            use_ast=not args.no_ast,
            include_deps=args.deps or args.osv,
            use_network=args.osv,
            include_fixes=args.fixes,
            sarif_path=args.sarif,
            sbom_format=args.sbom,
            max_files=args.max_files,
        )
        # Shrink console output: drop full nested sarif blob if written
        if args.sarif and isinstance(report.get("sarif"), dict) and "written" in report["sarif"]:
            pass
        elif "sarif" in report and not args.json_out:
            report = {**report, "sarif": {"result_count": report.get("issue_count", 0)}}
        _print(report, args.json_out)
        return 0 if report.get("security_verdict") != "REJECTED" else 2

    if cmd == "scan-diff":
        if args.staged:
            scan = scan_git_diff(args.path, staged=True, use_ast=not args.no_ast)
        else:
            scan = scan_git_diff(
                args.path, base=args.base, head=args.head, use_ast=not args.no_ast
            )
        issues = scan.get("issues") or []
        out = {
            **scan,
            "fixes": generate_fixes_for_issues(issues) if args.fixes else [],
        }
        if args.sarif:
            write_sarif(args.sarif, findings_to_sarif(issues))
            out["sarif_written"] = args.sarif
        _print(out, args.json_out)
        return 0 if scan.get("security_verdict") != "REJECTED" else 2

    if cmd == "scan-deps":
        res = scan_dependencies(
            args.path,
            use_network=args.osv,
            run_pip_audit=args.pip_audit,
            run_npm_audit=args.npm_audit,
        )
        _print(res, args.json_out)
        return 0

    if cmd == "sbom":
        root = args.path
        payload = {}
        if args.format in ("cyclonedx", "both"):
            payload["cyclonedx"] = generate_cyclonedx(root)
        if args.format in ("spdx", "both"):
            payload["spdx"] = generate_spdx(root)
        if args.out:
            Path(args.out).write_text(json.dumps(payload if args.format == "both" else payload.get(args.format) or payload.get("cyclonedx"), indent=2), encoding="utf-8")
            print(f"Wrote {args.out}", file=sys.stderr)
        else:
            print(json.dumps(payload if args.format == "both" else (payload.get(args.format) or payload.get("cyclonedx")), indent=2))
        return 0

    if cmd == "export-sarif":
        if args.diff:
            scan = scan_git_diff(args.path, base=args.base, head=args.head)
        else:
            scan = scan_repository(args.path)
        path = write_sarif(args.out, findings_to_sarif(scan.get("issues") or []))
        print(json.dumps({"written": path, "issues": scan.get("issue_count", 0)}, indent=2))
        return 0 if scan.get("security_verdict") != "REJECTED" else 2

    print(f"Unknown command {cmd}", file=sys.stderr)
    return 1
