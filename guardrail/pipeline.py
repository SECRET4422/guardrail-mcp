"""
High-level orchestration: repo/diff scan → optional deps → SARIF/SBOM/fixes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .deps import scan_dependencies
from .fixes import generate_fixes_for_issues
from .git_scan import scan_git_diff
from .repo_scan import scan_repository
from .sarif_export import findings_to_sarif, write_sarif
from .sbom import generate_cyclonedx, generate_spdx


def run_full_pipeline(
    root: str | Path,
    *,
    mode: str = "repo",  # repo | diff | staged
    base: str = "HEAD~1",
    head: str = "HEAD",
    workers: Optional[int] = None,
    use_ast: bool = True,
    include_deps: bool = True,
    use_network: bool = False,
    include_fixes: bool = True,
    sarif_path: Optional[str] = None,
    sbom_format: Optional[str] = None,  # cyclonedx | spdx | both
    max_files: int = 2000,
) -> Dict[str, Any]:
    root_p = Path(root).resolve()

    if mode == "diff":
        scan = scan_git_diff(root_p, base=base, head=head, use_ast=use_ast)
    elif mode == "staged":
        scan = scan_git_diff(root_p, staged=True, use_ast=use_ast)
    else:
        scan = scan_repository(
            root_p, workers=workers, use_ast=use_ast, max_files=max_files
        )

    issues = list(scan.get("issues") or [])

    deps: Optional[Dict[str, Any]] = None
    if include_deps:
        deps = scan_dependencies(root_p, use_network=use_network)
        # fold OSV vulns into issues-like entries for SARIF
        for hit in (deps.get("osv") or {}).get("results") or []:
            for v in hit.get("vulns") or []:
                issues.append(
                    {
                        "rule_id": f"GR-CVE-{(v.get('id') or 'OSV')}",
                        "vulnerability_name": v.get("id") or "OSV vulnerability",
                        "severity": v.get("severity") or "MEDIUM",
                        "description": v.get("summary")
                        or f"Vulnerability in {hit.get('package')}@{hit.get('version')}",
                        "remediation": f"Upgrade {hit.get('package')} from {hit.get('version')}",
                        "line": 1,
                        "column": 1,
                        "excerpt_redacted": f"{hit.get('package')}@{hit.get('version')}",
                        "path": f"dependency:{hit.get('ecosystem')}/{hit.get('package')}",
                    }
                )

    fixes = generate_fixes_for_issues(issues, limit=100) if include_fixes else []

    sarif = findings_to_sarif(issues)
    written_sarif = None
    if sarif_path:
        written_sarif = write_sarif(sarif_path, sarif)

    sbom: Dict[str, Any] = {}
    if sbom_format in {"cyclonedx", "both"}:
        sbom["cyclonedx"] = generate_cyclonedx(root_p)
    if sbom_format in {"spdx", "both"}:
        sbom["spdx"] = generate_spdx(root_p)

    return {
        "status": scan.get("status", "OK"),
        "mode": mode,
        "root": str(root_p),
        "scan": scan,
        "dependencies": deps,
        "issue_count": len(issues),
        "issues": issues,
        "fixes": fixes,
        "sarif": sarif if not sarif_path else {"written": written_sarif, "result_count": len(issues)},
        "sbom": sbom or None,
        "security_verdict": scan.get("security_verdict"),
    }


def write_json_report(path: str | Path, report: Dict[str, Any]) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Avoid dumping huge nested sarif twice if present as full object
    p.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return str(p)
