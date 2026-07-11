"""
Dependency & CVE analysis via OSV API + optional local tool wrappers.

- Parses requirements.txt / package.json / go.mod / Cargo.toml
- Queries https://api.osv.dev/v1/querybatch (network optional)
- Can shell out to pip-audit / npm audit when installed
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .sbom import collect_components

logger = logging.getLogger("GuardRailMCP.deps")

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
DEFAULT_TIMEOUT = 20


_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "cargo": "crates.io",
}


def _osv_ecosystem(purl_type: str, ecosystem_hint: str) -> str:
    return _ECOSYSTEM.get(purl_type, ecosystem_hint or "PyPI")


def query_osv_batch(
    packages: List[Dict[str, Any]],
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """
    packages: [{name, version, ecosystem}]
    Returns list of {package, vulns: [...]} 
    """
    if not packages:
        return []

    queries = []
    for p in packages:
        ver = p.get("version")
        if not ver or ver == "UNKNOWN":
            # OSV needs a version for precise results; skip unpinned
            continue
        queries.append(
            {
                "package": {
                    "name": p["name"],
                    "ecosystem": p.get("ecosystem") or "PyPI",
                },
                "version": ver,
            }
        )
    if not queries:
        return []

    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERYBATCH,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "guardrail-mcp/1.2"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("OSV query failed: %s", exc)
        return [{"error": str(exc), "package": q["package"]} for q in queries]

    results = data.get("results") or []
    out = []
    for q, r in zip(queries, results):
        vulns = r.get("vulns") or []
        out.append(
            {
                "package": q["package"]["name"],
                "version": q["version"],
                "ecosystem": q["package"]["ecosystem"],
                "vuln_count": len(vulns),
                "vulns": [
                    {
                        "id": v.get("id"),
                        "summary": v.get("summary") or "",
                        "severity": _severity_from_osv(v),
                        "aliases": v.get("aliases") or [],
                        "references": [
                            ref.get("url")
                            for ref in (v.get("references") or [])
                            if ref.get("url")
                        ][:5],
                    }
                    for v in vulns[:20]
                ],
            }
        )
    return out


def _severity_from_osv(v: dict) -> str:
    # Prefer CVSS if present
    for sev in v.get("severity") or []:
        score = sev.get("score") or ""
        if isinstance(score, str) and "CVSS" in score.upper():
            # crude: parse trailing number
            import re

            m = re.search(r"(\d+\.?\d*)\s*$", score)
            if m:
                val = float(m.group(1))
                if val >= 9:
                    return "CRITICAL"
                if val >= 7:
                    return "HIGH"
                if val >= 4:
                    return "MEDIUM"
                return "LOW"
    db = v.get("database_specific") or {}
    sev = (db.get("severity") or "").upper()
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return sev
    return "MEDIUM"


def scan_dependencies(
    root: str | Path,
    *,
    use_network: bool = True,
    run_pip_audit: bool = False,
    run_npm_audit: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    root = Path(root)
    comps = collect_components(root)
    packages = [
        {
            "name": c["name"],
            "version": c["version"],
            "ecosystem": c.get("ecosystem") or _osv_ecosystem(c["purl"].split("/")[0].replace("pkg:", ""), ""),
        }
        for c in comps
    ]

    osv_hits: List[Dict[str, Any]] = []
    if use_network and packages:
        osv_hits = query_osv_batch(packages, timeout=timeout)

    tool_results: Dict[str, Any] = {}
    if run_pip_audit and shutil.which("pip-audit"):
        tool_results["pip_audit"] = _run_json_cmd(
            ["pip-audit", "-f", "json", "--progress-spinner", "off"],
            cwd=str(root),
            timeout=timeout,
        )
    elif run_pip_audit:
        tool_results["pip_audit"] = {"skipped": True, "reason": "pip-audit not installed"}

    if run_npm_audit and (root / "package.json").is_file() and shutil.which("npm"):
        tool_results["npm_audit"] = _run_json_cmd(
            ["npm", "audit", "--json"],
            cwd=str(root),
            timeout=timeout,
        )
    elif run_npm_audit:
        tool_results["npm_audit"] = {"skipped": True, "reason": "npm or package.json missing"}

    total_vulns = sum(h.get("vuln_count", 0) for h in osv_hits if "error" not in h)
    critical = 0
    for h in osv_hits:
        for v in h.get("vulns") or []:
            if v.get("severity") == "CRITICAL":
                critical += 1

    return {
        "status": "OK",
        "root": str(root.resolve()),
        "packages_discovered": len(packages),
        "packages": packages,
        "osv": {
            "enabled": use_network,
            "packages_with_vulns": sum(1 for h in osv_hits if h.get("vuln_count", 0) > 0),
            "total_vulns": total_vulns,
            "critical_vulns": critical,
            "results": osv_hits,
        },
        "tools": tool_results,
        "notes": [
            "OSV results require network access to api.osv.dev.",
            "Unpinned versions (UNKNOWN) are listed but not queried.",
            "pip-audit/npm audit are optional enhancers when installed.",
        ],
    }


def _run_json_cmd(cmd: List[str], *, cwd: str, timeout: int) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        try:
            return {"returncode": proc.returncode, "data": json.loads(proc.stdout or "{}")}
        except json.JSONDecodeError:
            return {
                "returncode": proc.returncode,
                "stdout": (proc.stdout or "")[:4000],
                "stderr": (proc.stderr or "")[:2000],
            }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
