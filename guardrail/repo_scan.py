"""
Repository-wide recursive scanning with parallel workers.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .docker_k8s import analyze_container_config
from .infra_security import deep_analyze_infra
from .languages import detect_language, scan_language
from .models import Finding, risk_level_from_score
from .safety import run_core_safety_audit

# Directories skipped by default
DEFAULT_SKIP_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".arena",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".next",
    ".nuxt",
    "coverage",
    "vendor",
    ".idea",
    ".vscode",
}

DEFAULT_EXTENSIONS: Set[str] = {
    ".py",
    ".pyw",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".kt",
    ".rs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".cs",
    ".rb",
    ".php",
    ".swift",
    ".tf",
    ".hcl",
    ".yml",
    ".yaml",
    ".json",
    ".sh",
    ".bash",
    ".sql",
    ".Dockerfile",
    ".toml",
    ".md",
}

SPECIAL_NAMES: Set[str] = {
    "Dockerfile",
    "dockerfile",
    "Makefile",
    "go.mod",
    "Cargo.toml",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
}


@dataclass
class FileScanResult:
    path: str
    language: str
    status: str
    risk_score: int = 0
    issue_count: int = 0
    issues: List[Dict[str, Any]] = field(default_factory=list)
    engines: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "path": self.path,
            "language": self.language,
            "status": self.status,
            "risk_score": self.risk_score,
            "issue_count": self.issue_count,
            "issues": self.issues,
            "engines": self.engines,
        }
        if self.error:
            d["error"] = self.error
        return d


def _should_skip_dir(name: str, extra_skip: Set[str]) -> bool:
    return name in DEFAULT_SKIP_DIRS or name in extra_skip or name.startswith(".")


def iter_source_files(
    root: str | Path,
    *,
    max_files: int = 2000,
    max_file_bytes: int = 512_000,
    extra_skip_dirs: Optional[Iterable[str]] = None,
    extensions: Optional[Set[str]] = None,
) -> List[Path]:
    root = Path(root).resolve()
    skip = set(extra_skip_dirs or [])
    exts = extensions or DEFAULT_EXTENSIONS
    out: List[Path] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # prune in-place
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d, skip)]
        for fn in filenames:
            p = Path(dirpath) / fn
            if fn in SPECIAL_NAMES or p.suffix.lower() in exts or p.name == "Dockerfile":
                try:
                    if p.stat().st_size > max_file_bytes:
                        continue
                except OSError:
                    continue
                out.append(p)
                if len(out) >= max_files:
                    return out
    return out


def scan_file_path(
    path: Path,
    *,
    root: Optional[Path] = None,
    use_ast: bool = True,
    cache: Any = None,
) -> FileScanResult:
    rel = str(path.relative_to(root)) if root else str(path)

    if cache is not None:
        cached = cache.get(path)
        if cached and isinstance(cached, dict) and cached.get("status") == "OK":
            return FileScanResult(
                path=rel,
                language=cached.get("language") or "unknown",
                status="OK",
                risk_score=int(cached.get("risk_score") or 0),
                issue_count=int(cached.get("issue_count") or 0),
                issues=list(cached.get("issues") or []),
                engines=list(cached.get("engines") or []) + ["cache"],
            )

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return FileScanResult(path=rel, language="unknown", status="ERROR", error=str(exc))

    lang = detect_language(str(path), text)
    issues: List[Dict[str, Any]] = []
    engines: List[str] = []
    score = 0

    # Container / k8s / terraform-ish
    if lang in {"dockerfile", "yaml", "terraform"} or path.name == "Dockerfile":
        if lang == "dockerfile" or path.name == "Dockerfile" or "kind:" in text[:300].lower():
            ctr = analyze_container_config(text, filename=path.name)
            engines.append("docker_k8s")
            for iss in ctr.get("issues") or []:
                item = dict(iss)
                item["path"] = rel
                if "vulnerability_name" not in item:
                    item["vulnerability_name"] = item.get("anomaly_id") or item.get("rule_id")
                if "description" not in item:
                    item["description"] = item.get("technical_breakdown") or ""
                if "excerpt_redacted" not in item:
                    item["excerpt_redacted"] = item.get("excerpt") or ""
                issues.append(item)
        if lang == "terraform" or path.suffix in {".tf", ".hcl"}:
            infra = deep_analyze_infra(text, "aws")
            engines.append("infra")
            for iss in infra.get("security_issues") or []:
                item = dict(iss)
                item["path"] = rel
                if "vulnerability_name" not in item:
                    item["vulnerability_name"] = item.get("anomaly_id") or item.get("rule_id")
                if "description" not in item:
                    item["description"] = item.get("technical_breakdown") or ""
                if "excerpt_redacted" not in item:
                    item["excerpt_redacted"] = item.get("excerpt") or ""
                issues.append(item)

    # Hybrid scan for source languages
    if lang in {
        "python",
        "javascript",
        "typescript",
        "go",
        "java",
        "kotlin",
        "rust",
        "c",
        "cpp",
        "shell",
    }:
        from .hybrid_scan import hybrid_scan

        res = hybrid_scan(
            text,
            filename=rel,
            language=lang,
            tenant_id="local",
            use_ast=use_ast and lang == "python",
        )
        engines.extend(res.get("engines") or ["hybrid"])
        for iss in res.get("issues") or []:
            item = dict(iss)
            item["path"] = rel
            issues.append(item)
        score = int(res.get("risk_score") or 0)
    elif lang not in {"dockerfile", "yaml", "terraform", "unknown"}:
        res = run_core_safety_audit(text, tenant_id="local", filename=rel, use_ast=False)
        engines.extend(res.get("engines") or ["regex"])
        for iss in res.get("issues") or []:
            item = dict(iss)
            item["path"] = rel
            issues.append(item)
        score = int(res.get("risk_score") or 0)
        lang_findings = scan_language(text, lang, filename=rel)
        if lang_findings:
            engines.append(f"lang:{lang}")
        for f in lang_findings:
            d = f.to_dict()
            d["path"] = rel
            issues.append(d)

    dedup = {}
    for iss in issues:
        key = (iss.get("rule_id"), iss.get("line"), rel)
        dedup[key] = iss
    issues = list(dedup.values())

    if score == 0 and issues:
        from .languages import score_findings
        from .models import Finding as F

        tmp = []
        for iss in issues:
            tmp.append(
                F(
                    rule_id=str(iss.get("rule_id") or ""),
                    vulnerability_name=str(iss.get("vulnerability_name") or ""),
                    severity=str(iss.get("severity") or "MEDIUM"),
                    description=str(iss.get("description") or ""),
                    remediation=str(iss.get("remediation") or ""),
                    line=int(iss.get("line") or 1),
                    column=int(iss.get("column") or 1),
                    excerpt_redacted=str(iss.get("excerpt_redacted") or ""),
                    match_length=int(iss.get("match_length") or 0),
                )
            )
        score = score_findings(tmp)

    result = FileScanResult(
        path=rel,
        language=lang,
        status="OK",
        risk_score=min(score, 999),
        issue_count=len(issues),
        issues=issues,
        engines=engines,
    )
    if cache is not None:
        cache.put(path, result.to_dict())
    return result


def scan_repository(
    root: str | Path,
    *,
    workers: Optional[int] = None,
    max_files: int = 2000,
    max_file_bytes: int = 512_000,
    use_ast: bool = True,
    include_clean: bool = False,
    incremental: bool = True,
) -> Dict[str, Any]:
    """Recursively scan a repository in parallel with optional incremental cache."""
    root_p = Path(root).resolve()
    if not root_p.is_dir():
        return {"status": "ERROR", "reason": f"Not a directory: {root_p}"}

    files = iter_source_files(root_p, max_files=max_files, max_file_bytes=max_file_bytes)
    workers = workers or min(32, max(4, (os.cpu_count() or 4) * 2))

    cache = None
    if incremental:
        try:
            from .incremental import ScanCache

            cache = ScanCache(root_p / ".guardrail_cache.json")
        except Exception:
            cache = None

    results: List[FileScanResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(scan_file_path, p, root=root_p, use_ast=use_ast, cache=cache): p
            for p in files
        }
        for fut in as_completed(futs):
            results.append(fut.result())

    if cache is not None:
        cache.save()

    results.sort(key=lambda r: (-r.risk_score, r.path))
    all_issues: List[Dict[str, Any]] = []
    for r in results:
        all_issues.extend(r.issues)

    total_score = sum(r.risk_score for r in results)
    files_with_issues = [r for r in results if r.issue_count > 0]
    file_dicts = [
        r.to_dict()
        for r in results
        if include_clean or r.issue_count > 0 or r.status != "OK"
    ]

    out = {
        "status": "OK",
        "root": str(root_p),
        "files_scanned": len(results),
        "files_with_issues": len(files_with_issues),
        "issue_count": len(all_issues),
        "aggregate_risk_score": min(total_score, 99999),
        "risk_level": risk_level_from_score(min(total_score, 999)),
        "security_verdict": "REJECTED"
        if total_score >= 40
        or any((i.get("severity") or "").upper() == "CRITICAL" for i in all_issues)
        else "APPROVED",
        "workers": workers,
        "files": file_dicts,
        "issues": all_issues,
        "notes": [
            f"Parallel scan with {workers} workers.",
            "Skipped VCS/cache/vendor directories.",
            "Hybrid engines + optional incremental file cache.",
        ],
    }
    if cache is not None:
        out["cache"] = cache.stats()
    return out
