"""
Git-aware scanning: diff / PR changed files.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .repo_scan import scan_file_path
from .models import risk_level_from_score


def _run_git(repo: Path, args: Sequence[str], timeout: int = 30) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "git failed")
    return proc.stdout


def list_changed_files(
    repo: str | Path,
    *,
    base: str = "HEAD~1",
    head: str = "HEAD",
    staged: bool = False,
    unstaged: bool = False,
) -> List[str]:
    """
    Return paths (relative) changed between base...head, or working tree.
    """
    repo_p = Path(repo).resolve()
    if staged:
        out = _run_git(repo_p, ["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    if unstaged:
        out = _run_git(repo_p, ["diff", "--name-only", "--diff-filter=ACMR"])
        untracked = _run_git(repo_p, ["ls-files", "--others", "--exclude-standard"])
        files = [ln.strip() for ln in out.splitlines() if ln.strip()]
        files += [ln.strip() for ln in untracked.splitlines() if ln.strip()]
        return sorted(set(files))

    # triple-dot for merge-base semantics (PR style)
    try:
        out = _run_git(repo_p, ["diff", "--name-only", "--diff-filter=ACMR", f"{base}...{head}"])
    except RuntimeError:
        out = _run_git(repo_p, ["diff", "--name-only", "--diff-filter=ACMR", base, head])
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def get_unified_diff(
    repo: str | Path,
    *,
    base: str = "HEAD~1",
    head: str = "HEAD",
    path: Optional[str] = None,
) -> str:
    repo_p = Path(repo).resolve()
    args = ["diff", f"{base}...{head}"]
    if path:
        args.extend(["--", path])
    try:
        return _run_git(repo_p, args)
    except RuntimeError:
        args = ["diff", base, head]
        if path:
            args.extend(["--", path])
        return _run_git(repo_p, args)


def scan_git_diff(
    repo: str | Path,
    *,
    base: str = "HEAD~1",
    head: str = "HEAD",
    staged: bool = False,
    unstaged: bool = False,
    use_ast: bool = True,
) -> Dict[str, Any]:
    """
    Scan only files changed in a git range (PR/diff mode).
    """
    repo_p = Path(repo).resolve()
    if not (repo_p / ".git").exists():
        # allow worktree
        try:
            _run_git(repo_p, ["rev-parse", "--is-inside-work-tree"])
        except Exception as exc:  # noqa: BLE001
            return {"status": "ERROR", "reason": f"Not a git repository: {exc}"}

    try:
        changed = list_changed_files(
            repo_p, base=base, head=head, staged=staged, unstaged=unstaged
        )
    except Exception as exc:  # noqa: BLE001
        return {"status": "ERROR", "reason": str(exc)}

    results = []
    all_issues: List[Dict[str, Any]] = []
    for rel in changed:
        path = repo_p / rel
        if not path.is_file():
            continue
        # skip huge
        try:
            if path.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        r = scan_file_path(path, root=repo_p, use_ast=use_ast)
        results.append(r.to_dict())
        all_issues.extend(r.issues)

    total = sum(int(r.get("risk_score") or 0) for r in results)
    return {
        "status": "OK",
        "root": str(repo_p),
        "mode": "staged" if staged else ("unstaged" if unstaged else f"{base}...{head}"),
        "base": base,
        "head": head,
        "files_changed": len(changed),
        "files_scanned": len(results),
        "issue_count": len(all_issues),
        "aggregate_risk_score": total,
        "risk_level": risk_level_from_score(min(total, 999)),
        "security_verdict": "REJECTED"
        if total >= 40
        or any((i.get("severity") or "").upper() == "CRITICAL" for i in all_issues)
        else "APPROVED",
        "changed_files": changed,
        "files": results,
        "issues": all_issues,
        "notes": [
            "Only added/changed files are scanned (not full history).",
            "Pair with SARIF export for PR annotations.",
        ],
    }
