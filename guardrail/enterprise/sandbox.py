"""Path sandboxing for repository / filesystem tools."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


def _resolve(path: str) -> Path:
    return Path(path).expanduser().resolve()


def validate_path(
    path: str,
    allowed_roots: Sequence[str],
    *,
    must_exist: bool = False,
) -> Tuple[bool, str, Optional[str]]:
    """
    Ensure path is inside one of allowed_roots.
    If allowed_roots empty, allow any path (dev mode) but still normalize.
    Returns (ok, message, resolved_path).
    """
    try:
        target = _resolve(path)
    except (OSError, RuntimeError) as exc:
        return False, f"Invalid path: {exc}", None

    if must_exist and not target.exists():
        return False, f"Path does not exist: {target}", None

    if not allowed_roots:
        return True, "ok", str(target)

    for root in allowed_roots:
        try:
            root_p = _resolve(root)
        except (OSError, RuntimeError):
            continue
        try:
            target.relative_to(root_p)
            return True, "ok", str(target)
        except ValueError:
            continue

    return (
        False,
        f"Path '{target}' is outside allowed roots: {list(allowed_roots)}",
        None,
    )


def merge_roots(global_roots: Sequence[str], tenant_roots: Sequence[str]) -> List[str]:
    """Tenant roots further restrict global roots when both set."""
    g = [str(_resolve(r)) for r in global_roots if r]
    t = [str(_resolve(r)) for r in tenant_roots if r]
    if g and t:
        # intersection-ish: tenant roots must live under global
        out = []
        for tr in t:
            for gr in g:
                try:
                    Path(tr).resolve().relative_to(Path(gr).resolve())
                    out.append(tr)
                    break
                except ValueError:
                    # if tenant root is broader, keep global child only when equal
                    try:
                        Path(gr).resolve().relative_to(Path(tr).resolve())
                        out.append(gr)
                        break
                    except ValueError:
                        continue
        return out or g
    return t or g
