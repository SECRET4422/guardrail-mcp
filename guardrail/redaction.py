"""Secret-safe excerpt redaction for findings and logs."""

from __future__ import annotations

import re
from typing import Match


# High-signal secret-ish runs to mask inside excerpts
_SECRETISH = re.compile(
    r"(?i)("
    r"(?:sk|pk|rk|ak|api|key|token|secret|password|passwd|pwd|bearer)[-_a-z0-9]*"
    r"\s*[:=]\s*['\"]?[^\s'\"\\]{8,}['\"]?"
    r"|AKIA[0-9A-Z]{16}"
    r"|[A-Za-z0-9+/]{32,}={0,2}"
    r"|[A-Fa-f0-9]{32,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r")"
)


def _mask_token(token: str, keep_edges: int = 3) -> str:
    if len(token) <= keep_edges * 2:
        return "*" * len(token)
    return f"{token[:keep_edges]}{'*' * min(12, len(token) - keep_edges * 2)}{token[-keep_edges:]}"


def redact_match(text: str) -> str:
    """Redact a single matched secret, preserving short edges for triage."""
    if not text:
        return text
    # Prefer full mask for short secrets; edge-preserve for long ones
    if len(text) <= 8:
        return "*" * len(text)
    return _mask_token(text, keep_edges=2)


def redact_excerpt(line: str, match_start: int, match_end: int, context: int = 40) -> str:
    """
    Build a single-line excerpt with the matched span redacted and
    surrounding context truncated for display.

    Keeps identifier/context text readable; only the matched secret span
    (plus any additional high-entropy literal values) is masked.
    """
    if not line:
        return ""

    # Normalize whitespace for display
    raw = line.replace("\t", " ").rstrip("\n\r")
    # Clamp indices to line bounds
    match_start = max(0, min(match_start, len(raw)))
    match_end = max(match_start, min(match_end, len(raw)))

    start = max(0, match_start - context)
    end = min(len(raw), match_end + context)

    prefix = raw[start:match_start]
    matched = raw[match_start:match_end]
    suffix = raw[match_end:end]

    if start > 0:
        prefix = "…" + prefix
    if end < len(raw):
        suffix = suffix + "…"

    # Mask additional long quoted/bare literals in the window only (not key names)
    _extra_literal = re.compile(
        r"(['\"])([A-Za-z0-9_+\-/=.]{12,})\1"  # quoted long literals
        r"|(\b[A-Za-z0-9_+/=]{32,}\b)"  # bare high-entropy runs
    )

    def _mask_extra(m: Match[str]) -> str:
        if m.group(1):  # quoted
            return f"{m.group(1)}{redact_match(m.group(2))}{m.group(1)}"
        return redact_match(m.group(3) or m.group(0))

    prefix = _extra_literal.sub(_mask_extra, prefix)
    suffix = _extra_literal.sub(_mask_extra, suffix)

    # match_start==match_end → context-only pass (no primary secret span)
    if match_start == match_end:
        return _extra_literal.sub(_mask_extra, raw[start:end] if end > start else raw)

    return f"{prefix}{redact_match(matched)}{suffix}"


def sanitize_for_log(message: str, max_len: int = 500) -> str:
    """Redact secret-like tokens before writing to logs."""
    cleaned = _SECRETISH.sub(lambda m: redact_match(m.group(0)), message)
    if len(cleaned) > max_len:
        return cleaned[: max_len - 1] + "…"
    return cleaned
