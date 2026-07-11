"""
AI-powered autofix drafts.

Modes:
  1. template (offline, default) — uses fixes.py
  2. openai-compatible HTTP API when GUARDRAIL_LLM_API_KEY + base URL set

Never auto-applies patches without explicit apply=True and path sandbox checks.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .fixes import generate_fix_draft, generate_fixes_for_issues


def _llm_enabled() -> bool:
    return bool(os.environ.get("GUARDRAIL_LLM_API_KEY"))


def _chat_completion(prompt: str, *, max_tokens: int = 800) -> str:
    api_key = os.environ.get("GUARDRAIL_LLM_API_KEY", "")
    base = os.environ.get("GUARDRAIL_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("GUARDRAIL_LLM_MODEL", "gpt-4o-mini")
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior application security engineer. "
                    "Propose minimal secure patches. Return JSON with keys: "
                    "title, guidance, patched_code, risk_notes."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": max_tokens,
    }
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "guardrail-mcp-autofix/2.1",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def generate_ai_fix(
    finding: Dict[str, Any],
    *,
    source_snippet: str = "",
    path: Optional[str] = None,
    use_llm: Optional[bool] = None,
) -> Dict[str, Any]:
    base = generate_fix_draft(finding, path=path)
    base["mode"] = "template"
    want_llm = _llm_enabled() if use_llm is None else use_llm
    if not want_llm:
        base["agent_prompt"] = base.get("agent_prompt") or ""
        return base

    prompt = (
        f"Finding {finding.get('rule_id')} at {path or 'file'}:{finding.get('line')}\n"
        f"Severity: {finding.get('severity')}\n"
        f"Description: {finding.get('description')}\n"
        f"Excerpt: {finding.get('excerpt_redacted')}\n"
        f"Remediation hint: {finding.get('remediation')}\n"
        f"Source context:\n```\n{source_snippet[:3000]}\n```\n"
        "Return only JSON."
    )
    try:
        raw = _chat_completion(prompt)
        # extract JSON
        m = re.search(r"\{[\s\S]*\}", raw)
        parsed = json.loads(m.group(0) if m else raw)
        base["mode"] = "llm"
        base["title"] = parsed.get("title") or base["title"]
        base["guidance"] = parsed.get("guidance") or base["guidance"]
        if parsed.get("patched_code"):
            base["example_after"] = parsed["patched_code"]
        base["risk_notes"] = parsed.get("risk_notes")
        base["llm_raw_ok"] = True
    except Exception as exc:  # noqa: BLE001
        base["mode"] = "template"
        base["llm_error"] = str(exc)[:200]
    return base


def batch_ai_fixes(
    issues: List[Dict[str, Any]],
    *,
    path: Optional[str] = None,
    use_llm: bool = False,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    if not use_llm or not _llm_enabled():
        return generate_fixes_for_issues(issues, path=path, limit=limit)
    out = []
    for iss in issues[:limit]:
        out.append(generate_ai_fix(iss, path=path or iss.get("path"), use_llm=True))
    return out
