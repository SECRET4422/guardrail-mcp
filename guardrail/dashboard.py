"""
Lightweight web dashboard for security scoring & historical reports.

Served under FastAPI when GUARDRAIL_DASHBOARD=1 (default on for http mode).
Uses SQLite for history (no external DB required).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_DB_LOCK = threading.Lock()


def _db_path() -> Path:
    return Path(os.environ.get("GUARDRAIL_DB_PATH", ".guardrail_history.db"))


def _connect() -> sqlite3.Connection:
    p = _db_path()
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _DB_LOCK:
        conn = _connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    tenant_id TEXT,
                    tool TEXT,
                    path TEXT,
                    risk_score INTEGER,
                    issue_count INTEGER,
                    verdict TEXT,
                    policy_decision TEXT,
                    payload TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    tenant_id TEXT,
                    score INTEGER,
                    grade TEXT,
                    details TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()


def record_scan(
    *,
    tenant_id: str,
    tool: str,
    path: str,
    risk_score: int,
    issue_count: int,
    verdict: str,
    policy_decision: str,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    init_db()
    with _DB_LOCK:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO scan_runs
                (ts, tenant_id, tool, path, risk_score, issue_count, verdict, policy_decision, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    tenant_id,
                    tool,
                    path,
                    int(risk_score),
                    int(issue_count),
                    verdict,
                    policy_decision,
                    json.dumps(payload or {})[:200000],
                ),
            )
            conn.commit()
        finally:
            conn.close()


def compute_security_score(issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    """100 = clean; deduct by severity."""
    weights = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    score = 100
    counts: Dict[str, int] = {}
    for iss in issues:
        sev = str(iss.get("severity") or "MEDIUM").upper()
        counts[sev] = counts.get(sev, 0) + 1
        score -= weights.get(sev, 5)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return {"score": score, "grade": grade, "severity_counts": counts}


def record_score(tenant_id: str, score_info: Dict[str, Any]) -> None:
    init_db()
    with _DB_LOCK:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO scores (ts, tenant_id, score, grade, details) VALUES (?, ?, ?, ?, ?)",
                (
                    time.time(),
                    tenant_id,
                    int(score_info.get("score") or 0),
                    str(score_info.get("grade") or ""),
                    json.dumps(score_info),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def history(limit: int = 50, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    with _DB_LOCK:
        conn = _connect()
        try:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM scan_runs WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def score_history(limit: int = 50, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    with _DB_LOCK:
        conn = _connect()
        try:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM scores WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scores ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def dashboard_html() -> str:
    runs = history(30)
    scores = score_history(30)
    latest_score = scores[0]["score"] if scores else "—"
    latest_grade = scores[0]["grade"] if scores else "—"
    rows = ""
    for r in runs[:20]:
        rows += (
            f"<tr><td>{time.strftime('%Y-%m-%d %H:%M', time.gmtime(r['ts']))}Z</td>"
            f"<td>{r.get('tenant_id') or ''}</td><td>{r.get('tool')}</td>"
            f"<td>{r.get('path') or ''}</td><td>{r.get('issue_count')}</td>"
            f"<td>{r.get('risk_score')}</td><td>{r.get('verdict')}</td>"
            f"<td>{r.get('policy_decision') or ''}</td></tr>"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>GuardRail Security Dashboard</title>
<style>
  :root {{ --bg:#0b1220; --card:#121a2b; --text:#e8eefc; --muted:#93a0b8; --accent:#5b9dff; --bad:#ff6b6b; --ok:#3ddc97; }}
  body {{ margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--text); }}
  header {{ padding:24px 32px; border-bottom:1px solid #1e2a44; display:flex; justify-content:space-between; align-items:center; }}
  h1 {{ margin:0; font-size:1.25rem; letter-spacing:.02em; }}
  .badge {{ background:#1a2744; color:var(--accent); padding:6px 10px; border-radius:999px; font-size:.8rem; }}
  main {{ padding:24px 32px; display:grid; gap:20px; }}
  .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap:16px; }}
  .card {{ background:var(--card); border:1px solid #1e2a44; border-radius:14px; padding:16px 18px; }}
  .metric {{ font-size:2rem; font-weight:700; }}
  .muted {{ color:var(--muted); font-size:.85rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
  th, td {{ text-align:left; padding:10px 8px; border-bottom:1px solid #1e2a44; }}
  th {{ color:var(--muted); font-weight:600; }}
  a {{ color:var(--accent); }}
</style>
</head>
<body>
<header>
  <h1>GuardRail Security Dashboard</h1>
  <span class="badge">Enterprise MCP · local history</span>
</header>
<main>
  <section class="grid">
    <div class="card"><div class="muted">Latest score</div><div class="metric">{latest_score}</div></div>
    <div class="card"><div class="muted">Grade</div><div class="metric">{latest_grade}</div></div>
    <div class="card"><div class="muted">Runs recorded</div><div class="metric">{len(runs)}</div></div>
    <div class="card"><div class="muted">API</div><div class="muted"><a href="/health">/health</a> · <a href="/metrics">/metrics</a> · <a href="/api/dashboard/history">/api/dashboard/history</a></div></div>
  </section>
  <section class="card">
    <h2 style="margin-top:0;font-size:1rem;">Recent scans</h2>
    <table>
      <thead><tr><th>Time</th><th>Tenant</th><th>Tool</th><th>Path</th><th>Issues</th><th>Risk</th><th>Verdict</th><th>Policy</th></tr></thead>
      <tbody>{rows or '<tr><td colspan="8" class="muted">No scans recorded yet. Run tools via MCP/HTTP.</td></tr>'}</tbody>
    </table>
  </section>
</main>
</body>
</html>"""
