#!/usr/bin/env python3
"""Performance + detection benchmarks for GuardRail hybrid engines."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SAMPLES = {
    "python_taint": '''
def f(request):
    a = request.args.get("q")
    b = a
    c = f"SELECT * FROM t WHERE x='{b}'"
    db.execute(c)
    cmd = b
    os.system(cmd)
''',
    "python_clean": "def add(a,b):\n    return a+b\n",
    "js_eval": "function x(u){ eval(u); element.innerHTML = u; }\n",
    "go_sql": 'package main\nfunc f(db *sql.DB, id string){ db.Query(fmt.Sprintf("SELECT %s", id)) }\n',
    "c_buf": '#include <string.h>\nvoid f(char*s){ char b[8]; strcpy(b,s); system(s); }\n',
}


def bench_once(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    dt = (time.perf_counter() - t0) * 1000
    return result, dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    from guardrail.hybrid_scan import hybrid_scan
    from guardrail.taint import analyze_taint
    from guardrail.treesitter_engine import scan_with_treesitter, treesitter_status

    report = {
        "treesitter": treesitter_status(),
        "cases": [],
        "summary": {},
    }

    for name, src in SAMPLES.items():
        lang = {
            "python_taint": "python",
            "python_clean": "python",
            "js_eval": "javascript",
            "go_sql": "go",
            "c_buf": "c",
        }[name]
        times = []
        last = None
        for _ in range(args.rounds):
            res, ms = bench_once(
                hybrid_scan, src, language=lang, filename=f"{name}.ext", use_plugins=False
            )
            times.append(ms)
            last = res
        case = {
            "name": name,
            "language": lang,
            "issue_count": last.get("issue_count") if last else 0,
            "engines": last.get("engines") if last else [],
            "ms_mean": round(statistics.mean(times), 3),
            "ms_p50": round(statistics.median(times), 3),
            "ms_min": round(min(times), 3),
            "ms_max": round(max(times), 3),
        }
        # taint-only microbench for python
        if lang == "python":
            t_times = []
            for _ in range(args.rounds):
                _, ms = bench_once(analyze_taint, src)
                t_times.append(ms)
            case["taint_ms_mean"] = round(statistics.mean(t_times), 3)
            ts_times = []
            for _ in range(args.rounds):
                _, ms = bench_once(scan_with_treesitter, src, "python")
                ts_times.append(ms)
            case["treesitter_ms_mean"] = round(statistics.mean(ts_times), 3)
        report["cases"].append(case)
        print(
            f"{name:16} issues={case['issue_count']:3} mean={case['ms_mean']:8.3f}ms engines={case['engines']}"
        )

    report["summary"] = {
        "total_cases": len(report["cases"]),
        "mean_ms": round(statistics.mean(c["ms_mean"] for c in report["cases"]), 3),
    }
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("wrote", args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
