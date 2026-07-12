# Performance metrics

GuardRail is optimized for **interactive agent loops** (sub‑10–50 ms on typical snippets) and **parallel repo walks**.

> Numbers below were measured on the CI/dev sandbox (Python 3.13). Re-run on your hardware with:
> `python benchmarks/run_benchmarks.py --json benchmarks/latest.json`
> and `python benchmarks/measure_perf.py` (if present) / see `benchmarks/performance_report.json`.

## Single-file hybrid scan (representative)

| Workload | Mean latency | Throughput (approx) | Peak traced mem |
|----------|--------------|---------------------|-----------------|
| Dirty Python sample (`examples/vulnerable_sample.py`) | **~9 ms** | ~115 scans/s | ~110 KB |
| Clean Python function | **~0.7 ms** | ~1.4k scans/s | ~30 KB |
| Small JavaScript snippet | **~0.5 ms** | ~2k scans/s | ~4 KB |

Micro-benchmarks (regex/AST path) often land **&lt;1 ms** for tiny files.

## Repo scan

- Parallel workers: default `min(32, cpu*2)`
- Skips `node_modules`, `.git`, venv, build caches
- Incremental content-hash cache: `.guardrail_cache.json` (hit rate reported in scan JSON)
- Caps: max files (default 2000), max file bytes (512 KiB)

## What dominates cost

1. **Tree-sitter** parse (when grammar available)  
2. **AST + multi-hop taint** on large Python modules  
3. **Number of files** in repo mode (I/O bound more than CPU for small files)

## Memory

- Process RSS in lightweight microbench runs: on the order of **~15–50 MB** depending on imports (tree-sitter grammars increase baseline).  
- Per-scan traced allocations for a dirty sample: ~**100 KB** class (not RSS).

## CI expectations

- Unit suite: **65 tests in &lt;1s** on a warm machine (`OK`, occasionally 1 skip if optional grammar missing).  
- Full multilang tree-sitter install recommended for production accuracy.

## Reproducing

```bash
export PYTHONPATH=$PWD
python -m unittest discover -s tests -v
python benchmarks/run_benchmarks.py --rounds 5 --json benchmarks/latest.json
python -c "import json; print(json.load(open('benchmarks/performance_report.json')))"
```

See published artifacts:

- [`benchmarks/performance_report.json`](../benchmarks/performance_report.json)
- [`benchmarks/latest.json`](../benchmarks/latest.json)
- [`docs/test-results.md`](test-results.md)
