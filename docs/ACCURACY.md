# Accuracy & claims policy

This document defines what GuardRail **does** and **does not** claim.

## Verified in-repo

| Claim | Evidence |
|-------|----------|
| Hybrid static analysis (regex + Python AST + taint + optional tree-sitter) | `guardrail/hybrid_scan.py`, tests |
| Multi-language pattern/tree-sitter support | `languages.py`, `treesitter_engine.py`, tests |
| Secret redaction in findings | `redaction.py`, tests |
| MCP tools over STDIO / optional SDK / HTTP | `mcp_stdio.py`, `http_api.py` |
| Enterprise gateway (auth, RBAC, policy, audit) | `guardrail/enterprise/*`, tests |
| Automated tests | `python -m unittest discover -s tests` → see `docs/test-results.md` |
| MIT license | `LICENSE` |

## Website “Live security playground”

- Runs **entirely in the browser** (`website/js/demo-engine.js`).
- Uses **similar rule IDs and severity labels** for product education.
- Is **not** a byte-for-byte port of the Python engines.
- For production decisions, use the **Python MCP server or CLI** (`hybrid_scan` / `audit_code_safety`).

## Performance numbers

- Published figures in `docs/PERFORMANCE.md` and `benchmarks/*.json` are from a **specific environment**.
- Re-run benchmarks on your hardware before using numbers in contracts or SLAs.

## What we do not claim

- Full commercial SAST/DAST replacement  
- Zero false positives / false negatives  
- Formal SOC2/ISO certification by shipping GuardRail alone  
- That example fixtures contain real credentials (they must not)  
- Endorsements from unnamed “staff engineers” or fabricated reviews  

## Example fixtures

Files under `examples/` are **intentional insecure fixtures** for demos and tests.  
They are labeled in-file. Treat any secret-shaped strings there as **synthetic**.

## Reporting inaccurate marketing

Open a GitHub issue if you find a claim in the README, website, or listing that is not supported by the code.
