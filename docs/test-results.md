# Automated test results

**Command**

```bash
export PYTHONPATH=$PWD
python -m unittest discover -s tests -v
```

**Last recorded run in this repository**

| Metric | Value |
|--------|-------|
| Result | **OK** |
| Tests run | **65** |
| Duration | **0.256 s** |
| Date (UTC) | 2026-07-12 |

Reproduce the table anytime with the command above. CI workflows under `.github/workflows/` also execute tests when Actions are enabled.

## Suites

| Module | Focus |
|--------|--------|
| `tests/test_safety.py` | Regex safety rules, redaction, truncation |
| `tests/test_ast_engine.py` | Python AST sinks |
| `tests/test_advanced_platform.py` | Taint, tree-sitter, plugins, hybrid |
| `tests/test_enterprise.py` | Auth, RBAC, policy, sandbox |
| `tests/test_platform.py` | Repo scan, SARIF, SBOM, tools |
| `tests/test_mcp_dispatch.py` | JSON-RPC MCP methods |
| `tests/test_cost.py` / `test_infra_security.py` | Cost & IaC heuristics |

HTML mirror: [test-results.html](test-results.html)
