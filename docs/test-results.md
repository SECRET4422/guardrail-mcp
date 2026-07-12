# Automated test results

**Last published run (local CI sandbox)**

| Metric | Value |
|--------|-------|
| Framework | `unittest` |
| Tests run | **65** |
| Failures | **0** |
| Errors | **0** |
| Skipped | **1** (optional tree-sitter grammar edge) |
| Duration | **~0.31 s** |
| Result | **OK** |

## How to reproduce

```bash
git clone https://github.com/SECRET4422/guardrail-mcp.git
cd guardrail-mcp
pip install -r requirements.txt
export PYTHONPATH=$PWD
python -m unittest discover -s tests -v
```

## Coverage areas

| Suite | What it proves |
|-------|----------------|
| `test_safety` / `test_ast_engine` / `test_advanced_platform` | Hybrid engines, taint, tree-sitter, redaction |
| `test_enterprise` | Auth, RBAC, policy DENY, sandbox |
| `test_platform` | Repo scan, SARIF, SBOM, tools catalog |
| `test_cost` / `test_infra_security` | Cost + IaC heuristics |
| `test_mcp_dispatch` | MCP JSON-RPC tools/list & tools/call |

## CI

GitHub Actions workflows under `.github/workflows/` run tests on PR/push and can upload SARIF.

Badge (workflow must be enabled on the repo):

![Tests](https://github.com/SECRET4422/guardrail-mcp/actions/workflows/guardrail-app.yml/badge.svg)
