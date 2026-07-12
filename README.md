# GuardRail MCP

[![Release](https://img.shields.io/github/v/release/SECRET4422/guardrail-mcp?color=5b9dff)](https://github.com/SECRET4422/guardrail-mcp/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-3ddc97.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-65%20passing-3ddc97)](docs/test-results.md)
[![Website](https://img.shields.io/badge/website-live-3ddc97)](https://secret4422.github.io/guardrail-mcp/)
[![MCPize](https://img.shields.io/badge/MCPize-listing-5b9dff)](https://mcpize.com/mcp/guardrail)

**Hybrid multi-language security analysis over MCP** for AI-assisted development workflows.

GuardRail exposes tools that scan source and infrastructure text for high-signal issues (secrets, dangerous APIs, injection patterns, IaC misconfigurations), with optional tree-sitter structural checks, dependency inventory/OSV, SARIF/SBOM export, and an enterprise policy gateway.

| Resource | URL |
|----------|-----|
| Website | https://secret4422.github.io/guardrail-mcp/ |
| MCPize listing | https://mcpize.com/mcp/guardrail |
| Accuracy policy | [docs/ACCURACY.md](docs/ACCURACY.md) |
| Security / threat model | [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) |
| Examples | [docs/EXAMPLES.md](docs/EXAMPLES.md) |
| Performance | [docs/PERFORMANCE.md](docs/PERFORMANCE.md) |
| Test results | [docs/test-results.md](docs/test-results.md) |
| Enterprise | [docs/ENTERPRISE.md](docs/ENTERPRISE.md) |

## Scope (read this)

- **Does:** static analysis of text you provide; redacts many secret-shaped substrings in excerpts.
- **Does not:** execute scanned code; replace commercial SAST/DAST; guarantee zero false positives/negatives; provide SOC2 certification by itself.
- **Website playground:** browser-only demonstration (`docs/ACCURACY.md`). Production use = Python MCP/CLI.

## Quick start

```bash
git clone https://github.com/SECRET4422/guardrail-mcp.git
cd guardrail-mcp
pip install -r requirements.txt
export PYTHONPATH=$PWD

python -m unittest discover -s tests -v
python -m guardrail --mode stdio
```

### MCP client configuration

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "python",
      "args": ["-m", "guardrail", "--mode", "stdio"],
      "cwd": "/absolute/path/to/guardrail-mcp",
      "env": { "PYTHONPATH": "/absolute/path/to/guardrail-mcp" }
    }
  }
}
```

### CLI scan (ground truth)

```bash
python - <<'PY'
from pathlib import Path
from guardrail.hybrid_scan import hybrid_scan
r = hybrid_scan(
    Path("examples/vulnerable_sample.py").read_text(encoding="utf-8"),
    filename="examples/vulnerable_sample.py",
)
print(r["status"], r["security_verdict"], r["issue_count"], r.get("engines"))
PY
```

`examples/` contains **intentional insecure fixtures** for tests and demos only (labeled in-file). Values are synthetic.

## Capabilities

| Area | Implementation |
|------|----------------|
| Secrets / high-signal patterns | `rules.py`, language grids |
| Python AST + multi-hop taint | `ast_engine.py`, `taint.py` |
| Tree-sitter (optional grammars) | `treesitter_engine.py` |
| Repo / git-diff scan | `repo_scan.py`, `git_scan.py` |
| Dependencies / OSV | `deps.py` (network optional) |
| SARIF / SBOM | `sarif_export.py`, `sbom.py` |
| Enterprise auth, RBAC, policy | `guardrail/enterprise/` |
| Custom rules / plugins | `rule_engine.py`, `plugins.py` |

## Tests

```bash
PYTHONPATH=$PWD python -m unittest discover -s tests -v
```

Published summary: [docs/test-results.md](docs/test-results.md) (reproduce with the command above).

## Performance

Indicative micro-benchmarks are in [docs/PERFORMANCE.md](docs/PERFORMANCE.md) and `benchmarks/`. Re-run on your machine before relying on numbers.

## Enterprise mode

Optional multi-tenant gateway (API keys/JWT, RBAC, path sandbox, audit, rate limits). See [docs/ENTERPRISE.md](docs/ENTERPRISE.md). Do not deploy HTTP enterprise mode without authentication.

## Hosted listing

Optional commercial listing: [mcpize.com/mcp/guardrail](https://mcpize.com/mcp/guardrail).  
Self-hosting the MIT core remains free. Pricing on MCPize is set in that marketplace dashboard.

## Security

- Threat model: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)  
- Vulnerability reporting: [SECURITY.md](SECURITY.md)  
- Claims policy: [docs/ACCURACY.md](docs/ACCURACY.md)

## License

MIT — [LICENSE](LICENSE).
