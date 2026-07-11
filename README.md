# GuardRail MCP v2.0 (Enterprise)

Multi-language **enterprise agent security MCP**: hybrid Python AST taint, multi-language sinks, parallel repo & PR scanning, OSV CVEs, SARIF/SBOM, Docker/K8s checks, **plus multi-tenant RBAC, policy packs, audit logs, path sandbox, quotas, and Prometheus metrics**.

> Heuristic guardrails for developers & coding agents — not a replacement for commercial SAST or a formal SOC2 certification. Secrets are redacted in findings.

**Enterprise guide:** [docs/ENTERPRISE.md](docs/ENTERPRISE.md)

## Feature map

| Capability | Status | Entry point |
|------------|--------|-------------|
| Multi-language analysis | **Shipped** | `audit_code_safety`, `languages.py` |
| Repo-wide recursive scan | **Shipped** | `scan-repo` / `scan_repository` |
| Git diff / PR scanning | **Shipped** | `scan-diff` / `scan_git_diff` |
| Dependency & CVE (OSV) | **Shipped** | `scan_dependencies` |
| SARIF / SBOM | **Shipped** | `export_sarif`, `generate_sbom` |
| Fix drafts | **Shipped** | `suggest_fixes` |
| Docker/K8s security | **Shipped** | `audit_container_config` |
| **Enterprise RBAC + API keys/JWT** | **Shipped** | `guardrail/enterprise/` |
| **Policy packs (strict/soc2/pci)** | **Shipped** | `evaluate_policy`, gateway gates |
| **Path sandbox** | **Shipped** | `allowed_roots` |
| **Audit log + correlation IDs** | **Shipped** | JSONL + `list_audit_events` |
| **Rate limit + quotas** | **Shipped** | per-tenant RPM / monthly |
| **Prometheus metrics** | **Shipped** | `GET /metrics` |
| **K8s/Docker deploy** | **Shipped** | `deploy/` |

### Language coverage

| Language | Engine |
|----------|--------|
| Python | Regex secrets + **AST taint** (`eval` aliases, SQL, shell, pickle, yaml) |
| JavaScript / TypeScript | `eval`/`Function`, `child_process`, `innerHTML`, TLS flags |
| Go | `fmt.Sprintf` SQL, shell `Command`, `unsafe`, `InsecureSkipVerify` |
| Java / Kotlin | `Runtime.exec`, concat SQL, `ObjectInputStream`, `ScriptEngine` |
| Rust | `unsafe {}`, shell `Command`, invalid certs |
| C / C++ | `gets/strcpy/sprintf`, `system()` |
| Docker / K8s / TF | Privileged, root, `0.0.0.0/0`, latest tags, curl\|sh, hostPath, … |

## Install

```bash
cd guardrail-mcp
pip install -r requirements.txt
export PYTHONPATH=$PWD
```

## CLI

```bash
# MCP server (IDE)
python -m guardrail --mode stdio
python -m guardrail --mode stdio-sdk   # official mcp package
python -m guardrail serve --mode http --port 8787

# Full repo scan (parallel)
python -m guardrail scan-repo . --sarif out.sarif --fixes --deps --json-out report.json

# PR / git diff
python -m guardrail scan-diff . --base origin/main --head HEAD --sarif pr.sarif --fixes

# Dependencies + OSV (network)
python -m guardrail scan-deps . --osv

# SBOM
python -m guardrail sbom . --format both --out sbom.json

# SARIF only
python -m guardrail export-sarif . --out guardrail.sarif
```

Exit code **2** when `security_verdict` is `REJECTED` (handy for CI gates).

## MCP tools (19)

**Security:** `audit_code_safety` · `audit_cloud_cost` · `audit_infra_security` · `scan_repository` · `scan_git_diff` · `scan_dependencies` · `export_sarif` · `generate_sbom` · `suggest_fixes` · `audit_container_config` · `full_pipeline`

**Enterprise:** `enterprise_health` · `enterprise_policy_status` · `evaluate_policy` · `compliance_report` · `list_audit_events` · `issue_access_token` · `reload_enterprise_config` · `manage_tenant`

### Enable enterprise mode

```bash
export GUARDRAIL_ENTERPRISE=1
export GUARDRAIL_ENTERPRISE_CONFIG=$PWD/config/enterprise.json
python -m guardrail serve --mode http --port 8787
# Auth: Authorization: Bearer gr_demo_enterprise_key_change_me
```

## GitHub Actions

Copy `.github/workflows/guardrail.yml` into your app repo (set `PYTHONPATH` / install path as needed). It:

1. Scans PR diffs (or full repo on push)
2. Writes `guardrail.sarif` + JSON report + SBOM
3. Uploads SARIF to GitHub code scanning (when permissions allow)

## HTTP

```bash
GUARDRAIL_HTTP_API_KEY=dev python -m guardrail serve --mode http
curl -H "Authorization: Bearer dev" -H "Content-Type: application/json" \
  -d '{"name":"scan_repository","arguments":{"path":"."}}' \
  http://127.0.0.1:8787/v1/tools/call
```

## Layout

```
guardrail/
  safety.py / ast_engine.py / rules.py   # Python hybrid core
  languages.py                           # JS/Go/Java/Rust/C grids
  repo_scan.py / git_scan.py             # parallel repo + PR
  deps.py / sbom.py                      # OSV + SBOM
  sarif_export.py / fixes.py             # SARIF + fix drafts
  docker_k8s.py / infra_security.py      # containers + IaC
  pipeline.py / tools_catalog.py         # orchestration
  mcp_stdio.py / mcp_sdk_server.py / http_api.py
```

## Tests

```bash
PYTHONPATH=. python -m unittest discover -s tests -v
```

## Honest limits

- Non-Python “AST” is **pattern-based**, not tree-sitter/full compilers.
- OSV needs network; unpinned versions are inventoried but not queried.
- Fix drafts are **template/agent prompts**, not guaranteed patches.
- Not a substitute for CodeQL/Semgrep + SCA at enterprise scale — a strong local/CI agent guardrail.

## License

MIT
