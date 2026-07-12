# GuardRail security model & threat model

This document describes **what GuardRail is designed to protect**, **what it does not protect**, and **how the server itself should be operated**.

> GuardRail is a **static heuristic / hybrid semantic scanner** exposed over MCP.  
> It is **not** a full commercial SAST, DAST, or runtime WAF.

---

## 1. Security goals

1. **Help AI coding agents and developers** detect high-risk patterns **before** code is merged or executed.
2. **Reduce secret leakage into chat/tool transcripts** via redacted excerpts.
3. **Provide policy gates** (ALLOW/DENY) for CI and enterprise agent workflows.
4. **Stay safe by default** when run as a local STDIO MCP (no network required for core scans).

---

## 2. Trust boundaries

```
┌────────────────────┐     tool calls      ┌──────────────────────┐
│  AI client         │ ──────────────────► │  GuardRail MCP       │
│  (Cursor/Claude)   │ ◄────────────────── │  (this process)      │
└────────────────────┘   findings JSON     └──────────┬───────────┘
                                                      │
                         optional                     │ filesystem reads
                         (OSV / LLM fix)              ▼
                                               ┌──────────────┐
                                               │  Repo files  │
                                               └──────────────┘
```

| Component | Trust level | Notes |
|-----------|-------------|--------|
| Developer laptop / CI runner | Trusted host | GuardRail process runs with user permissions |
| MCP client (Cursor, Claude) | Semi-trusted | Can send arbitrary tool arguments |
| Scanned source code | Untrusted input | May contain secrets, malware-like strings, huge blobs |
| Network (OSV, LLM API) | Untrusted | Optional; disabled by default for core path |
| Marketplace host (MCPize) | Third party | Use least-privilege keys; prefer local STDIO for secrets |

---

## 3. Threat model (STRIDE-style)

### 3.1 Threats GuardRail **helps mitigate** (in *user code*)

| Threat | Examples | GuardRail controls |
|--------|----------|--------------------|
| Secret exposure | AWS keys, API tokens, PEM, webhooks | Regex/token rules + redaction |
| Injection | SQL f-strings, `shell=True`, tainted `eval` | AST + multi-hop taint + tree-sitter |
| Supply chain smell | Risky deps (via OSV), curl\|sh | Dep scan + shell/Docker rules |
| IaC misconfig | `0.0.0.0/0`, privileged pods | Infra / Docker / K8s heuristics |
| Agent over-apply | AI merges unsafe patch | MCP tools + policy DENY |

### 3.2 Threats against **GuardRail itself**

| Threat | Risk | Mitigations in product / ops |
|--------|------|------------------------------|
| **Path traversal / arbitrary file read** via `scan_repository` | High on multi-tenant hosts | Enterprise **path sandbox** (`allowed_roots`); local mode only scans paths the operator passes |
| **DoS** (huge input, regex ReDoS) | Medium | Input size caps (`MAX_SOURCE_BYTES`), finding caps, parallel worker limits |
| **Secret re-leak** in responses/logs | High | `redaction.py`, audit arg scrubbing, never log full source at INFO |
| **Auth bypass** (HTTP/enterprise) | High | API keys / JWT, RBAC, `require_auth`, rate limits, quotas |
| **Supply-chain of GuardRail deps** | Medium | Pin requirements, CI tests, minimal dependency surface |
| **Malicious scanned code execution** | Low for static path | GuardRail **does not execute** scanned code; pure parse/scan |
| **Prompt injection via findings** | Medium | Structured JSON findings; keep remediations non-executable |

### 3.3 Out of scope (explicit non-goals)

- Detecting all CVEs / 0-days  
- Binary reverse engineering  
- Runtime exploit prevention  
- Guaranteeing zero false positives/negatives  
- Replacing human security review for critical systems  

---

## 4. Data handling

| Data | Handled? | Stored? |
|------|----------|---------|
| Source snippets in tool args | Yes (in memory) | Optional SQLite dashboard history (local) |
| Secrets in code | Detected | **Redacted** in findings; rotate if real |
| API keys for enterprise | Yes | Config / env (operator-managed) |
| Telemetry to GuardRail authors | **No** | No phoning home in open-source core |

**Recommendation:** For sensitive monorepos, run **local STDIO**, not a shared multi-tenant cloud, unless sandbox + auth are fully configured.

---

## 5. Recommended deployment modes

### A) Local developer MCP (default)
- Transport: STDIO  
- Auth: none (single-user machine)  
- Network: off  

### B) CI gate
- `scan-diff` / `scan-repo` + SARIF  
- Fail on `security_verdict=REJECTED` or policy DENY  

### C) Enterprise HTTP
- `GUARDRAIL_ENTERPRISE=1`  
- `require_auth=true`  
- JWT/API keys, path roots, audit log path, rate limits  
- Bind `127.0.0.1` or private network; put reverse proxy + TLS in front  

---

## 6. Secure configuration checklist

- [ ] Do not commit real API keys / JWT secrets  
- [ ] Set `GUARDRAIL_ALLOWED_ROOTS` / tenant roots in enterprise mode  
- [ ] Enable `require_auth` for any non-local HTTP listener  
- [ ] Keep CORS empty unless you intentionally expose browser clients  
- [ ] Cap body size / workers for shared hosts  
- [ ] Review plugin directory contents (`GUARDRAIL_PLUGIN_PATH`) — plugins run as code  
- [ ] Treat LLM autofix (`GUARDRAIL_LLM_API_KEY`) as optional; it sends finding context to a third party  

---

## 7. Reporting vulnerabilities **in GuardRail**

See [SECURITY.md](../SECURITY.md). Prefer private disclosure for issues that could lead to RCE, auth bypass, or secret exposure in the server itself.

---

## 8. Compliance note

Enterprise **policy packs** and `compliance_report` produce **engineering evidence**, not a certification (SOC2/ISO). Use them as control support artifacts alongside your real audit program.
