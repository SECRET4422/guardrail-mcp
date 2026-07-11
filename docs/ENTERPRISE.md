# GuardRail Enterprise MCP

Enterprise control plane for multi-tenant, policy-gated agent security tooling.

## Capabilities

| Control | Detail |
|---------|--------|
| **Authentication** | Tenant API keys, admin keys, HS256 JWT |
| **RBAC** | `viewer` → `scanner` → `operator` → `admin` |
| **Policy packs** | `default`, `strict`, `soc2`, `pci` — fail-on-severity + max risk |
| **Path sandbox** | `global_allowed_roots` ∩ tenant roots |
| **Rate limits** | Per-subject token bucket (RPM) |
| **Quotas** | Monthly scan counters per tenant |
| **Audit log** | Structured JSONL (args redacted) + in-memory ring buffer |
| **Metrics** | Prometheus `/metrics` + JSON health |
| **Correlation IDs** | `X-Request-Id` / envelope `correlation_id` |
| **Compliance aid** | `compliance_report` control narratives (not a certification) |

## Quick start (enterprise)

```bash
export GUARDRAIL_ENTERPRISE=1
export GUARDRAIL_ENTERPRISE_CONFIG=$PWD/config/enterprise.json
export PYTHONPATH=$PWD

# HTTP
python -m guardrail serve --mode http --host 127.0.0.1 --port 8787

curl -s -H "Authorization: Bearer gr_demo_enterprise_key_change_me" \
  http://127.0.0.1:8787/v1/enterprise/health | jq .

curl -s -H "Authorization: Bearer gr_demo_enterprise_key_change_me" \
  -H "Content-Type: application/json" \
  -d '{"name":"audit_code_safety","arguments":{"source_code":"eval(x)"}}' \
  http://127.0.0.1:8787/v1/tools/call | jq .policy
```

## MCP tool arguments for auth

When `require_auth: true`, pass credentials in tool arguments:

```json
{
  "name": "scan_repository",
  "arguments": {
    "path": "/repos/app",
    "api_key": "gr_acme_prod_replace_me"
  }
}
```

Or HTTP header: `Authorization: Bearer <key-or-jwt>` / `X-Api-Key: <key>`.

## Roles

| Role | Can call |
|------|----------|
| viewer | health, policy status, SARIF, SBOM |
| scanner | all audit/scan tools + evaluate_policy |
| operator | + compliance_report, list_audit_events |
| admin | + issue_access_token, manage_tenant, reload config |

## Policy decisions

Scan tools attach:

```json
{
  "policy": {
    "decision": "DENY",
    "passed": false,
    "fail_on_severity": ["CRITICAL", "HIGH"],
    "max_risk_score": 40,
    "blocking_findings": [...],
    "reasons": ["..."],
    "compliance_controls": ["CC6.1", "CC7.1"]
  },
  "policy_decision": "DENY",
  "security_verdict": "REJECTED"
}
```

Use `policy_decision` as a **release gate** in CI/CD or agent workflows.

## Deployment

- Docker Compose: `deploy/docker-compose.yml`
- Kubernetes: `deploy/k8s/deployment.yaml` (non-root, read-only FS, NetworkPolicy, probes)
- Config example: `config/enterprise.example.yaml`

## Security defaults

- Secret redaction in findings + audit args
- No wide-open CORS by default
- Path sandbox when roots configured
- JWT HMAC verification with exp/iss/aud
- Rate limit + quota on expensive scan tools

## Not included (integrate upstream)

- SSO/OIDC broker (use JWT minted by your IdP with shared HS256 or put a gateway in front)
- Durable multi-region DB for quotas (in-memory/process today — plug Redis via limiter interface)
- Formal SOC2 Type II attestation — GuardRail produces **evidence**, not certificates
