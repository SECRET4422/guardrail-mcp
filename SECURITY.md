# Security Policy

## Reporting a vulnerability

If you find a security issue **in GuardRail itself** (e.g. path traversal when scanning, secret leakage in logs/SARIF, RCE via malicious file content):

1. **Do not** open a public GitHub issue with exploit details.
2. Email the maintainer privately or use GitHub Security Advisories on the repository.
3. Include: GuardRail version, reproduction steps, impact.

## Scope notes

GuardRail is a **static heuristic scanner**. Findings are leads, not proof of exploitability.
Intentionally vulnerable samples under `examples/` are for demos only.

## Secret handling

- Excerpts are redacted before return to agents.
- Prefer local STDIO MCP over posting source to remote HTTP.
- Rotate any real credential that was ever scanned.
