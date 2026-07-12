# Aiming for MCPize “Verified” / quality bar

MCPize listing: **https://mcpize.com/mcp/guardrail**

Platform quality bars vary over time. Treat this as a **practical checklist** to maximize trust score, reviews, and verification eligibility.

## Product quality (you largely have this)

- [x] Clear description & use cases on listing  
- [x] Working tools (`audit_code_safety`, `scan_git_diff`, deps, SARIF, SBOM, …)  
- [x] Public GitHub with LICENSE (MIT)  
- [x] Automated tests (**65** passing) + published results (`docs/test-results.md`)  
- [x] Performance numbers (`docs/PERFORMANCE.md`)  
- [x] Security / threat model (`docs/SECURITY_MODEL.md`)  
- [x] Examples (`docs/EXAMPLES.md`)  
- [x] Brand assets (logo, favicon, OG, MCPize banner)  
- [x] Marketing site with **working interactive demo**  
- [ ] Short demo **video** (record using `docs/DEMO_SCRIPT.md`)  
- [ ] Responsive maintainer support on issues  

## Security hygiene for marketplace hosting

- Prefer **no default network** for core scans  
- Document optional network (OSV, LLM fixes)  
- Redact secrets in tool output (implemented)  
- Auth for any multi-tenant HTTP mode (enterprise gateway)  
- Path sandbox for repo tools in enterprise mode  
- Do not ship real credentials in repo (demo fixtures only)

## Trust / social proof actions

1. Ask users to **★ star** https://github.com/SECRET4422/guardrail-mcp  
2. Ask MCPize users to leave a **review** on the listing  
3. Cross-list on Smithery / mcp.so for traffic (`docs/DISTRIBUTION.md`)  
4. Keep CI green on `main`  
5. Pin a release (`v2.1.0`) and changelog  

## Listing content tips (conversion)

- One-liner: *Hybrid security MCP that blocks unsafe AI code before merge.*  
- Pin video + playground/demo link  
- Pricing: Free self-host · Pro $29 · Team $99 · Enterprise $299 (adjust in dashboard)  
- Requirements: none for basic scan; optional LLM key for AI fix drafts  

## If a formal “Verified” badge exists on MCPize

Complete their in-dashboard verification flow (identity, security questionnaire, uptime). This repo is structured so evidence links are one click away:

| Evidence | Link |
|----------|------|
| Source | GitHub repo |
| Tests | `docs/test-results.md` |
| Perf | `docs/PERFORMANCE.md` |
| Threat model | `docs/SECURITY_MODEL.md` |
| Live site / demo | https://secret4422.github.io/guardrail-mcp/ |
| Release | https://github.com/SECRET4422/guardrail-mcp/releases/tag/v2.1.0 |
