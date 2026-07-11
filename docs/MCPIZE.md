# Publish GuardRail on MCPize (earn money)

GuardRail is already on GitHub. MCPize hosts it, bills subscribers, and pays you **~80–85%** revenue share via Stripe.

Official docs: [mcpize.com/developers](https://mcpize.com/developers) · [Monetize guide](https://mcpize.com/developers/monetize-mcp-servers)

## Prerequisites

1. GitHub repo: https://github.com/SECRET4422/guardrail-mcp  
2. Free MCPize developer account: https://mcpize.com/auth  
3. Node.js 18+ (for CLI)  
4. Stripe account (for payouts)

## One-time setup

```bash
cd guardrail-mcp
npm i -g mcpize   # or use npx every time

# Browser login (saves session)
npx mcpize login
npx mcpize whoami
```

## Deploy from this repo

```bash
# Already has mcpize.yaml — optional re-analyze:
npx mcpize analyze -y

# Deploy to MCPize cloud
npx mcpize deploy -y --notes "GuardRail v2.1.0"

# Check health
npx mcpize status
npx mcpize logs
```

### Or deploy from GitHub in the web UI

1. Open [mcpize.com developers portal](https://mcpize.com/developers)  
2. **Connect GitHub** → select `SECRET4422/guardrail-mcp`  
3. **Deploy** (auto-deploy on `main` optional)  
4. Open server → **Publish / Pricing**

## Set pricing (recommended for GuardRail)

Enterprise security tools on MCPize commonly list **$100–500/mo**. For first traction use freemium:

| Plan | Price | What to include |
|------|-------|-----------------|
| Free | $0 | `audit_code_safety` basic (rate-limited) |
| Pro | **$29/mo** | Full hybrid scan, repo/diff, SARIF/SBOM, fixes |
| Team | **$99/mo** | Higher limits, multi-seat, policy packs |
| Enterprise | **$299/mo** | RBAC, audit export, SSO-ready JWT, SLA |

CLI helpers:

```bash
# AI-assisted pricing + SEO + list (review before going live)
npx mcpize publish --pricing "Freemium security scanner for AI agents. Free: single-file scan. Pro $29/mo: full hybrid taint+treesitter, repo/PR scan, SARIF/SBOM. Team $99/mo. Enterprise $299/mo with policy packs and audit." --generate-seo --list

# Or free-only first to get installs, then raise price:
npx mcpize publish --free --list
```

Dashboard: set tiers, features, and Stripe Connect.

## Connect Stripe (get paid)

1. MCPize dashboard → **Connect Stripe**  
2. Complete Stripe Connect onboarding  
3. Payouts typically **1st of each month** (platform minimum may apply, often ~$100)

## Listing copy (paste into marketplace)

**Title:** GuardRail Security  

**One-liner:** Hybrid multi-language security MCP for AI coding agents — secrets, taint, tree-sitter, SARIF/SBOM, policy gates.

**Use cases:**
1. Scan AI-generated code in Cursor/Claude before merge  
2. PR security gates with SARIF + ALLOW/DENY policy  
3. Repo audits + Docker/K8s misconfigs + dependency CVEs  

**Requirements:** None for basic scans. Optional: `GUARDRAIL_LLM_API_KEY` for LLM fix drafts; enterprise env vars for multi-tenant mode.

**Permissions:** Reads code/paths you pass to tools. Does not exfiltrate secrets (redacts findings). Path sandbox available in enterprise mode.

## Realistic earnings expectations

- Listing alone ≠ revenue. You need installs + upgrades.  
- Promote: Twitter/LinkedIn, r/MachineLearning, HN “Show HN”, Cursor Discord, README badge.  
- Cross-list free on mcp.so / Smithery for discovery; sell paid on MCPize.  
- Enterprise security can support higher ARPU than toy MCPs if demos convert.

## After publish checklist

- [ ] `npx mcpize status` shows healthy  
- [ ] Install in Cursor/Claude and run `audit_code_safety` on a sample  
- [ ] Stripe connected  
- [ ] Pricing + screenshots/logo  
- [ ] README badge linking to MCPize listing  
- [ ] Optional: GitHub Action already in repo for CI demos  

## Support links

- Marketplace: https://mcpize.com/marketplace  
- CLI: `npx mcpize --help`  
- Docs: https://docs.mcpize.com/  
