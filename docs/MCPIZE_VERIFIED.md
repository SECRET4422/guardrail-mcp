# Marketplace quality checklist

Listing: https://mcpize.com/mcp/guardrail

This is a **maintainer checklist**, not a guarantee of any third-party badge.

## Evidence already in this repository

| Item | Location |
|------|----------|
| Source code | GitHub `main` |
| License | `LICENSE` (MIT) |
| Automated tests | `docs/test-results.md` (reproduce with `unittest`) |
| Performance notes | `docs/PERFORMANCE.md`, `benchmarks/` |
| Threat model | `docs/SECURITY_MODEL.md` |
| Accuracy / claims | `docs/ACCURACY.md` |
| Usage examples | `docs/EXAMPLES.md` |
| Brand assets | `assets/`, `assets/web/` |
| Public website | https://secret4422.github.io/guardrail-mcp/ |
| Release tag | `v2.1.0` |

## Recommended listing fields (factual)

- **One-liner:** Multi-language static security analysis tools for MCP clients (agents + CI).  
- **Demo:** Website playground (browser demo) + CLI `hybrid_scan` on `examples/vulnerable_sample.py`.  
- **Requirements:** Python 3.10+ for self-host; no API key required for core local scans.  
- **Optional network:** OSV dependency queries; optional LLM fix drafts if an API key is configured.  

## Do not put on the listing

- Fabricated testimonials or review counts  
- “Certified SOC2/ISO” claims  
- Guaranteed detection rates without methodology  
- Real customer credentials or private code in screenshots  

## Optional human steps

1. Keep CI green on `main`.  
2. Respond to GitHub issues.  
3. If MCPize offers verification, submit links to the evidence table above.  
4. Record a short screencast using only public fixtures (`docs/SCREENCAST.md`).
