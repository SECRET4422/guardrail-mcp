# List GuardRail on more platforms (beyond MCPize)

Your product is live on GitHub:

**https://github.com/SECRET4422/guardrail-mcp**

Use this as a distribution ladder: **money platforms** + **discovery directories**.

---

## Platform comparison

| Platform | Type | Monetize? | Best for | Link |
|----------|------|-----------|----------|------|
| **MCPize** | Host + bill + marketplace | **Yes (~80–85%)** | Paid subscriptions | [mcpize.com](https://mcpize.com/developers) |
| **Smithery** | Registry + install UX | No (discovery) | Cursor/Claude installs | [smithery.ai](https://smithery.ai) |
| **Glama** | Directory + gateway | Limited / evolving | Discovery + hosted gateway | [glama.ai](https://glama.ai) |
| **mcp.so** | Large directory | No | SEO / catalog traffic | [mcp.so](https://mcp.so) |
| **PulseMCP** | Directory + news | No | Visibility / newsletter | [pulsemcp.com](https://www.pulsemcp.com) |
| **Official MCP Registry** | Protocol registry | No | “Official” discovery | [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io) |
| **Awesome lists** | GitHub stars | No | Devs browsing lists | [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) |
| **npm / PyPI** | Package install | Indirect | `npx` / `pip` installs | — |
| **Your own site + Stripe** | Self-serve SaaS | **100%** (you operate) | Full control | Host HTTP mode yourself |

**Rule of thumb**

- **Earn:** MCPize (and/or your own hosted HTTP + Stripe).  
- **Get found:** Smithery, mcp.so, PulseMCP, Glama, awesome lists, Official Registry.  
- Cross-list everywhere; sell on one paid surface.

---

## 1) Smithery (high priority for installs)

1. Create account at [https://smithery.ai](https://smithery.ai)  
2. Connect GitHub repo `SECRET4422/guardrail-mcp`  
3. This repo includes `smithery.yaml`  
4. Publish via Smithery dashboard or CLI:

```bash
npm i -g @smithery/cli
smithery auth login
# follow smithery mcp publish / dashboard “Add server from GitHub”
```

5. Test one-click install into **Cursor** / Claude.

Smithery is mainly **distribution**, not payouts.

---

## 2) mcp.so

1. Open [https://mcp.so](https://mcp.so)  
2. Submit / claim server (GitHub URL)  
3. Use listing copy from below  

---

## 3) PulseMCP

1. [https://www.pulsemcp.com](https://www.pulsemcp.com)  
2. Submit server / request listing  
3. Optional: pitch for newsletter if you have a strong demo GIF  

---

## 4) Glama

1. [https://glama.ai/mcp](https://glama.ai/mcp) (or Glama MCP directory)  
2. Add server from GitHub  
3. Prefer **stdio** install instructions pointing at this repo  

---

## 5) Official MCP Registry

1. Read: [https://registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io)  
2. Publish with the official publisher tooling / `server.json` (see MCP docs)  
3. Namespace often: `io.github.SECRET4422/guardrail-mcp`  

Helps VS Code / ecosystem discovery.

---

## 6) Awesome MCP Servers (PR)

1. Fork [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers)  
2. Add under **Security** (or similar):

```markdown
- [GuardRail](https://github.com/SECRET4422/guardrail-mcp) - Hybrid multi-language security MCP (taint, tree-sitter, SARIF/SBOM, enterprise policy).
```

3. Open a PR  

---

## 7) Self-hosted paid product (max control)

Run GuardRail HTTP yourself and charge:

```bash
export GUARDRAIL_ENTERPRISE=1
export GUARDRAIL_REQUIRE_AUTH=1
export GUARDRAIL_HTTP_API_KEY=...
python -m guardrail serve --mode http --host 0.0.0.0 --port 8787
```

Front with:

- Stripe Checkout / Customer Portal  
- Cloudflare / Fly.io / Railway / Render  
- Custom domain  

You keep ~100% after Stripe fees; you own ops.

---

## Listing copy (reuse everywhere)

**Name:** GuardRail Security  

**One-liner:**  
Hybrid multi-language security MCP for AI coding agents — secrets, taint analysis, tree-sitter, SARIF/SBOM, policy gates.

**Use cases:**
1. Scan AI-generated code in Cursor/Claude before applying patches  
2. PR/CI security gates with SARIF + ALLOW/DENY  
3. Repo audits + Docker/K8s misconfigs + dependency CVEs  

**Install (local):**

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "python",
      "args": ["-m", "guardrail", "--mode", "stdio"],
      "cwd": "/path/to/guardrail-mcp",
      "env": { "PYTHONPATH": "/path/to/guardrail-mcp" }
    }
  }
}
```

**Repo:** https://github.com/SECRET4422/guardrail-mcp  
**License:** MIT  

---

## Suggested order this week

1. **MCPize** — paid listing (if not done)  
2. **Smithery** — installs  
3. **mcp.so + PulseMCP + Glama** — SEO  
4. **Awesome list PR**  
5. **Official registry**  
6. Optional: self-host Pro tier on your domain  

---

## What “done” means for multi-platform

| Goal | Action |
|------|--------|
| Make money | MCPize and/or self-host + Stripe |
| Get installs | Smithery + directories + awesome PR |
| Trust | GitHub stars, tests badge, clean README demos |
