# MCPize (optional hosted listing)

Public listing: https://mcpize.com/mcp/guardrail

GuardRail’s **core remains MIT and self-hostable**. MCPize is an optional distribution/billing channel operated by a third party.

## Maintainer steps

1. Sign in at https://mcpize.com/auth  
2. Link GitHub repository `SECRET4422/guardrail-mcp`  
3. Deploy using `mcpize.yaml` or the MCPize dashboard  
4. Set pricing in the dashboard (suggested defaults are only suggestions; confirm live prices on the listing)  
5. Connect Stripe for payouts if selling paid plans  

CLI (requires your MCPize login):

```bash
npx mcpize login
npx mcpize deploy -y
npx mcpize status
```

## Assets for the listing

| Role | File |
|------|------|
| Icon | `assets/web/logo-icon.png` |
| Banner | `assets/web/mcpize-banner.jpg` |
| Website / demo | https://secret4422.github.io/guardrail-mcp/ |
| Docs | this repository `docs/` |

## Accuracy

Follow [ACCURACY.md](ACCURACY.md). Do not overstate browser demo results as Python engine output.

## Quality checklist

See [MCPIZE_VERIFIED.md](MCPIZE_VERIFIED.md).
