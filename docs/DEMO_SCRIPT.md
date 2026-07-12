# 1–2 minute demo script (record this)

Use this script to record a short Loom / OBS video for MCPize, GitHub, and social.

## Goal

Show GuardRail **blocking unsafe agent-style code** in under 2 minutes.

## Setup (before recording)

```bash
cd guardrail-mcp
pip install -r requirements.txt
export PYTHONPATH=$PWD
# terminal A – optional website
cd website && ./serve.sh 8080
# terminal B – ready for CLI
```

Browser tabs:
1. https://secret4422.github.io/guardrail-mcp/#demo  
2. https://github.com/SECRET4422/guardrail-mcp  
3. Optional: https://mcpize.com/mcp/guardrail  

## Script (≈90–120 seconds)

| Time | Say | Show |
|------|-----|------|
| 0:00–0:10 | “AI agents write code fast — and can ship secrets and injection.” | GitHub README / logo |
| 0:10–0:35 | “GuardRail is a security MCP: hybrid regex, AST, multi-hop taint, tree-sitter.” | Website hero |
| 0:35–1:05 | “Here’s the live demo. Dirty Python with password, SQL f-string, eval.” | Click **Run scan** on site demo, show REJECTED cards |
| 1:05–1:30 | “Same engines in CLI — verdict REJECTED, secrets redacted.” | Run CLI below |
| 1:30–1:50 | “Wire it into Cursor as an MCP tool, or gate PRs with SARIF.” | Show mcp.json snippet |
| 1:50–2:00 | “Open source on GitHub — star it, try Pro on MCPize.” | Star button + MCPize |

### CLI one-liner for the recording

```bash
python - <<'PY'
from guardrail.hybrid_scan import hybrid_scan
from pathlib import Path
import json
r = hybrid_scan(Path('examples/vulnerable_sample.py').read_text(), filename='vulnerable_sample.py')
print('verdict', r['security_verdict'], 'score', r['risk_score'], 'issues', r['issue_count'])
print('top', [i['rule_id']+':'+i['severity'] for i in r['issues'][:6]])
print('sample excerpt', r['issues'][0]['excerpt_redacted'][:80])
PY
```

## Upload targets

- YouTube / Loom unlisted link in MCPize listing + README  
- GitHub social preview already uses `assets/web/og-social.jpg`  
- 15s cut for Twitter/LinkedIn  

## Checklist before publishing video

- [ ] No real secrets on screen  
- [ ] Show **REJECTED** clearly  
- [ ] Mention MIT self-host + MCPize paid hosting  
- [ ] End with **star the repo** CTA  
