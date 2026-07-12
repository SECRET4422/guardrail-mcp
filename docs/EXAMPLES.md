# Real-world examples

Practical recipes for GuardRail in agent + CI workflows.

## 1) Block an unsafe AI patch in Cursor / Claude

**Scenario:** The agent proposes a Python helper that uses `eval` and concatenates SQL.

```python
def search(db, name):
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'")
```

**Agent tool call**
```json
{
  "name": "audit_code_safety",
  "arguments": {
    "source_code": "def search(db, name):\n    return db.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
    "filename": "search.py",
    "language": "python"
  }
}
```

**Expected**
- Findings: SQL interpolation / taint-related rules  
- `security_verdict`: `REJECTED` (score threshold)  
- Excerpts redacted where secrets would appear  

**Human action:** reject the patch or ask the agent to use bound parameters.

---

## 2) PR-only scan in CI

```bash
export PYTHONPATH=$PWD
python -m guardrail scan-diff . \
  --base origin/main \
  --head HEAD \
  --sarif guardrail.sarif \
  --json-out guardrail-report.json \
  --fixes
```

Upload `guardrail.sarif` with GitHub code scanning (see `.github/workflows/`).

---

## 3) Full repo audit before release

```bash
python -m guardrail scan-repo . \
  --workers 8 \
  --sarif out.sarif \
  --deps \
  --fixes \
  --json-out release-security.json
```

Exit code **2** when verdict is `REJECTED` (useful as a hard gate).

---

## 4) Dependency CVE inventory (network)

```bash
python -m guardrail scan-deps . --osv
```

Requires outbound access to `api.osv.dev`. Unpinned packages are listed but not fully version-queried.

---

## 5) Docker / Kubernetes misconfigs

```bash
python - <<'PY'
from guardrail.docker_k8s import analyze_container_config
from pathlib import Path
print(analyze_container_config(Path('examples/multilang/Dockerfile').read_text(), filename='Dockerfile'))
PY
```

Looks for `USER root`, `curl | bash`, `privileged: true`, open CIDRs, etc.

---

## 6) Enterprise policy DENY

With `config/enterprise.json` and tenant key:

```bash
export GUARDRAIL_ENTERPRISE=1
export GUARDRAIL_ENTERPRISE_CONFIG=$PWD/config/enterprise.json
python - <<'PY'
from guardrail.tools_catalog import call_tool_gated
r = call_tool_gated(
  'audit_code_safety',
  {'source_code': 'eval(input())\n', 'filename': 'x.py'},
  api_key='gr_demo_enterprise_key_change_me',
  transport='http',
)
print(r['security_verdict'], r.get('policy_decision'), r.get('policy',{}).get('reasons'))
PY
```

---

## 7) MCP client config

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "python",
      "args": ["-m", "guardrail", "--mode", "stdio"],
      "cwd": "/absolute/path/to/guardrail-mcp",
      "env": { "PYTHONPATH": "/absolute/path/to/guardrail-mcp" }
    }
  }
}
```

---

## 8) Website interactive demo

Open the marketing site and use **Run live demo** in the Demo section:

- Local: `cd website && ./serve.sh` → http://127.0.0.1:8080  
- Live: https://secret4422.github.io/guardrail-mcp/#demo  

The browser demo runs a **client-side hybrid simulation** of findings (no server required). For ground truth, run the CLI/MCP tools above.
