# Examples (reproducible)

All paths are relative to the repository root. Fixtures under `examples/` are **intentional insecure samples** for demos and tests.

## 1) Hybrid scan of the Python fixture

```bash
export PYTHONPATH=$PWD
python - <<'PY'
from pathlib import Path
from guardrail.hybrid_scan import hybrid_scan
import json
r = hybrid_scan(
    Path("examples/vulnerable_sample.py").read_text(encoding="utf-8"),
    filename="examples/vulnerable_sample.py",
)
print(json.dumps({
    "status": r.get("status"),
    "security_verdict": r.get("security_verdict"),
    "issue_count": r.get("issue_count"),
    "engines": r.get("engines"),
    "top_rules": [i.get("rule_id") for i in (r.get("issues") or [])[:8]],
}, indent=2))
PY
```

Expect `status=OK`, non-zero `issue_count` on the insecure fixture, and redacted excerpts where secret-shaped strings appear.

## 2) Clean code baseline

```bash
python - <<'PY'
from guardrail.hybrid_scan import hybrid_scan
r = hybrid_scan("def add(a,b):\n    return a+b\n", filename="clean.py")
assert r["status"] == "OK"
assert r["issue_count"] == 0
print("clean ok", r.get("engines"))
PY
```

## 3) MCP tool dispatch (in-process)

```bash
python - <<'PY'
from guardrail.tools_catalog import call_tool
r = call_tool("audit_code_safety", {
    "source_code": "eval(x)\n",
    "filename": "x.py",
})
print(r["status"], r.get("issue_count"), r.get("security_verdict"))
PY
```

## 4) Repository scan (examples tree)

```bash
python -m guardrail scan-repo examples --max-files 50 --json-out /tmp/gr-examples.json || true
python - <<'PY'
import json
d=json.load(open("/tmp/gr-examples.json"))
# scan-repo may wrap under "scan" when using full pipeline; plain scan-repo prints scan dict at top level
print({k:d.get(k) for k in ("status","files_scanned","issue_count","security_verdict") if k in d} or list(d)[:8])
PY
```

## 5) SARIF export

```bash
python - <<'PY'
from guardrail.tools_catalog import call_tool
from guardrail.sarif_export import write_sarif
r = call_tool("audit_code_safety", {"source_code": "password='EXAMPLE_NOT_A_REAL_PASSWORD_123!'\n", "filename": "t.py"})
path = write_sarif("/tmp/guardrail.sarif", call_tool("export_sarif", {"issues": r.get("issues") or []}))
print("wrote", path)
PY
```

## 6) Website playground (browser only)

1. `cd website && ./serve.sh`  
2. Open http://127.0.0.1:8080/#demo  
3. Select a sample → **Run scan**

This uses `website/js/demo-engine.js` (browser demonstration). See [ACCURACY.md](ACCURACY.md).

## 7) Enterprise policy evaluation (optional)

Requires enterprise config; demo keys in `config/enterprise.json` are for **local development only** — replace before any shared deployment.

```bash
export GUARDRAIL_ENTERPRISE=1
export GUARDRAIL_ENTERPRISE_CONFIG=$PWD/config/enterprise.json
python - <<'PY'
from guardrail.tools_catalog import call_tool_gated
r = call_tool_gated(
    "audit_code_safety",
    {"source_code": "eval(input())\n", "filename": "x.py"},
    api_key="gr_demo_enterprise_key_change_me",
    transport="http",
)
print(r.get("status"), r.get("security_verdict"), r.get("policy_decision"))
PY
```
