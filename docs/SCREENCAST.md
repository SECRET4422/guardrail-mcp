# Screencast outline (optional)

Short recording outline for marketplace listings. Keep the tone factual.

## Goal (60–90 seconds)

Show one real scan of an intentional insecure fixture and the resulting verdict.

## Recommended flow

1. Open the repository README (show version and test badge).
2. Run:

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
print("status:", r.get("status"))
print("verdict:", r.get("security_verdict"))
print("issue_count:", r.get("issue_count"))
print("engines:", ", ".join(r.get("engines") or []))
for i in (r.get("issues") or [])[:5]:
    print(f"- {i.get('severity')}: {i.get('rule_id')} (line {i.get('line')})")
    print("  excerpt:", (i.get("excerpt_redacted") or "")[:100])
PY
```

3. Optionally open the website playground and run the **Python unsafe** sample  
   (browser demo — labeled as such on the page).
4. Show MCP config snippet from README.

## Rules for public recordings

- Only use files under `examples/` (synthetic fixtures).
- Never display real credentials, customer code, or private keys.
- State clearly if a UI demo is browser-side vs Python MCP/CLI.
- Prefer terminal output of `hybrid_scan` as the ground-truth demonstration.

## Publishing

Upload as unlisted YouTube/Loom and link from the MCPize listing if desired.  
This file is an outline only; it is not a marketing script with invented testimonials.
