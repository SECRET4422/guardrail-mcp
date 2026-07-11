# Contributing to GuardRail MCP

## Setup

```bash
git clone https://github.com/<you>/guardrail-mcp.git
cd guardrail-mcp
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=$PWD
python -m unittest discover -s tests -v
```

## Guidelines

- Keep findings **redacted** — never echo raw secrets in tests or fixtures.
- Prefer high-signal rules over noisy ones (document FPs in PR notes).
- Add unit tests for new rule IDs and CLI paths.
- Do not commit live credentials, tokens, or production IaC.

## PR checklist

- [ ] `python -m unittest discover -s tests -v` passes
- [ ] New MCP tools registered in `tools_catalog.py`
- [ ] README updated if user-facing behavior changes
