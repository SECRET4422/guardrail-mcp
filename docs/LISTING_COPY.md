# Copy-paste listing text (all directories)

## Short
GuardRail Security — hybrid multi-language security MCP for AI coding agents (secrets, taint, tree-sitter, SARIF/SBOM, policy gates).

## Medium
GuardRail is an enterprise-ready MCP server that scans code agents write before you merge it. It combines secret detection, Python AST + multi-hop taint tracking, tree-sitter structural analysis, multi-language sink rules, repo/PR scanning, dependency CVE checks (OSV), SARIF/SBOM export, Docker/Kubernetes misconfig heuristics, and optional policy packs with RBAC.

## Use cases
1. Scan AI-generated patches in Cursor / Claude before applying them  
2. CI/PR security gates with SARIF upload and ALLOW/DENY policy  
3. Full-repo audits including IaC and container configs  

## Install
GitHub: https://github.com/SECRET4422/guardrail-mcp  

```bash
git clone https://github.com/SECRET4422/guardrail-mcp.git
cd guardrail-mcp
pip install -r requirements.txt
export PYTHONPATH=$PWD
python -m guardrail --mode stdio
```

## Tags
security, sast, secrets, taint-analysis, tree-sitter, sarif, sbom, owasp, mcp, code-review, enterprise
