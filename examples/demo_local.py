#!/usr/bin/env python3
"""Run sample audits without MCP wiring."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guardrail.cost import run_core_cost_audit
from guardrail.infra_security import deep_analyze_infra
from guardrail.safety import run_core_safety_audit


def main() -> None:
    sample = (ROOT / "examples" / "vulnerable_sample.py").read_text(encoding="utf-8")
    safety = run_core_safety_audit(sample, filename="vulnerable_sample.py")
    print("=== CODE SAFETY (regex + AST) ===")
    print(json.dumps(safety, indent=2))

    tf = (ROOT / "examples" / "infra_aws.tf").read_text(encoding="utf-8")
    cost = run_core_cost_audit(tf, "aws")
    print("\n=== CLOUD COST ===")
    print(json.dumps(cost, indent=2))

    bad = (ROOT / "examples" / "bad_infra.yaml").read_text(encoding="utf-8")
    infra = deep_analyze_infra(bad, "aws", budget_limit_usd=500)
    print("\n=== INFRA SECURITY + BUDGET ===")
    print(json.dumps(infra, indent=2))


if __name__ == "__main__":
    main()
