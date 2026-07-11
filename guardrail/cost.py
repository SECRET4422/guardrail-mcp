"""Infrastructure-as-code cloud cost estimation (catalog-based heuristics)."""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from .models import CostAuditResult, CostLineItem

# Illustrative on-demand monthly list prices (USD), single-region rough averages.
# Not a billing API — for developer intuition only.
CLOUD_PRICING_CATALOG: Dict[str, Dict[str, float]] = {
    "aws": {
        "t3.micro": 7.44,
        "t3.small": 14.88,
        "t3.medium": 29.76,
        "t3.large": 59.52,
        "m5.large": 69.84,
        "m5.xlarge": 139.68,
        "m5.2xlarge": 279.36,
        "r5.large": 100.80,
        "r5.xlarge": 201.60,
        "r5.4xlarge": 1113.12,
        "c5.xlarge": 122.40,
        "p3.2xlarge": 2203.20,
        "p4d.24xlarge": 23929.40,
        "db.t3.micro": 11.52,
        "db.m5.large": 128.48,
        "db.r5.xlarge": 288.00,
        "io2": 150.00,  # placeholder provisioned-IOPS class marker
    },
    "gcp": {
        "e2-micro": 6.11,
        "e2-small": 12.23,
        "e2-medium": 24.46,
        "e2-standard-2": 48.71,
        "e2-standard-4": 97.41,
        "n2-standard-4": 141.70,
        "n2-highmem-8": 425.61,
        "n2-highmem-16": 851.22,
        "a2-highgpu-1g": 2684.50,
        "c2-standard-8": 338.00,
    },
}

def _enclosing_block(text: str, index: int) -> str:
    """
    Best-effort extract of the nearest brace-delimited block containing index
    (Terraform / JSON / K8s-ish). Falls back to a tight local window.
    """
    # Walk left for unmatched '{'
    depth = 0
    start = None
    for i in range(index, -1, -1):
        ch = text[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                start = i
                break
            depth -= 1
    if start is None:
        return text[max(0, index - 120) : index + 120]

    depth = 0
    end = len(text)
    for j in range(start, len(text)):
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = j + 1
                break
    return text[start:end]


def _detect_quantities(block: str) -> int:
    """Best-effort instance count from knobs inside the same block; default 1."""
    # Prefer count / replicas / desired_capacity over max_size
    preferred = [
        re.compile(r"(?i)\bcount\s*=\s*(\d+)"),
        re.compile(r"(?i)\breplicas\s*:\s*(\d+)"),
        re.compile(r"(?i)\bdesired_capacity\s*=\s*(\d+)"),
    ]
    for cre in preferred:
        m = cre.search(block)
        if m:
            try:
                return max(1, min(int(m.group(1)), 100))
            except ValueError:
                continue
    return 1


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def run_core_cost_audit(infrastructure_content: str, cloud_provider: str = "aws") -> dict:
    """
    Scan IaC text for known instance / SKU tokens and sum catalog monthly estimates.
    """
    provider = (cloud_provider or "aws").strip().lower()
    if provider not in CLOUD_PRICING_CATALOG:
        return CostAuditResult(
            status="ERROR",
            cloud_provider=provider,
            notes=[f"Unsupported cloud_provider '{provider}'. Use 'aws' or 'gcp'."],
        ).to_dict()

    content = infrastructure_content or ""
    if len(content) > 512_000:
        content = content[:512_000]

    catalog = CLOUD_PRICING_CATALOG[provider]
    # Longest SKU first so "m5.xlarge" wins over ambiguous substrings
    skus = sorted(catalog.keys(), key=len, reverse=True)

    line_items: List[CostLineItem] = []
    seen_spans: List[Tuple[int, int]] = []
    unmatched_hints: List[str] = []

    # Hint at full instance-class tokens not in catalog (skip bare family prefixes)
    loose = re.findall(
        r"\b(?:"
        r"(?:t2|t3|t4g|m5|m6i|m7i|r5|r6i|c5|c6i|c7i|p3|p4d|p5)\.[a-z0-9]+"
        r"|db\.[a-z0-9.]+"
        r"|e2-[a-z0-9-]+|n2-[a-z0-9-]+|a2-[a-z0-9-]+|c2-[a-z0-9-]+"
        r")\b",
        content,
        flags=re.IGNORECASE,
    )
    catalog_lower = {s.lower() for s in skus}
    matched_lower = {i.resource.lower() for i in line_items}
    for tok in sorted(set(loose)):
        tl = tok.lower()
        if tl not in catalog_lower and tl not in matched_lower:
            unmatched_hints.append(tok)

    for sku in skus:
        # Word-ish boundary: avoid matching inside longer identifiers
        pattern = re.compile(rf"(?<![A-Za-z0-9-]){re.escape(sku)}(?![A-Za-z0-9-])", re.I)
        for m in pattern.finditer(content):
            span = (m.start(), m.end())
            # Skip overlaps with already-billed spans
            if any(not (span[1] <= a or span[0] >= b) for a, b in seen_spans):
                continue
            seen_spans.append(span)

            # Quantity from the same brace block when possible (avoids leaking count=N)
            block = _enclosing_block(content, m.start())
            qty = _detect_quantities(block)
            unit = catalog[sku]
            line_no = _line_number(content, m.start())
            # Excerpt without secrets concern for SKU names
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            if line_end < 0:
                line_end = min(len(content), m.end() + 80)
            excerpt = content[line_start:line_end].strip()
            if len(excerpt) > 120:
                excerpt = excerpt[:117] + "…"

            line_items.append(
                CostLineItem(
                    resource=sku,
                    provider=provider,
                    unit_monthly_usd=unit,
                    quantity=qty,
                    estimated_monthly_usd=round(unit * qty, 2),
                    evidence_line=line_no,
                    evidence_excerpt=excerpt,
                )
            )

    total = sum(i.estimated_monthly_usd for i in line_items)
    notes = [
        "Matches known SKU tokens in text — comments and strings also count.",
        "Quantity inferred from nearby count/replicas/desired_capacity when present (else 1).",
    ]
    if not line_items:
        notes.append("No catalog SKUs detected. Try including instance_type / machine_type values.")

    return CostAuditResult(
        status="OK",
        cloud_provider=provider,
        estimated_monthly_usd=total,
        line_items=line_items,
        unmatched_hints=unmatched_hints[:20],
        notes=notes,
    ).to_dict()
