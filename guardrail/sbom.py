"""
Lightweight SBOM generation from common lock/manifest files.

Produces CycloneDX 1.5 JSON and SPDX 2.3 JSON without external tools.
Not a full package-url resolver — versions come from lockfiles when present.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_requirements(text: str) -> List[Tuple[str, Optional[str]]]:
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # name==ver / name>=ver
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]=?)\s*([A-Za-z0-9_.+\-]+)", line)
        if m:
            pkgs.append((m.group(1), m.group(3) if "==" in m.group(2) or m.group(2) == "==" else m.group(3)))
            continue
        m2 = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if m2:
            pkgs.append((m2.group(1), None))
    return pkgs


def _parse_package_json(data: dict) -> List[Tuple[str, Optional[str], str]]:
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(section) or {}
        for name, ver in block.items():
            v = ver.lstrip("^~>=<") if isinstance(ver, str) else None
            out.append((name, v, "npm"))
    return out


def _parse_go_mod(text: str) -> List[Tuple[str, Optional[str]]]:
    pkgs = []
    for m in re.finditer(r"^\s*([A-Za-z0-9.\-_/]+)\s+v([0-9][^\s]+)", text, re.M):
        pkgs.append((m.group(1), m.group(2)))
    return pkgs


def _parse_cargo_toml_deps(text: str) -> List[Tuple[str, Optional[str]]]:
    pkgs = []
    in_deps = False
    for line in text.splitlines():
        if re.match(r"^\[dependencies\]", line):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
        if not in_deps:
            continue
        m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', line)
        if m:
            pkgs.append((m.group(1), m.group(2)))
            continue
        m2 = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', line)
        if m2:
            pkgs.append((m2.group(1), m2.group(2)))
    return pkgs


def collect_components(root: str | Path) -> List[Dict[str, Any]]:
    root = Path(root)
    components: List[Dict[str, Any]] = []
    seen = set()

    def add(name: str, version: Optional[str], purl_type: str, ecosystem: str) -> None:
        key = (name.lower(), version or "", purl_type)
        if key in seen:
            return
        seen.add(key)
        purl = f"pkg:{purl_type}/{name}"
        if version:
            purl += f"@{version}"
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version or "UNKNOWN",
                "purl": purl,
                "ecosystem": ecosystem,
            }
        )

    # Python
    for cand in ("requirements.txt", "requirements-dev.txt", "requirements/prod.txt"):
        p = root / cand
        if p.is_file():
            for name, ver in _parse_requirements(p.read_text(encoding="utf-8", errors="replace")):
                add(name, ver, "pypi", "PyPI")
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8", errors="replace")
        # naive dependencies = [ ... ] block
        m = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.S)
        if m:
            for item in re.findall(r'"([^"]+)"', m.group(1)):
                parsed = _parse_requirements(item)
                if parsed:
                    add(parsed[0][0], parsed[0][1], "pypi", "PyPI")

    # Node
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            for name, ver, _ in _parse_package_json(data):
                add(name, ver, "npm", "npm")
        except json.JSONDecodeError:
            pass

    # Go
    gomod = root / "go.mod"
    if gomod.is_file():
        for name, ver in _parse_go_mod(gomod.read_text(encoding="utf-8", errors="replace")):
            add(name, ver, "golang", "Go")

    # Rust
    cargo = root / "Cargo.toml"
    if cargo.is_file():
        for name, ver in _parse_cargo_toml_deps(cargo.read_text(encoding="utf-8", errors="replace")):
            add(name, ver, "cargo", "crates.io")

    return components


def generate_cyclonedx(root: str | Path, *, name: Optional[str] = None) -> Dict[str, Any]:
    root = Path(root)
    comps = collect_components(root)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": [{"name": "guardrail-mcp", "version": "1.2.0"}],
            "component": {
                "type": "application",
                "name": name or root.name,
                "version": "0.0.0",
            },
        },
        "components": [
            {
                "type": c["type"],
                "name": c["name"],
                "version": c["version"],
                "purl": c["purl"],
            }
            for c in comps
        ],
    }


def generate_spdx(root: str | Path, *, name: Optional[str] = None) -> Dict[str, Any]:
    root = Path(root)
    comps = collect_components(root)
    doc_name = f"SBOM-{name or root.name}"
    packages = [
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc_name,
            "documentNamespace": f"https://guardrail.local/spdx/{uuid.uuid4()}",
            "creationInfo": {
                "created": _now(),
                "creators": ["Tool: guardrail-mcp-1.2.0"],
            },
            "dataLicense": "CC0-1.0",
            "spdxVersion": "SPDX-2.3",
        }
    ]
    # SPDX JSON simplified package list
    pkg_entries = []
    relationships = []
    for i, c in enumerate(comps):
        spdxid = f"SPDXRef-Package-{i+1}"
        pkg_entries.append(
            {
                "SPDXID": spdxid,
                "name": c["name"],
                "versionInfo": c["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c["purl"],
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdxid,
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": packages[0]["documentNamespace"],
        "creationInfo": packages[0]["creationInfo"],
        "packages": pkg_entries,
        "relationships": relationships,
    }
