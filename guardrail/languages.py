"""
Multi-language heuristic sink/secret patterns.

Python deep analysis stays in ast_engine.py.
Other languages use high-signal regex grids (no native parser required).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Finding, Severity, SEVERITY_WEIGHT
from .redaction import redact_excerpt


# Extension → language id
LANG_BY_EXT: Dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".scala": "scala",
    ".tf": "terraform",
    ".hcl": "terraform",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".Dockerfile": "dockerfile",
    ".dockerfile": "dockerfile",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
}


@dataclass(frozen=True)
class LangRule:
    id: str
    name: str
    languages: Tuple[str, ...]  # empty = all text languages
    pattern: str
    severity: Severity
    description: str
    remediation: str
    flags: int = re.MULTILINE


# Cross-language + language-specific sinks (secrets still primarily in rules.py)
LANG_RULES: List[LangRule] = [
    # --- JavaScript / TypeScript ---
    LangRule(
        id="GR-JS-001",
        name="JS eval / new Function",
        languages=("javascript", "typescript"),
        pattern=r"\b(?:eval|new\s+Function)\s*\(",
        severity=Severity.CRITICAL,
        description="Dynamic code execution via eval/Function in JS/TS.",
        remediation="Remove eval; use JSON.parse or explicit parsers.",
    ),
    LangRule(
        id="GR-JS-002",
        name="child_process shell execution",
        languages=("javascript", "typescript"),
        pattern=r"\b(?:exec|execSync|spawn)\s*\(\s*[`'\"].*\$\{",
        severity=Severity.CRITICAL,
        description="Shell command built with template interpolation — injection risk.",
        remediation="Use execFile/spawn with argument arrays; never interpolate untrusted input.",
    ),
    LangRule(
        id="GR-JS-003",
        name="child_process.exec usage",
        languages=("javascript", "typescript"),
        pattern=r"""require\s*\(\s*['"]child_process['"]\s*\)|\bchild_process\.(?:exec|execSync)\s*\(""",
        severity=Severity.HIGH,
        description="child_process.exec routes through a shell by default.",
        remediation="Prefer execFile/spawn with shell:false and fixed executables.",
    ),
    LangRule(
        id="GR-JS-004",
        name="innerHTML assignment",
        languages=("javascript", "typescript"),
        pattern=r"\.innerHTML\s*=",
        severity=Severity.HIGH,
        description="innerHTML assignment is a common XSS sink.",
        remediation="Use textContent or a sanitizer (DOMPurify) for untrusted HTML.",
    ),
    LangRule(
        id="GR-JS-005",
        name="document.write",
        languages=("javascript", "typescript"),
        pattern=r"\bdocument\.write\s*\(",
        severity=Severity.MEDIUM,
        description="document.write can enable XSS with untrusted input.",
        remediation="Use safe DOM APIs instead of document.write.",
    ),
    LangRule(
        id="GR-JS-006",
        name="TLS rejectUnauthorized disabled",
        languages=("javascript", "typescript"),
        pattern=r"rejectUnauthorized\s*:\s*false",
        severity=Severity.HIGH,
        description="TLS certificate validation disabled in Node.",
        remediation="Enable certificate verification; fix CA trust instead.",
    ),
    # --- Go ---
    LangRule(
        id="GR-GO-001",
        name="Go command with shell",
        languages=("go",),
        pattern=r"""exec\.Command\s*\(\s*["'](?:bash|sh|cmd|powershell)["']""",
        severity=Severity.HIGH,
        description="exec.Command invokes a shell binary — injection risk if args are tainted.",
        remediation="Invoke the target binary directly with discrete args; validate inputs.",
    ),
    LangRule(
        id="GR-GO-002",
        name="Go SQL string formatting",
        languages=("go",),
        pattern=r"""(?:Query|QueryRow|Exec)\s*\(\s*(?:fmt\.Sprintf|fmt\.Sprint)\s*\(""",
        severity=Severity.CRITICAL,
        description="SQL built via fmt.Sprintf into database/sql calls.",
        remediation="Use parameterized queries with placeholders ($1, ?).",
    ),
    LangRule(
        id="GR-GO-003",
        name="Go unsafe package",
        languages=("go",),
        pattern=r"""^\s*import\s+(?:\w+\s+)?["']unsafe["']|["']unsafe["']\s*\)""",
        severity=Severity.MEDIUM,
        description="Import of unsafe bypasses Go memory safety.",
        remediation="Limit unsafe to audited code paths; prefer safe APIs.",
        flags=re.MULTILINE,
    ),
    LangRule(
        id="GR-GO-004",
        name="Insecure TLS skip verify (Go)",
        languages=("go",),
        pattern=r"InsecureSkipVerify\s*:\s*true",
        severity=Severity.HIGH,
        description="tls.Config InsecureSkipVerify enabled.",
        remediation="Verify certificates properly; use custom RootCAs if needed.",
    ),
    # --- Java ---
    LangRule(
        id="GR-JAVA-001",
        name="Java Runtime.exec / ProcessBuilder",
        languages=("java", "kotlin"),
        pattern=r"\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(",
        severity=Severity.HIGH,
        description="Process execution sink — validate command arguments.",
        remediation="Avoid shell; use ProcessBuilder with discrete args and allow-lists.",
    ),
    LangRule(
        id="GR-JAVA-002",
        name="Java Statement string concat SQL",
        languages=("java", "kotlin"),
        pattern=r"\.(?:executeQuery|executeUpdate|execute)\s*\(\s*[^)]*\+",
        severity=Severity.CRITICAL,
        description="SQL executed with string concatenation — injection risk.",
        remediation="Use PreparedStatement with bind parameters.",
    ),
    LangRule(
        id="GR-JAVA-003",
        name="Java ObjectInputStream deserialization",
        languages=("java", "kotlin"),
        pattern=r"\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(",
        severity=Severity.HIGH,
        description="Java deserialization can lead to remote code execution.",
        remediation="Avoid native serialization for untrusted data; use JSON with allow-lists.",
    ),
    LangRule(
        id="GR-JAVA-004",
        name="Java ScriptEngine eval",
        languages=("java", "kotlin"),
        pattern=r"\bScriptEngine\b|\.eval\s*\(",
        severity=Severity.HIGH,
        description="ScriptEngine.eval enables dynamic code execution.",
        remediation="Do not eval untrusted scripts; sandbox or remove.",
    ),
    # --- Rust ---
    LangRule(
        id="GR-RS-001",
        name="Rust unsafe block",
        languages=("rust",),
        pattern=r"\bunsafe\s*\{",
        severity=Severity.MEDIUM,
        description="unsafe block requires manual memory/aliasing invariants.",
        remediation="Minimize unsafe; document safety invariants; prefer safe wrappers.",
    ),
    LangRule(
        id="GR-RS-002",
        name="Rust Command with shell",
        languages=("rust",),
        pattern=r"""Command::new\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*\)""",
        severity=Severity.HIGH,
        description="std::process::Command launches a shell.",
        remediation="Run the program directly; pass args via .arg/.args.",
    ),
    LangRule(
        id="GR-RS-003",
        name="Rust danger_accept_invalid_certs",
        languages=("rust",),
        pattern=r"danger_accept_invalid_certs\s*\(\s*true\s*\)",
        severity=Severity.HIGH,
        description="TLS certificate validation disabled (reqwest etc.).",
        remediation="Enable certificate validation in production.",
    ),
    # --- C / C++ ---
    LangRule(
        id="GR-C-001",
        name="Dangerous C string functions",
        languages=("c", "cpp"),
        pattern=r"\b(?:gets|strcpy|strcat|sprintf|vsprintf|scanf)\s*\(",
        severity=Severity.HIGH,
        description="Unbounded C string APIs are classic buffer-overflow vectors.",
        remediation="Use snprintf, strlcpy/strncpy_s, or C++ std::string with bounds checks.",
    ),
    LangRule(
        id="GR-C-002",
        name="system() call",
        languages=("c", "cpp"),
        pattern=r"\bsystem\s*\(",
        severity=Severity.CRITICAL,
        description="system() invokes a shell with the given command string.",
        remediation="Use execve/posix_spawn with argv arrays; never pass untrusted strings.",
    ),
    LangRule(
        id="GR-C-003",
        name="scanf without width",
        languages=("c", "cpp"),
        pattern=r"""\bscanf\s*\(\s*"[^"]*%s""",
        severity=Severity.HIGH,
        description="scanf %s without field width can overflow buffers.",
        remediation="Use width-limited formats or fgets.",
    ),
    # --- SQL ---
    LangRule(
        id="GR-SQL-001",
        name="Dynamic SQL EXECUTE IMMEDIATE",
        languages=("sql",),
        pattern=r"(?i)\bEXECUTE\s+IMMEDIATE\b",
        severity=Severity.MEDIUM,
        description="Dynamic SQL execution — ensure bind variables, not string concat.",
        remediation="Use parameterized dynamic SQL APIs.",
    ),
    # --- Shell ---
    LangRule(
        id="GR-SH-001",
        name="Unquoted variable expansion",
        languages=("shell",),
        pattern=r"(?m)^\s*(?:eval|curl|wget|rm)\s+[^#\n]*\$[A-Za-z_]{2,}",
        severity=Severity.HIGH,
        description="Command with unquoted expansions can enable word-splitting/injection.",
        remediation="Quote expansions, avoid eval, use arrays for args.",
    ),
    LangRule(
        id="GR-SH-002",
        name="curl | sh pattern",
        languages=("shell", "python", "javascript", "typescript", "markdown"),
        pattern=r"curl\s+[^\n|]*\|\s*(?:ba)?sh",
        severity=Severity.CRITICAL,
        description="Piping remote content directly to a shell is supply-chain risky.",
        remediation="Download, verify checksum/signature, then run a pinned script.",
    ),
]


def detect_language(path: Optional[str], content: str = "") -> str:
    if path:
        p = Path(path)
        name = p.name
        if name == "Dockerfile" or name.endswith(".Dockerfile"):
            return "dockerfile"
        ext = p.suffix.lower()
        if ext in LANG_BY_EXT:
            return LANG_BY_EXT[ext]
        # compound e.g. .d.ts
        if name.endswith(".d.ts"):
            return "typescript"
    # light content sniff
    head = (content or "")[:200]
    if "package main" in head and "func " in (content or "")[:2000]:
        return "go"
    if "def " in head or "import " in head:
        return "python"
    return "unknown"


def _line_col(text: str, index: int) -> Tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last = text.rfind("\n", 0, index)
    col = index + 1 if last < 0 else index - last
    return line, col


def _line_text(text: str, index: int) -> Tuple[str, int]:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end < 0:
        end = len(text)
    return text[start:end], start


_COMPILED: List[Tuple[LangRule, re.Pattern[str]]] = []
for _rule in LANG_RULES:
    try:
        _COMPILED.append((_rule, re.compile(_rule.pattern, _rule.flags)))
    except re.error:
        continue


def scan_language(
    source: str,
    language: str,
    *,
    filename: Optional[str] = None,
    max_findings: int = 100,
) -> List[Finding]:
    """Apply language-scoped rules; also apply universal shell-pipe rules for any lang."""
    if not source:
        return []
    findings: List[Finding] = []
    lang = (language or "unknown").lower()

    for rule, cre in _COMPILED:
        if rule.languages and lang not in rule.languages and "markdown" not in rule.languages:
            # allow unknown to still get critical universal rules with empty langs — none empty
            if lang == "unknown":
                if rule.id not in {"GR-SH-002"}:
                    continue
            else:
                continue
        for m in cre.finditer(source):
            if len(findings) >= max_findings:
                return findings
            gstart, gend = m.start(), m.end()
            line, col = _line_col(source, gstart)
            line_text, line_start = _line_text(source, gstart)
            rel_s, rel_e = gstart - line_start, gend - line_start
            excerpt = redact_excerpt(line_text, max(0, rel_s), min(len(line_text), rel_e))
            findings.append(
                Finding(
                    rule_id=rule.id,
                    vulnerability_name=rule.name,
                    severity=rule.severity.value,
                    description=rule.description,
                    remediation=rule.remediation,
                    line=line,
                    column=col,
                    excerpt_redacted=excerpt,
                    match_length=max(0, gend - gstart),
                )
            )
    return findings


def score_findings(findings: Sequence[Finding]) -> int:
    total = 0
    for f in findings:
        try:
            sev = Severity(f.severity)
        except ValueError:
            sev = Severity.MEDIUM
        total += SEVERITY_WEIGHT.get(sev, 10)
    return total
