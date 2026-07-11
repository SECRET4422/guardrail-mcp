"""
Tree-sitter based multi-language structural scanning.

Falls back gracefully if grammars are missing.
Captures syntactic sinks more accurately than pure regex.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models import Finding, Severity
from .redaction import redact_excerpt

# Optional imports
try:
    from tree_sitter import Language, Parser, Query, QueryCursor

    HAS_TS = True
except ImportError:
    HAS_TS = False
    Language = Parser = Query = QueryCursor = None  # type: ignore


@dataclass
class TSQueryRule:
    id: str
    name: str
    language: str
    query: str
    severity: Severity
    description: str
    remediation: str
    capture: str = "sink"


_LANG_LOADERS = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_javascript",  # approx with js grammar
    "go": "tree_sitter_go",
    "java": "tree_sitter_java",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "rust": "tree_sitter_rust",
}


def _load_language(lang: str):
    if not HAS_TS:
        return None
    mod_name = _LANG_LOADERS.get(lang)
    if not mod_name:
        return None
    try:
        mod = __import__(mod_name)
        return Language(mod.language())
    except Exception:
        return None


# Tree-sitter query patterns (S-expression)
TS_RULES: List[TSQueryRule] = [
    TSQueryRule(
        id="GR-TS-PY-001",
        name="Python eval/exec call (tree-sitter)",
        language="python",
        query=r"""
        (call
          function: (identifier) @fn
          (#match? @fn "^(eval|exec)$")) @sink
        """,
        severity=Severity.CRITICAL,
        description="eval/exec detected via tree-sitter CST.",
        remediation="Remove dynamic execution of untrusted strings.",
    ),
    TSQueryRule(
        id="GR-TS-PY-002",
        name="Python subprocess/os system call",
        language="python",
        query=r"""
        (call
          function: (attribute
            attribute: (identifier) @meth)
          (#match? @meth "^(system|popen|Popen|run|call|check_output)$")) @sink
        """,
        severity=Severity.HIGH,
        description="Process-spawning call via attribute (os/subprocess).",
        remediation="Use shell=False and argument vectors.",
    ),
    TSQueryRule(
        id="GR-TS-JS-001",
        name="JS eval call (tree-sitter)",
        language="javascript",
        query=r"""
        (call_expression
          function: (identifier) @fn
          (#eq? @fn "eval")) @sink
        """,
        severity=Severity.CRITICAL,
        description="eval() detected in JavaScript CST.",
        remediation="Use JSON.parse or safe parsers.",
    ),
    TSQueryRule(
        id="GR-TS-JS-002",
        name="JS new Function",
        language="javascript",
        query=r"""
        (new_expression
          constructor: (identifier) @fn
          (#eq? @fn "Function")) @sink
        """,
        severity=Severity.CRITICAL,
        description="new Function(...) dynamic code construction.",
        remediation="Avoid dynamic function construction from strings.",
    ),
    TSQueryRule(
        id="GR-TS-GO-001",
        name="Go exec.Command",
        language="go",
        query=r"""
        (call_expression
          function: (selector_expression
            field: (field_identifier) @meth)
          (#eq? @meth "Command")) @sink
        """,
        severity=Severity.HIGH,
        description="exec.Command detected via tree-sitter.",
        remediation="Avoid shell binaries; pass discrete args.",
    ),
    TSQueryRule(
        id="GR-TS-JAVA-001",
        name="Java Runtime.exec / ProcessBuilder",
        language="java",
        query=r"""
        (method_invocation
          name: (identifier) @meth
          (#match? @meth "^(exec|start)$")) @sink
        """,
        severity=Severity.HIGH,
        description="Process execution method invocation.",
        remediation="Validate arguments; avoid shell concatenation.",
    ),
    TSQueryRule(
        id="GR-TS-C-001",
        name="C dangerous call",
        language="c",
        query=r"""
        (call_expression
          function: (identifier) @fn
          (#match? @fn "^(system|gets|strcpy|sprintf|scanf)$")) @sink
        """,
        severity=Severity.HIGH,
        description="Dangerous C libc call.",
        remediation="Use bounded APIs; avoid system().",
    ),
    TSQueryRule(
        id="GR-TS-CPP-001",
        name="C++ dangerous call",
        language="cpp",
        query=r"""
        (call_expression
          function: (identifier) @fn
          (#match? @fn "^(system|gets|strcpy|sprintf)$")) @sink
        """,
        severity=Severity.HIGH,
        description="Dangerous C++/C call.",
        remediation="Prefer safe alternatives.",
    ),
    TSQueryRule(
        id="GR-TS-RS-001",
        name="Rust unsafe block",
        language="rust",
        query=r"""
        (unsafe_block) @sink
        """,
        severity=Severity.MEDIUM,
        description="unsafe block requires manual safety invariants.",
        remediation="Minimize unsafe and document invariants.",
    ),
]


_PARSER_CACHE: Dict[str, Any] = {}
_LANG_CACHE: Dict[str, Any] = {}


def available_languages() -> List[str]:
    out = []
    for lang in _LANG_LOADERS:
        if _load_language(lang) is not None:
            out.append(lang)
    return out


def _parser_for(lang: str):
    if lang in _PARSER_CACHE:
        return _PARSER_CACHE[lang]
    language = _load_language(lang)
    if language is None:
        return None
    parser = Parser(language)
    _PARSER_CACHE[lang] = parser
    _LANG_CACHE[lang] = language
    return parser


def _line_col(source: bytes, start_byte: int) -> Tuple[int, int]:
    pre = source[:start_byte]
    line = pre.count(b"\n") + 1
    last = pre.rfind(b"\n")
    col = start_byte + 1 if last < 0 else start_byte - last
    return line, col


def _line_text(source: str, line_no: int) -> str:
    lines = source.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def scan_with_treesitter(
    source: str,
    language: str,
    *,
    max_findings: int = 100,
) -> List[Finding]:
    if not HAS_TS or not source:
        return []
    lang = language.lower()
    if lang == "typescript":
        lang = "javascript"
    parser = _parser_for(lang)
    if parser is None:
        return []

    src_b = source.encode("utf-8", errors="replace")
    tree = parser.parse(src_b)
    language_obj = _LANG_CACHE[lang]
    findings: List[Finding] = []

    for rule in TS_RULES:
        if rule.language not in {lang, language.lower()}:
            if not (rule.language == "javascript" and language.lower() == "typescript"):
                if rule.language != lang:
                    continue
        try:
            query = Query(language_obj, rule.query)
        except Exception:
            continue
        try:
            # tree-sitter 0.22+ API
            cursor = QueryCursor(query)
            matches = cursor.matches(tree.root_node)
            # matches: list of (pattern_index, {capture: [nodes]})
            nodes = []
            for _pat, caps in matches:
                for cap_name, cap_nodes in caps.items():
                    if cap_name in (rule.capture, "sink", "fn", "meth") or True:
                        for n in cap_nodes:
                            if cap_name == rule.capture or cap_name == "sink":
                                nodes.append(n)
            if not nodes:
                # fallback: any capture
                for _pat, caps in matches:
                    for cap_nodes in caps.values():
                        nodes.extend(cap_nodes)
        except Exception:
            # older API
            try:
                captures = query.captures(tree.root_node)
                nodes = [n for n, name in captures if name in (rule.capture, "sink")]
                if not nodes:
                    nodes = [n for n, _ in captures]
            except Exception:
                continue

        seen_bytes = set()
        for node in nodes:
            if len(findings) >= max_findings:
                return findings
            key = (node.start_byte, node.end_byte, rule.id)
            if key in seen_bytes:
                continue
            seen_bytes.add(key)
            line, col = _line_col(src_b, node.start_byte)
            lt = _line_text(source, line)
            # highlight approx
            excerpt = redact_excerpt(lt, 0, min(len(lt), 80)) if lt else node.type
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
                    match_length=max(0, node.end_byte - node.start_byte),
                )
            )
    return findings


def treesitter_status() -> Dict[str, Any]:
    return {
        "available": HAS_TS,
        "languages": available_languages(),
        "rules": len(TS_RULES),
    }
