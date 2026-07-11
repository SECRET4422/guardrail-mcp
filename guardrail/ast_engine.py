"""
Semantic AST security engine with light taint tracking.

Complements regex rules in rules.py:
  - Regex: secrets, token prefixes, multi-language text
  - AST: Python control/data-flow sinks (eval, shell, SQL, pickle, yaml.load)

This is still heuristic — not a full interprocedural taint solver.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import Finding, Severity
from .redaction import redact_excerpt


# Imports that are *always* worth a finding when used unsafely later;
# bare import of popular libs is NOT a vulnerability by itself.
UNSAFE_IMPORT_NOTES: Dict[str, str] = {
    "pickle": "pickle can execute code on load — never deserialize untrusted data.",
    "marshal": "marshal is not a safe untrusted-data format.",
    "shelve": "shelve uses pickle underneath — same trust boundary as pickle.",
}

# Only flag these packages when paired with known-bad call patterns elsewhere,
# or when import alias suggests legacy patterns. We do NOT flag requests/urllib3
# merely for existing — that is noise, not a CVE scanner.


@dataclass
class ASTAnalysis:
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    tainted: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)

    def add(
        self,
        *,
        rule_id: str,
        name: str,
        severity: Severity,
        description: str,
        remediation: str,
        line: int,
        column: int,
        excerpt: str,
        weight: int,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                vulnerability_name=name,
                severity=severity.value,
                description=description,
                remediation=remediation,
                line=max(1, line or 1),
                column=max(1, column or 1),
                excerpt_redacted=excerpt,
                match_length=0,
            )
        )
        self.risk_score += weight


def _src_segment(source: str, node: ast.AST, limit: int = 140) -> str:
    try:
        seg = ast.get_source_segment(source, node)
    except Exception:  # noqa: BLE001
        seg = None
    if not seg:
        lineno = getattr(node, "lineno", 1) or 1
        lines = source.splitlines()
        if 1 <= lineno <= len(lines):
            seg = lines[lineno - 1]
        else:
            seg = ""
    seg = seg.strip().replace("\n", " ")
    if len(seg) > limit:
        return seg[: limit - 1] + "…"
    return seg


def _call_name(node: ast.Call) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (qualifier, name) e.g. ('subprocess', 'run'), (None, 'eval'),
    ('os', 'system'), ('yaml', 'load').
    """
    func = node.func
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return func.value.id, func.attr
        return None, func.attr
    return None, None


def _name_id(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _joinedstr_names(node: ast.JoinedStr) -> Set[str]:
    names: Set[str] = set()
    for v in node.values:
        if isinstance(v, ast.FormattedValue):
            n = _name_id(v.value)
            if n:
                names.add(n)
            # obj.attr — treat base as potential taint carrier
            if isinstance(v.value, ast.Attribute) and isinstance(v.value.value, ast.Name):
                names.add(v.value.value.id)
    return names


def _binop_str_names(node: ast.AST) -> Set[str]:
    """Collect Name ids involved in string-ish BinOp chains."""
    names: Set[str] = set()

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, ast.BinOp):
            walk(n.left)
            walk(n.right)
        elif isinstance(n, ast.Call):
            # "x".format(y) / "%s" % y handled elsewhere
            for a in n.args:
                walk(a)
        elif isinstance(n, ast.JoinedStr):
            names |= _joinedstr_names(n)

    walk(node)
    return names


# Sources that mark a variable as tainted (untrusted)
_TAINT_SOURCE_FUNCS = {
    "input",
    "raw_input",
    "getline",
}
_TAINT_SOURCE_ATTRS = {
    # Flask / Django-ish
    ("request", "args"),
    ("request", "form"),
    ("request", "values"),
    ("request", "json"),
    ("request", "data"),
    ("request", "cookies"),
    ("request", "headers"),
    ("request", "get_json"),
    ("request", "get"),
    # FastAPI / Starlette style often uses function params — harder; skip
    ("sys", "argv"),
    ("os", "environ"),  # env can be attacker-controlled in some threat models
}


def _expr_is_taint_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        q, name = _call_name(node)
        if name in _TAINT_SOURCE_FUNCS and q is None:
            return True
        if q and name and (q, name) in _TAINT_SOURCE_ATTRS:
            return True
        # request.form.get(...)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Attribute):
                base = node.func.value
                if isinstance(base.value, ast.Name) and base.value.id == "request":
                    if base.attr in {"args", "form", "values", "cookies", "headers", "json"}:
                        return True
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "request":
                if node.func.attr in {"get", "get_json", "json"}:
                    return True
    if isinstance(node, ast.Subscript):
        # request.args["x"]
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            if node.value.value.id == "request" and node.value.attr in {
                "args",
                "form",
                "values",
                "cookies",
                "headers",
            }:
                return True
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and (node.value.id, node.attr) in _TAINT_SOURCE_ATTRS:
            return True
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            if node.value.value.id == "request":
                return True
    if isinstance(node, ast.Name) and node.id in {"sys"}:
        return False
    # sys.argv
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id == "sys" and node.attr == "argv":
            return True
    return False


def _expr_taint_ids(node: ast.AST, tainted: Set[str]) -> bool:
    """True if expression is tainted or references a tainted name."""
    if _expr_is_taint_source(node):
        return True
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if isinstance(node, ast.JoinedStr):
        return bool(_joinedstr_names(node) & tainted) or any(
            _expr_taint_ids(v.value, tainted)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp):
        return _expr_taint_ids(node.left, tainted) or _expr_taint_ids(node.right, tainted)
    if isinstance(node, ast.Call):
        # str.format / % already BinOp; also .format on constant
        if any(_expr_taint_ids(a, tainted) for a in node.args):
            return True
        if any(_expr_taint_ids(kw.value, tainted) for kw in node.keywords if kw.value):
            return True
    if isinstance(node, ast.Attribute):
        return _expr_taint_ids(node.value, tainted)
    if isinstance(node, ast.Subscript):
        return _expr_taint_ids(node.value, tainted) or _expr_taint_ids(node.slice, tainted)
    return False


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.source = source
        self.result = ASTAnalysis()
        self.tainted: Set[str] = set()
        # alias map: local_name -> module root (import pickle as p)
        self.import_aliases: Dict[str, str] = {}
        # names bound to dangerous callables: cmd = eval
        self.alias_to_sink: Dict[str, str] = {}

    # --- imports ---
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            local = alias.asname or alias.name
            self.import_aliases[local] = root
            if root in UNSAFE_IMPORT_NOTES:
                self.result.add(
                    rule_id="GR-AST-010",
                    name="High-Risk Module Import",
                    severity=Severity.MEDIUM,
                    description=UNSAFE_IMPORT_NOTES[root],
                    remediation="Avoid deserializing untrusted data with this module; prefer JSON.",
                    line=node.lineno,
                    column=node.col_offset + 1,
                    excerpt=_src_segment(self.source, node),
                    weight=10,
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = (node.module or "").split(".")[0]
        for alias in node.names:
            local = alias.asname or alias.name
            if mod:
                self.import_aliases[local] = mod
            # from pickle import loads
            if mod in UNSAFE_IMPORT_NOTES or alias.name in {"loads", "load", "Unpickler"}:
                if mod in {"pickle", "marshal", "shelve"} or (
                    mod == "" and alias.name in {"loads"}
                ):
                    self.result.add(
                        rule_id="GR-AST-010",
                        name="High-Risk Deserialization Import",
                        severity=Severity.MEDIUM,
                        description=UNSAFE_IMPORT_NOTES.get(
                            mod, "Potentially unsafe deserialization symbol imported."
                        ),
                        remediation="Do not unpickle untrusted inputs.",
                        line=node.lineno,
                        column=node.col_offset + 1,
                        excerpt=_src_segment(self.source, node),
                        weight=10,
                    )
            # track eval/exec imports from builtins
            if alias.name in {"eval", "exec"}:
                self.alias_to_sink[local] = alias.name
        self.generic_visit(node)

    # --- assignments / taint ---
    def visit_Assign(self, node: ast.Assign) -> None:
        # cmd = eval
        if isinstance(node.value, ast.Name) and node.value.id in {"eval", "exec"}:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.alias_to_sink[t.id] = node.value.id

        if _expr_is_taint_source(node.value) or _expr_taint_ids(node.value, self.tainted):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.tainted.add(t.id)
                elif isinstance(t, ast.Tuple):
                    for elt in t.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted.add(elt.id)

        # f-string / concat assignment carrying taint
        if isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
            if _expr_taint_ids(node.value, self.tainted):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.tainted.add(t.id)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            if _expr_is_taint_source(node.value) or _expr_taint_ids(node.value, self.tainted):
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            if _expr_taint_ids(node.value, self.tainted) or node.target.id in self.tainted:
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    # --- calls / sinks ---
    def visit_Call(self, node: ast.Call) -> None:
        qual, name = _call_name(node)
        resolved_mod = self.import_aliases.get(qual or "", qual)

        # Alias sink: cmd = eval; cmd(x)
        if isinstance(node.func, ast.Name) and node.func.id in self.alias_to_sink:
            sink = self.alias_to_sink[node.func.id]
            self.result.add(
                rule_id="GR-AST-003",
                name="Aliased Dynamic Code Execution",
                severity=Severity.CRITICAL,
                description=(
                    f"Callable alias '{node.func.id}' resolves to '{sink}' — "
                    "obfuscated dynamic execution."
                ),
                remediation="Remove eval/exec aliases; use explicit safe parsers.",
                line=node.lineno,
                column=node.col_offset + 1,
                excerpt=_src_segment(self.source, node),
                weight=50,
            )

        # eval / exec
        if name in {"eval", "exec"} and (qual is None or qual in {"builtins"}):
            self.result.add(
                rule_id="GR-AST-003",
                name="Dynamic Code Execution (AST)",
                severity=Severity.CRITICAL,
                description=f"Direct invocation of {name}() enables arbitrary code execution.",
                remediation="Eliminate eval/exec; use ast.literal_eval for literals only.",
                line=node.lineno,
                column=node.col_offset + 1,
                excerpt=_src_segment(self.source, node),
                weight=50,
            )

        # compile(..., 'exec') often precedes exec
        if name == "compile":
            for a in node.args[1:2]:
                if isinstance(a, ast.Constant) and a.value in {"exec", "eval", "single"}:
                    self.result.add(
                        rule_id="GR-AST-003b",
                        name="compile() for Dynamic Execution",
                        severity=Severity.HIGH,
                        description="compile() with exec/eval mode often feeds runtime execution.",
                        remediation="Avoid dynamic compilation of untrusted strings.",
                        line=node.lineno,
                        column=node.col_offset + 1,
                        excerpt=_src_segment(self.source, node),
                        weight=25,
                    )

        # os.system / os.popen
        if (qual in {"os", None} and name in {"system", "popen"}) or (
            resolved_mod == "os" and name in {"system", "popen"}
        ):
            # Avoid flagging random .system on other objects if qual is None and not os —
            # if qual is None and name == system, still flag (common style from import)
            if qual in {"os", None} or resolved_mod == "os":
                self.result.add(
                    rule_id="GR-AST-005",
                    name="Shell via os.system/os.popen (AST)",
                    severity=Severity.HIGH,
                    description=f"{qual + '.' if qual else ''}{name}() routes through a shell-like interface.",
                    remediation="Use subprocess.run([...], shell=False) with an argument list.",
                    line=node.lineno,
                    column=node.col_offset + 1,
                    excerpt=_src_segment(self.source, node),
                    weight=45,
                )

        # subprocess.* shell=True
        if name in {"run", "Popen", "call", "check_output", "check_call"} and _is_shell_true(node):
            self.result.add(
                rule_id="GR-AST-005",
                name="subprocess shell=True (AST)",
                severity=Severity.HIGH,
                description="subprocess invoked with shell=True — injection risk if input is untrusted.",
                remediation="Pass a list of args with shell=False; never interpolate untrusted strings.",
                line=node.lineno,
                column=node.col_offset + 1,
                excerpt=_src_segment(self.source, node),
                weight=45,
            )
        # subprocess with tainted string command even without shell=True on list — still warn if single string + taint
        if name in {"run", "Popen", "call", "check_output", "check_call"} and node.args:
            arg0 = node.args[0]
            if _expr_taint_ids(arg0, self.tainted) and (
                isinstance(arg0, (ast.Name, ast.JoinedStr, ast.BinOp)) or _is_shell_true(node)
            ):
                self.result.add(
                    rule_id="GR-AST-005t",
                    name="Tainted Data to subprocess",
                    severity=Severity.CRITICAL,
                    description="Untrusted data flows into a process-spawning call.",
                    remediation="Validate against an allow-list; use shell=False + fixed executable.",
                    line=node.lineno,
                    column=node.col_offset + 1,
                    excerpt=_src_segment(self.source, node),
                    weight=55,
                )

        # SQL execute / executemany with interpolation or taint
        if name in {"execute", "executemany", "executescript"}:
            if node.args:
                arg0 = node.args[0]
                tainted_sql = _expr_taint_ids(arg0, self.tainted)
                interpolated = isinstance(arg0, (ast.JoinedStr, ast.BinOp))
                format_call = (
                    isinstance(arg0, ast.Call)
                    and isinstance(arg0.func, ast.Attribute)
                    and arg0.func.attr == "format"
                )
                percent = isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Mod)
                if tainted_sql:
                    self.result.add(
                        rule_id="GR-AST-004",
                        name="Tainted SQL Sink (AST)",
                        severity=Severity.CRITICAL,
                        description=(
                            "Untrusted input flows into a DB execute() argument without "
                            "bound parameters."
                        ),
                        remediation="Use parameterized queries (?/%s placeholders + args tuple).",
                        line=node.lineno,
                        column=node.col_offset + 1,
                        excerpt=_src_segment(self.source, node),
                        weight=55,
                    )
                elif interpolated or format_call or percent:
                    self.result.add(
                        rule_id="GR-AST-004b",
                        name="Interpolated SQL in execute() (AST)",
                        severity=Severity.HIGH,
                        description="SQL/query string is built via f-string/format/concat inside execute().",
                        remediation="Use bound parameters instead of string building.",
                        line=node.lineno,
                        column=node.col_offset + 1,
                        excerpt=_src_segment(self.source, node),
                        weight=35,
                    )

        # pickle.loads / yaml.load
        if name in {"loads", "load", "Unpickler"} and (
            qual in {"pickle", "marshal", "_pickle"} or resolved_mod in {"pickle", "marshal"}
        ):
            self.result.add(
                rule_id="GR-AST-009",
                name="Pickle/Marshal Deserialization (AST)",
                severity=Severity.HIGH,
                description="Deserialization may execute arbitrary code on malicious payloads.",
                remediation="Prefer JSON; if pickle is required, only load trusted, signed data.",
                line=node.lineno,
                column=node.col_offset + 1,
                excerpt=_src_segment(self.source, node),
                weight=35,
            )

        if name == "load" and (qual == "yaml" or resolved_mod == "yaml"):
            # safe if Loader=SafeLoader / safe_load name
            has_safe = False
            for kw in node.keywords:
                if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
                    if kw.value.attr in {"SafeLoader", "CSafeLoader"}:
                        has_safe = True
            if not has_safe:
                self.result.add(
                    rule_id="GR-AST-006",
                    name="yaml.load without SafeLoader (AST)",
                    severity=Severity.HIGH,
                    description="yaml.load without SafeLoader can execute constructors from untrusted YAML.",
                    remediation="Use yaml.safe_load() or Loader=yaml.SafeLoader.",
                    line=node.lineno,
                    column=node.col_offset + 1,
                    excerpt=_src_segment(self.source, node),
                    weight=35,
                )

        # assert False patterns — skip
        # open(tainted) — optional info
        if name == "open" and node.args and _expr_taint_ids(node.args[0], self.tainted):
            self.result.add(
                rule_id="GR-AST-011",
                name="Tainted Path to open()",
                severity=Severity.MEDIUM,
                description="Untrusted data used as filesystem path — path traversal risk.",
                remediation="Resolve paths under a fixed root; reject .. and absolute user paths.",
                line=node.lineno,
                column=node.col_offset + 1,
                excerpt=_src_segment(self.source, node),
                weight=15,
            )

        self.generic_visit(node)


def analyze_python_ast(source: str) -> ASTAnalysis:
    """Parse source and run the security visitor. Non-Python → empty with note."""
    if not source or not source.strip():
        return ASTAnalysis()

    try:
        tree = ast.parse(source)
    except SyntaxError as err:
        res = ASTAnalysis()
        res.notes.append(
            f"AST parse skipped (SyntaxError at line {err.lineno}): not valid Python — regex rules still apply."
        )
        # Low-weight finding only if it looks like Python
        if re.search(r"\b(def|class|import)\b", source):
            res.add(
                rule_id="GR-AST-000",
                name="Unparseable Python Syntax",
                severity=Severity.LOW,
                description="File looks like Python but failed to parse; AST sinks not fully checked.",
                remediation="Fix syntax errors to enable semantic analysis.",
                line=err.lineno or 1,
                column=(err.offset or 1),
                excerpt=(err.text or "").strip()[:140],
                weight=2,
            )
        return res
    except ValueError as err:
        # null bytes etc.
        res = ASTAnalysis()
        res.notes.append(f"AST parse skipped: {err}")
        return res

    visitor = SecurityASTVisitor(source)
    visitor.visit(tree)
    visitor.result.tainted = set(visitor.tainted)
    visitor.result.notes.append(
        f"AST taint set size={len(visitor.tainted)} (heuristic sources: input/request/argv/env flows)."
    )
    return visitor.result
