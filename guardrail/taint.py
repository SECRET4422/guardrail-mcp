"""
Advanced multi-hop taint tracking for Python (stdlib ast).

Improvements over basic ast_engine:
  - Multi-hop assignments (a = input(); b = a; sink(b))
  - Propagation through calls/returns within a module
  - Container element taint (list/dict append)
  - Parameter taint at function entry (conservative)
  - Sanitizer recognition (escape, quote, int())
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .models import Finding, Severity
from .redaction import redact_excerpt


SANITIZERS = {
    "html.escape",
    "escape",
    "quote",
    "urlencode",
    "int",
    "float",
    "bool",
    "len",
    "hash",
    "ast.literal_eval",
    "bleach.clean",
    "markupsafe.escape",
}

SOURCES = {
    "input",
    "raw_input",
    "sys.argv",
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.cookies",
    "request.headers",
    "request.get_json",
    "request.get",
    "os.environ",
    "os.getenv",
    "flask.request",
}


@dataclass
class TaintFinding:
    rule_id: str
    name: str
    severity: Severity
    line: int
    column: int
    sink: str
    source_hint: str
    taint_path: List[str]
    excerpt: str
    description: str
    remediation: str

    def to_finding(self) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            vulnerability_name=self.name,
            severity=self.severity.value,
            description=f"{self.description} Path: {' → '.join(self.taint_path)}",
            remediation=self.remediation,
            line=self.line,
            column=self.column,
            excerpt_redacted=self.excerpt,
            match_length=0,
        )


def _seg(source: str, node: ast.AST, limit: int = 140) -> str:
    try:
        s = ast.get_source_segment(source, node)
    except Exception:
        s = None
    if not s:
        lines = source.splitlines()
        ln = getattr(node, "lineno", 1) or 1
        s = lines[ln - 1] if 1 <= ln <= len(lines) else ""
    s = s.strip().replace("\n", " ")
    return s[: limit - 1] + "…" if len(s) > limit else s


def _qual_call(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        parts = []
        cur: ast.AST = f
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _name(node: ast.AST) -> Optional[str]:
    return node.id if isinstance(node, ast.Name) else None


class AdvancedTaintEngine(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.source = source
        self.tainted: Dict[str, List[str]] = {}  # var -> path
        self.findings: List[TaintFinding] = []
        # function defs: name -> (args, body analysis deferred)
        self.functions: Dict[str, ast.FunctionDef] = {}
        self.func_param_taint: Dict[str, Set[str]] = {}
        self.func_returns_taint: Dict[str, bool] = {}
        self.import_aliases: Dict[str, str] = {}

    def mark(self, name: str, path: List[str]) -> None:
        if name:
            prev = self.tainted.get(name, [])
            # keep shortest path
            if not prev or len(path) < len(prev):
                self.tainted[name] = path

    def is_tainted_expr(self, node: ast.AST) -> Tuple[bool, List[str]]:
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return True, list(self.tainted[node.id])
        if self._is_source(node):
            return True, [self._source_label(node)]
        if isinstance(node, ast.Call):
            q = _qual_call(node)
            if q in SANITIZERS or q.split(".")[-1] in SANITIZERS:
                return False, []
            # return-tainted callee
            base = q.split(".")[-1]
            if base in self.func_returns_taint and self.func_returns_taint[base]:
                # if any arg tainted or params assumed
                for a in node.args:
                    t, p = self.is_tainted_expr(a)
                    if t:
                        return True, p + [f"call:{base}"]
                if base in self.func_param_taint:
                    return True, [f"call:{base}"]
            for a in node.args:
                t, p = self.is_tainted_expr(a)
                if t:
                    return True, p + [f"arg→{q}"]
            for kw in node.keywords:
                if kw.value:
                    t, p = self.is_tainted_expr(kw.value)
                    if t:
                        return True, p + [f"kw→{q}"]
        if isinstance(node, ast.JoinedStr):
            path: List[str] = []
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t, p = self.is_tainted_expr(v.value)
                    if t:
                        path = p + ["f-string"]
            return (True, path) if path else (False, [])
        if isinstance(node, ast.BinOp):
            t1, p1 = self.is_tainted_expr(node.left)
            t2, p2 = self.is_tainted_expr(node.right)
            if t1 or t2:
                return True, (p1 or p2) + ["binop"]
        if isinstance(node, ast.Attribute):
            t, p = self.is_tainted_expr(node.value)
            if t:
                return True, p + [f".{node.attr}"]
            if self._is_source(node):
                return True, [self._source_label(node)]
        if isinstance(node, ast.Subscript):
            t, p = self.is_tainted_expr(node.value)
            if t:
                return True, p + ["[]"]
            if self._is_source(node):
                return True, [self._source_label(node)]
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                t, p = self.is_tainted_expr(elt)
                if t:
                    return True, p + ["container"]
        if isinstance(node, ast.Dict):
            for v in node.values:
                if v is None:
                    continue
                t, p = self.is_tainted_expr(v)
                if t:
                    return True, p + ["dict"]
        return False, []

    def _is_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            q = _qual_call(node)
            if q in SOURCES or q.split(".")[-1] in {"input", "getenv", "get_json", "get"}:
                if q.split(".")[-1] == "get" and not q.startswith("request") and "environ" not in q:
                    return False
                return True
        if isinstance(node, ast.Attribute):
            q = _qual_call(ast.Call(func=node, args=[], keywords=[])) if False else None
            # request.args etc
            parts = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            label = ".".join(reversed(parts))
            if label in SOURCES or label.startswith("request.") or label in {"sys.argv", "os.environ"}:
                return True
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
            return self._is_source(node.value)
        return False

    def _source_label(self, node: ast.AST) -> str:
        if isinstance(node, ast.Call):
            return f"source:{_qual_call(node)}"
        if isinstance(node, ast.Attribute):
            parts = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return "source:" + ".".join(reversed(parts))
        return "source:unknown"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions[node.name] = node
        # Assume parameters may be tainted (interprocedural conservative)
        for a in node.args.args:
            self.mark(a.arg, [f"param:{node.name}.{a.arg}"])
            self.func_param_taint.setdefault(node.name, set()).add(a.arg)
        self.generic_visit(node)
        # detect if any return is tainted
        for n in ast.walk(node):
            if isinstance(n, ast.Return) and n.value is not None:
                t, _ = self.is_tainted_expr(n.value)
                if t:
                    self.func_returns_taint[node.name] = True

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        t, path = self.is_tainted_expr(node.value)
        if t:
            for tgt in node.targets:
                self._assign_target(tgt, path)
        # alias: x = y when y tainted
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            t, path = self.is_tainted_expr(node.value)
            if t:
                self._assign_target(node.target, path)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        t, path = self.is_tainted_expr(node.value)
        if t or (isinstance(node.target, ast.Name) and node.target.id in self.tainted):
            base = list(self.tainted.get(getattr(node.target, "id", ""), []))
            self._assign_target(node.target, (path or base) + ["augassign"])
        self.generic_visit(node)

    def _assign_target(self, tgt: ast.AST, path: List[str]) -> None:
        if isinstance(tgt, ast.Name):
            self.mark(tgt.id, path + [f"var:{tgt.id}"])
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            for elt in tgt.elts:
                self._assign_target(elt, path)
        elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
            self.mark(f"{tgt.value.id}.{tgt.attr}", path)
        elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
            # container becomes tainted
            self.mark(tgt.value.id, path + ["store[]"])

    def visit_Call(self, node: ast.Call) -> None:
        q = _qual_call(node)
        sink_kind = self._sink_kind(q, node)
        if sink_kind:
            # check args
            for i, a in enumerate(node.args):
                t, path = self.is_tainted_expr(a)
                if t:
                    self._emit(node, sink_kind, q, path)
                    break
            else:
                for kw in node.keywords:
                    if kw.value:
                        t, path = self.is_tainted_expr(kw.value)
                        if t:
                            self._emit(node, sink_kind, q, path)
                            break
        # method append on list: xs.append(tainted)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "extend", "add"}:
            if isinstance(node.func.value, ast.Name) and node.args:
                t, path = self.is_tainted_expr(node.args[0])
                if t:
                    self.mark(node.func.value.id, path + [node.func.attr])
        self.generic_visit(node)

    def _sink_kind(self, q: str, node: ast.Call) -> Optional[str]:
        name = q.split(".")[-1]
        if name in {"eval", "exec", "compile"}:
            return "code_exec"
        if name in {"system", "popen"} or (
            name in {"run", "Popen", "call", "check_output", "check_call"}
            and any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
        ):
            return "command"
        if name in {"run", "Popen", "call", "check_output", "system"}:
            return "command"
        if name in {"execute", "executemany", "executescript"}:
            return "sql"
        if name in {"loads", "load"} and ("pickle" in q or q in {"loads", "load"}):
            return "deser"
        if name == "open":
            return "path"
        if name in {"urlopen", "get", "post", "request", "urlretrieve"}:
            return "ssrf"
        if name == "write" and "document" not in q:
            return "write"
        return None

    def _emit(self, node: ast.Call, kind: str, sink: str, path: List[str]) -> None:
        meta = {
            "code_exec": (
                "GR-TAINT-001",
                "Tainted Dynamic Code Execution",
                Severity.CRITICAL,
                "Untrusted data reaches eval/exec.",
                "Never eval untrusted input; use parsers/allow-lists.",
            ),
            "command": (
                "GR-TAINT-002",
                "Tainted Command Injection",
                Severity.CRITICAL,
                "Untrusted data reaches a process execution sink.",
                "Use argv lists, shell=False, and allow-listed binaries.",
            ),
            "sql": (
                "GR-TAINT-003",
                "Tainted SQL Sink",
                Severity.CRITICAL,
                "Untrusted data reaches a DB execute path.",
                "Use bound parameters / prepared statements.",
            ),
            "deser": (
                "GR-TAINT-004",
                "Tainted Deserialization",
                Severity.HIGH,
                "Untrusted data reaches pickle/load.",
                "Prefer JSON; never unpickle untrusted bytes.",
            ),
            "path": (
                "GR-TAINT-005",
                "Tainted Path Traversal",
                Severity.HIGH,
                "Untrusted data used as filesystem path.",
                "Resolve under a fixed root; reject .. segments.",
            ),
            "ssrf": (
                "GR-TAINT-006",
                "Tainted Outbound Request",
                Severity.HIGH,
                "Untrusted data reaches HTTP client URL.",
                "Allow-list hosts; block link-local/metadata IPs.",
            ),
            "write": (
                "GR-TAINT-007",
                "Tainted Write Sink",
                Severity.MEDIUM,
                "Untrusted data written to an external stream.",
                "Encode/escape for the output context.",
            ),
        }[kind]
        rid, name, sev, desc, rem = meta
        self.findings.append(
            TaintFinding(
                rule_id=rid,
                name=name,
                severity=sev,
                line=getattr(node, "lineno", 1) or 1,
                column=(getattr(node, "col_offset", 0) or 0) + 1,
                sink=sink,
                source_hint=path[0] if path else "unknown",
                taint_path=path + [f"sink:{sink}"],
                excerpt=_seg(self.source, node),
                description=desc,
                remediation=rem,
            )
        )


def analyze_taint(source: str) -> List[Finding]:
    if not source or not source.strip():
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    eng = AdvancedTaintEngine(source)
    eng.visit(tree)
    # second pass: re-walk calls now that func_returns_taint known
    eng.visit(tree)
    # dedupe by line+rule
    seen = set()
    out: List[Finding] = []
    for tf in eng.findings:
        k = (tf.rule_id, tf.line, tf.sink)
        if k in seen:
            continue
        seen.add(k)
        out.append(tf.to_finding())
    return out
