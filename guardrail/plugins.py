"""
Plugin architecture for GuardRail.

Discovery:
  1. Entry points group: guardrail.plugins (if installed)
  2. Directories in GUARDRAIL_PLUGIN_PATH (os.pathsep-separated)
  3. ./plugins under cwd

A plugin module may export:
  PLUGIN_NAME: str
  PLUGIN_VERSION: str
  register(registry: PluginRegistry) -> None

Or provide:
  RULES: list[dict]  (custom rules)
  hooks: dict with optional callables
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol

from .rule_engine import CustomRule, load_rules_from_mapping

logger = logging.getLogger("GuardRailMCP.plugins")


class ScanHook(Protocol):
    def __call__(self, source: str, language: str, context: Dict[str, Any]) -> List[Any]:
        ...


@dataclass
class PluginInfo:
    name: str
    version: str
    path: str
    rules: int = 0
    hooks: List[str] = field(default_factory=list)


@dataclass
class PluginRegistry:
    rules: List[CustomRule] = field(default_factory=list)
    post_scan_hooks: List[Callable[..., Any]] = field(default_factory=list)
    pre_scan_hooks: List[Callable[..., Any]] = field(default_factory=list)
    infos: List[PluginInfo] = field(default_factory=list)

    def add_rules(self, rules: List[CustomRule] | List[dict]) -> None:
        for r in rules:
            if isinstance(r, CustomRule):
                self.rules.append(r)
            elif isinstance(r, dict):
                self.rules.extend(load_rules_from_mapping({"rules": [r]}))

    def on_pre_scan(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        self.pre_scan_hooks.append(fn)
        return fn

    def on_post_scan(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        self.post_scan_hooks.append(fn)
        return fn


_REGISTRY: Optional[PluginRegistry] = None


def get_plugin_registry(reload: bool = False) -> PluginRegistry:
    global _REGISTRY
    if _REGISTRY is None or reload:
        _REGISTRY = PluginRegistry()
        load_all_plugins(_REGISTRY)
    return _REGISTRY


def _load_module_from_path(path: Path):
    name = f"guardrail_plugin_{path.stem}_{abs(hash(str(path))) % 10**8}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _register_module(mod: Any, registry: PluginRegistry, path: str) -> None:
    name = getattr(mod, "PLUGIN_NAME", getattr(mod, "__name__", "plugin"))
    version = getattr(mod, "PLUGIN_VERSION", "0.0.0")
    hooks: List[str] = []
    if hasattr(mod, "register") and callable(mod.register):
        mod.register(registry)
        hooks.append("register")
    if hasattr(mod, "RULES"):
        registry.add_rules(list(mod.RULES))
        hooks.append("RULES")
    if hasattr(mod, "pre_scan") and callable(mod.pre_scan):
        registry.pre_scan_hooks.append(mod.pre_scan)
        hooks.append("pre_scan")
    if hasattr(mod, "post_scan") and callable(mod.post_scan):
        registry.post_scan_hooks.append(mod.post_scan)
        hooks.append("post_scan")
    # count rules contributed roughly
    registry.infos.append(
        PluginInfo(name=str(name), version=str(version), path=path, rules=0, hooks=hooks)
    )


def load_all_plugins(registry: PluginRegistry) -> None:
    dirs: List[Path] = []
    env = os.environ.get("GUARDRAIL_PLUGIN_PATH", "")
    if env:
        dirs.extend(Path(p) for p in env.split(os.pathsep) if p.strip())
    dirs.append(Path("plugins"))
    dirs.append(Path(__file__).resolve().parents[1] / "plugins")

    seen = set()
    for d in dirs:
        try:
            d = d.resolve()
        except OSError:
            continue
        if not d.is_dir() or str(d) in seen:
            continue
        seen.add(str(d))
        # rules yaml
        for yml in list(d.glob("**/*.yaml")) + list(d.glob("**/*.yml")) + list(d.glob("**/*.json")):
            if yml.name.startswith("."):
                continue
            try:
                from .rule_engine import load_rules_file

                rules = load_rules_file(yml)
                if rules:
                    registry.rules.extend(rules)
                    registry.infos.append(
                        PluginInfo(
                            name=f"rules:{yml.name}",
                            version="file",
                            path=str(yml),
                            rules=len(rules),
                            hooks=["rules_file"],
                        )
                    )
            except Exception as exc:
                logger.warning("plugin rules load failed %s: %s", yml, exc)
        # python plugins
        for py in d.glob("*.py"):
            if py.name.startswith("_"):
                continue
            try:
                mod = _load_module_from_path(py)
                if mod:
                    _register_module(mod, registry, str(py))
            except Exception as exc:
                logger.warning("plugin import failed %s: %s", py, exc)

    # entry points
    try:
        from importlib.metadata import entry_points

        eps = entry_points()
        group = eps.select(group="guardrail.plugins") if hasattr(eps, "select") else eps.get("guardrail.plugins", [])  # type: ignore
        for ep in group or []:
            try:
                mod = ep.load()
                _register_module(mod, registry, f"entrypoint:{ep.name}")
            except Exception as exc:
                logger.warning("entrypoint plugin failed %s: %s", ep.name, exc)
    except Exception:
        pass


def run_pre_scan_hooks(source: str, language: str, context: Optional[Dict[str, Any]] = None) -> None:
    reg = get_plugin_registry()
    ctx = context or {}
    for h in reg.pre_scan_hooks:
        try:
            h(source, language, ctx)
        except Exception as exc:
            logger.warning("pre_scan hook error: %s", exc)


def run_post_scan_hooks(
    source: str,
    language: str,
    findings: list,
    context: Optional[Dict[str, Any]] = None,
) -> list:
    reg = get_plugin_registry()
    ctx = context or {}
    out = findings
    for h in reg.post_scan_hooks:
        try:
            res = h(source, language, out, ctx)
            if isinstance(res, list):
                out = res
        except Exception as exc:
            logger.warning("post_scan hook error: %s", exc)
    return out
