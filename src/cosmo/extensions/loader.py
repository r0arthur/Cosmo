"""Discover + activate extensions (custom plugins/skills).

Discovery finds *candidate* extensions from two sources without running them:

  * **local paths** — each entry in `extensions.paths` is a directory containing
    `cosmo_extension.py`; the extension's name is the directory basename, known
    without importing anything.
  * **installed packages** — entry points in the `cosmo.extensions` group, whose
    names come from package metadata, again without importing the module.

Activation is separate and gated: only names in `extensions.enabled` (operator /
safety tier) are actually imported and executed. A disabled extension's module
is never imported — `discovery ≠ activation` is a real boundary, not a label.
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..config import Config
from ..skills.loader import ORG, REPO, Skill
from .registry import Extension


@dataclass
class Discovered:
    """A candidate extension found but not yet imported/run."""
    name: str
    source: str                     # "path:<dir>" | "entrypoint:<dist>"
    load: Callable[[], Extension]   # imports + extracts the Extension when called


@dataclass
class LoadedExtensions:
    active: list[Extension] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)      # discovered, not enabled
    errors: dict[str, str] = field(default_factory=dict)   # name -> load error
    reference_only: set[str] = field(default_factory=set)

    def command_table(self) -> dict[str, "object"]:
        """Namespaced `x-<name>` commands. Collisions across extensions: first
        wins; a later duplicate is dropped (never silently overrides)."""
        table: dict[str, object] = {}
        for ext in self.active:
            for cname, handler in ext.commands.items():
                key = f"x-{cname}"
                table.setdefault(key, handler)
        return table

    def detectors(self) -> dict[str, "object"]:
        table: dict[str, object] = {}
        for ext in self.active:
            for dname, det in ext.detectors.items():
                table.setdefault(f"{ext.name}:{dname}", det)
        return table

    def skills(self) -> list[Skill]:
        """Contributed skills, with trust set by activation: enabled → trusted,
        unless the operator listed the extension under `reference_only`."""
        out: list[Skill] = []
        for ext in self.active:
            ref = ext.name in self.reference_only
            for sk in ext.skills:
                sk.origin = f"ext:{ext.name}"
                sk.trusted_override = not ref
                out.append(sk)
        return out


def _load_from_path(directory: Path) -> Extension:
    mod_path = directory / "cosmo_extension.py"
    if not mod_path.is_file():
        raise FileNotFoundError(f"no cosmo_extension.py in {directory}")
    spec = importlib.util.spec_from_file_location(
        f"cosmo_ext_{directory.name}", mod_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load extension at {mod_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)              # <-- only reached for ENABLED names
    return _extract(module, directory.name)


def _extract(module, fallback_name: str) -> Extension:
    ext = getattr(module, "COSMO_EXTENSION", None)
    if ext is None and hasattr(module, "register"):
        ext = module.register()
    if not isinstance(ext, Extension):
        raise TypeError(
            "extension module must define COSMO_EXTENSION or register() "
            "returning a cosmo.extensions.Extension")
    if not ext.name:
        ext.name = fallback_name
    return ext


def discover(config: Config) -> list[Discovered]:
    """Enumerate candidate extensions without importing/running any of them."""
    found: list[Discovered] = []
    for raw in config.get("extensions.paths", []) or []:
        d = Path(raw)
        if (d / "cosmo_extension.py").is_file():
            found.append(Discovered(
                name=d.name, source=f"path:{d}",
                load=(lambda d=d: _load_from_path(d))))
    found.extend(_discover_entrypoints())
    return found


def _discover_entrypoints() -> list[Discovered]:
    try:
        from importlib.metadata import entry_points
    except Exception:                            # pragma: no cover
        return []
    out: list[Discovered] = []
    try:
        eps = entry_points(group="cosmo.extensions")
    except TypeError:                            # <3.10 selectable API shim
        eps = entry_points().get("cosmo.extensions", [])   # pragma: no cover
    for ep in eps:
        out.append(Discovered(
            name=ep.name, source=f"entrypoint:{getattr(ep, 'value', ep.name)}",
            load=(lambda ep=ep: _extract(_call_ep(ep), ep.name))))
    return out


def _call_ep(ep):                                # pragma: no cover - needs installed dist
    obj = ep.load()
    return obj() if callable(obj) and not isinstance(obj, Extension) else obj


def load_enabled(config: Config) -> LoadedExtensions:
    """Import + register ONLY the operator-enabled extensions. Disabled candidates
    are recorded by name but never imported (their top-level code never runs)."""
    enabled = set(config.get("extensions.enabled", []) or [])
    ref_only = set(config.get("extensions.reference_only", []) or [])
    result = LoadedExtensions(reference_only=ref_only)
    for cand in discover(config):
        if cand.name not in enabled:
            result.disabled.append(cand.name)
            continue                             # <-- not imported, not executed
        try:
            ext = cand.load()
        except Exception as exc:                 # a broken extension can't break cosmo
            result.errors[cand.name] = f"{type(exc).__name__}: {exc}"
            continue
        result.active.append(ext)
    return result
