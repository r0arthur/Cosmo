"""Generate the on-disk plugin from the code (build step 20).

`sync_plugin(root)` writes `.claude-plugin/plugin.json` and `commands/*.md` from
the single source of truth (`manifest`), and prunes stale `cosmo-*.md` command
files that no longer correspond to a guarded command. Because both the manifest
and the command bodies are derived from `interactive.commands._COMMANDS`, the
shipped plugin surface can never drift away from — or widen past — the enforced
dispatcher. `check_plugin(root)` is the read-only counterpart used in CI/tests:
it reports drift without writing.
"""
from __future__ import annotations

import json
from pathlib import Path

from .manifest import command_markdown, command_specs, plugin_manifest


def _plugin_json_text(root: Path) -> str:
    return json.dumps(plugin_manifest(), indent=2) + "\n"


def _managed_command_files(specs) -> dict[str, str]:
    return {f"{s.slug}.md": command_markdown(s) for s in specs}


def sync_plugin(root: str | Path) -> list[str]:
    """Write the manifest + command files; prune stale ones. Returns changes."""
    root = Path(root)
    specs = command_specs()
    changed: list[str] = []

    pj = root / ".claude-plugin" / "plugin.json"
    pj.parent.mkdir(parents=True, exist_ok=True)
    text = _plugin_json_text(root)
    if not pj.exists() or pj.read_text() != text:
        pj.write_text(text)
        changed.append(str(pj.relative_to(root)))

    cmd_dir = root / "commands"
    cmd_dir.mkdir(parents=True, exist_ok=True)
    managed = _managed_command_files(specs)
    for fname, body in managed.items():
        path = cmd_dir / fname
        if not path.exists() or path.read_text() != body:
            path.write_text(body)
            changed.append(str(path.relative_to(root)))

    # Prune stale cosmo-*.md files (a command removed from the guarded registry).
    for path in cmd_dir.glob("cosmo-*.md"):
        if path.name not in managed:
            path.unlink()
            changed.append(f"removed {path.relative_to(root)}")

    return changed


def check_plugin(root: str | Path) -> list[str]:
    """Read-only drift report: what `sync_plugin` *would* change. Empty == clean."""
    root = Path(root)
    specs = command_specs()
    drift: list[str] = []

    pj = root / ".claude-plugin" / "plugin.json"
    if not pj.exists() or pj.read_text() != _plugin_json_text(root):
        drift.append(".claude-plugin/plugin.json")

    cmd_dir = root / "commands"
    managed = _managed_command_files(specs)
    for fname, body in managed.items():
        path = cmd_dir / fname
        if not path.exists() or path.read_text() != body:
            drift.append(f"commands/{fname}")
    if cmd_dir.exists():
        for path in cmd_dir.glob("cosmo-*.md"):
            if path.name not in managed:
                drift.append(f"stale commands/{path.name}")

    return drift
