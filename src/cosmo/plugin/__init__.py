"""Claude Code plugin/skill integration (architecture §17, build step 20).

The final build step: cosmo ships as a Claude Code plugin/skill (`/cosmo-review`
and the `/cosmo-*` command family) that reuses Claude Code's auth/session/
tool-use by shelling to the same `cosmo` binary the CLI, git hook, and GitHub
Action already use — it does not fork Claude Code. Every guardrail is enforced
in one place (the binary); the plugin is a thin, generated surface over the
guarded interactive dispatcher, and cannot widen past it.

- `manifest` — derives the slash-command surface + plugin.json from the one
  enforced registry (`interactive.commands._COMMANDS`), with `allowed-tools`
  narrowed to the `cosmo` binary.
- `sync` — writes/prunes the on-disk plugin from that source of truth;
  `check_plugin` reports drift without writing.
- `bridge` — the in-process integration point: opens the same `Session` and
  routes every line through the same `dispatch`, with the operator config as the
  §15 ceiling.
"""
from .bridge import PluginBridge, open_session
from .manifest import (
    ALLOWED_TOOLS,
    CommandSpec,
    command_markdown,
    command_specs,
    interactive_command_names,
    plugin_manifest,
)
from .sync import check_plugin, sync_plugin

__all__ = [
    "PluginBridge", "open_session",
    "ALLOWED_TOOLS", "CommandSpec", "command_markdown", "command_specs",
    "interactive_command_names", "plugin_manifest",
    "check_plugin", "sync_plugin",
]
