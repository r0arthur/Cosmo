"""Plugin ⇄ engine bridge (build step 20).

The integration point a Claude Code plugin/skill uses to drive cosmo *in
process*: it opens the same `Session` the interactive REPL and batch mode use,
and routes every slash line through the same `dispatch`. There is no second code
path — the plugin is a caller, never a re-implementation.

Two safety properties are load-bearing and covered by tests:

1. **Operator config is the ceiling.** `open_session` loads config through
   `load_config`, which applies the trust tiers: the operator/org config is
   the ceiling and the target repo may only *tighten* safety keys. A plugin
   invocation supplies the operator config path — it cannot inject a safety-tier
   value, because it never bypasses `load_config`.

2. **No bypass surface.** `handle` calls `interactive.dispatch` verbatim. A
   command the enforced dispatcher rejects (unknown, or one that would need a
   runtime cosmo doesn't have) is rejected here identically. The plugin adds no
   command of its own.

Importing this module never requires Claude Code to be installed — cosmo depends
on the auth/session layer as a library and degrades gracefully without it, which
is exactly the "reuse, don't fork" relationship calls for.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..config import load_config
from ..interactive.commands import dispatch
from ..interactive.session import Session


def _is_local(target: str) -> bool:
    return "#" not in target and not target.startswith("http")


def open_session(target: str, *, operator_config: str | None = None) -> Session:
    """Open a plugin-driven session with the operator config as the ceiling.

    The config resolution is identical to the REPL's: no plugin-supplied value
    can loosen a safety-tier key, because it is clamped by `load_config` before
    the session ever sees it.
    """
    config = load_config(target if _is_local(target) else ".",
                         operator_config=operator_config)
    return Session(config=config, target=target)


@dataclass
class PluginBridge:
    """A thin façade a Claude Code command handler can hold across turns.

    Holds one `Session`; forwards each line to the guarded dispatcher. It exposes
    the plugin's command surface for discovery, but executes nothing the enforced
    layer wouldn't.
    """
    session: Session

    @classmethod
    def open(cls, target: str, *, operator_config: str | None = None) -> "PluginBridge":
        return cls(session=open_session(target, operator_config=operator_config))

    def handle(self, line: str) -> str:
        """Route one slash line through the same dispatcher batch/REPL use."""
        return dispatch(self.session, line)

    def commands(self) -> list[str]:
        """The slash-command surface — exactly the guarded registry's keys."""
        from ..interactive.commands import _COMMANDS
        return list(_COMMANDS.keys())
