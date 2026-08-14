"""Interactive command layer (architecture §7, build step 17).

Cosmo as a live session: the same engine as batch mode, streamed, answering
follow-ups from in-session findings state without re-scanning. Slash-commands
(`/duration`, `/model`, `/threshold`, `/skills`, `/confirm`, `/waive`,
`/baseline`, `/status`, `/report`, `/help`) each delegate to the same guarded
code batch mode runs — **the command layer cannot bypass the guardrails**: the
fuzz duration cap, the config trust tiers, the data-governance gate, and the
fail-closed public-comment gate all still apply. `/scope` (§9, step 19) and
`/disclose` (§13, step 18) register into this same dispatcher when those steps
land.
"""
from .commands import dispatch
from .repl import run_repl
from .session import Session

__all__ = ["Session", "dispatch", "run_repl"]
