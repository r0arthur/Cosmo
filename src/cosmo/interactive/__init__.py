"""Interactive command layer (build step 17).

Cosmo as a live session: the same engine as batch mode, streamed, answering
follow-ups from in-session findings state without re-scanning. Slash-commands
(`/duration`, `/model`, `/threshold`, `/skills`, `/confirm`, `/waive`,
`/baseline`, `/status`, `/report`, `/help`) each delegate to the same guarded
code batch mode runs — **the command layer cannot bypass the guardrails**: the
fuzz duration cap, the config trust tiers, the data-governance gate, and the
fail-closed public-comment gate all still apply. `/scope` (step 19) and
`/disclose` (step 18) register into this same dispatcher when those steps
land.
"""
from .commands import dispatch
from .driver import (
    AgentDriver,
    CommandCall,
    Plan,
    PlanRequest,
    Planner,
    ToolSpec,
    TurnResult,
    llm_planner,
    parse_plan,
    provider_planner,
    resolve_planner,
    rule_based_planner,
    run_agent,
)
from .repl import run_repl
from .session import Session

__all__ = [
    "Session", "dispatch", "run_repl",
    # Harness-agnostic driver (option 2) — orchestration on any model, or none.
    "AgentDriver", "run_agent", "Planner", "Plan", "PlanRequest", "CommandCall",
    "ToolSpec", "TurnResult", "rule_based_planner", "llm_planner", "parse_plan",
    "provider_planner", "resolve_planner",
]
