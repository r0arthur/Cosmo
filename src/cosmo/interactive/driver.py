"""Harness-agnostic interactive driver (architecture §17, option 2).

The Claude Code plugin (§17 option 1) reuses Claude Code's *agent loop* to turn
natural language into cosmo commands. That couples the orchestration — not the
review model, but the loop that drives it — to Claude Code's runtime. This module
is the other option: cosmo's own minimal agent loop, so the whole interactive
experience (orchestration included) can run under **any** model, or none.

The design keeps the model on a short leash. A *planner* (backed by whatever
provider you like — a local Llama, DeepSeek, an OpenAI-compatible endpoint, or a
pure rule-based fallback with no model at all) proposes which cosmo commands to
run. The **driver** is the containment boundary:

  * The model is only ever offered the **guarded command catalog** — the exact
    `interactive.commands` registry (plus active `/x-*` extension commands). It
    cannot be offered, and cannot invoke, anything outside it.
  * Every proposed call is **validated against that catalog and executed only
    through `dispatch`** — the same guarded path the REPL and batch mode use. A
    hallucinated or hostile command name is refused, never executed.
  * Therefore the orchestrating model is contained to *exactly* the surface a
    human at the REPL has: it cannot run a shell, reach past the dispatcher, or
    loosen a safety-tier setting. All the downstream guardrails (config trust
    tiers, the §11 gate, the egress broker, disclosure's human-approval step)
    still apply, because nothing bypasses `dispatch`.

Provider-agnostic by construction: the driver never imports a provider. It takes
a `Planner` callable; `rule_based_planner` needs no model, and `llm_planner`
adapts any text-completion function into a planner.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable

from .commands import _COMMANDS, dispatch
from .session import Session


@dataclass(frozen=True)
class ToolSpec:
    """One command offered to the planner — name + its one-line usage."""
    name: str
    usage: str


@dataclass(frozen=True)
class CommandCall:
    name: str
    args: list[str] = field(default_factory=list)

    def to_line(self) -> str:
        return "/" + " ".join([self.name, *self.args]).strip()


@dataclass
class Plan:
    """A planner's proposal for one turn: an optional message + commands to run."""
    message: str = ""
    calls: list[CommandCall] = field(default_factory=list)


@dataclass
class PlanRequest:
    instruction: str
    catalog: list[ToolSpec]
    transcript: list[str]


# A planner turns a natural-language instruction (+ the offered catalog) into a
# Plan. It is UNTRUSTED — the driver validates and contains whatever it returns.
Planner = Callable[[PlanRequest], Plan]


@dataclass
class TurnResult:
    message: str = ""
    executed: list[tuple[str, str]] = field(default_factory=list)   # (line, output)
    refused: list[tuple[str, str]] = field(default_factory=list)    # (name, reason)

    def render(self) -> str:
        parts: list[str] = []
        if self.message:
            parts.append(self.message)
        for line, out in self.executed:
            parts.append(f"$ {line}\n{out}")
        for name, reason in self.refused:
            parts.append(f"[refused /{name}: {reason}]")
        return "\n\n".join(parts).strip()


class AgentDriver:
    """Model-agnostic agent loop over a guarded `Session`."""

    def __init__(self, session: Session, planner: Planner, *, max_calls_per_turn: int = 4):
        self.session = session
        self.planner = planner
        self.max_calls_per_turn = max_calls_per_turn
        self.transcript: list[str] = []

    def catalog(self) -> list[ToolSpec]:
        """The exact guarded surface offered to the model: builtins + active
        `/x-*` extension commands. This is the *only* set of tools the planner
        sees, so it cannot be widened past the enforced dispatcher."""
        specs = [ToolSpec(name, _first_line(h.__doc__)) for name, h in _COMMANDS.items()]
        for xname in self.session.loaded_extensions().command_table():
            specs.append(ToolSpec(xname, "custom extension command"))
        return specs

    def _offered(self) -> set[str]:
        return {t.name for t in self.catalog()}

    def step(self, instruction: str) -> TurnResult:
        """Run one turn: plan, validate, execute through the guarded dispatcher."""
        offered = self._offered()
        plan = self.planner(PlanRequest(instruction, self.catalog(), list(self.transcript)))
        result = TurnResult(message=plan.message)
        self.transcript.append(f"user: {instruction}")

        for call in plan.calls[: self.max_calls_per_turn]:
            if call.name not in offered:
                # Containment: the model proposed something outside the guarded
                # catalog. It is never executed — not as a command, not otherwise.
                result.refused.append(
                    (call.name, "not in the guarded command catalog"))
                continue
            line = call.to_line()
            out = dispatch(self.session, line)     # the ONE execution path
            result.executed.append((line, out))
            self.transcript.append(f"cosmo: {line} -> {out}")
        return result


# --------------------------------------------------------------------------- #
# Planners.  Both are provider-agnostic; neither imports a model.
# --------------------------------------------------------------------------- #

def _first_line(doc: str | None) -> str:
    for ln in (doc or "").splitlines():
        if ln.strip():
            return ln.strip()
    return ""


def rule_based_planner(req: PlanRequest) -> Plan:
    """A deterministic planner with NO model — proof the loop runs on nothing but
    cosmo. Maps a few plain-language intents onto guarded commands; anything it
    can't map becomes a help message rather than a guessed command."""
    text = req.instruction.strip()
    low = text.lower()
    names = {t.name for t in req.catalog}
    words = text.split()

    def call(name, *args):
        return Plan(calls=[CommandCall(name, list(args))]) if name in names else _menu(req)

    if low in ("help", "?") or low.startswith("help"):
        return call("help")
    if any(w in low for w in ("status", "state", "where am i", "summary")):
        return call("status")
    if "extension" in low or "plugin" in low:
        return call("extensions")
    m = re.search(r"threshold\s+(?:to\s+)?(\w+)", low)
    if m:
        return call("threshold", m.group(1))
    m = re.search(r"(?:model|switch to|use)\s+(\w+)", low)
    if m and "threshold" not in low:
        return call("model", m.group(1))
    if "sarif" in low:
        return call("report", "sarif")
    if "pr comment" in low or low.strip() in ("report pr", "pr"):
        return call("report", "pr")
    if low.startswith("report") or "export" in low:
        return call("report")
    m = re.search(r"waive\s+(\S+)", text)
    if m:
        return call("waive", m.group(1))
    m = re.search(r"disclose\s+(\S+)", text)
    if m:
        return call("disclose", m.group(1))
    if low.startswith("scope") or "in scope" in low:
        return call("scope", *words[1:]) if "scope" in names else _menu(req)
    return _menu(req)


def _menu(req: PlanRequest) -> Plan:
    listing = ", ".join(f"/{t.name}" for t in req.catalog)
    return Plan(message=f"I can run these cosmo commands: {listing}. "
                        f"Tell me which, e.g. \"show status\" or \"set threshold to high\".")


_PLAN_INSTRUCTIONS = (
    "You orchestrate cosmo, a security review tool, by choosing which of its "
    "commands to run. You may ONLY choose commands from the catalog below; you "
    "cannot run anything else. Reply with a single JSON object: "
    '{"message": "<short reply>", "calls": [{"name": "<command>", "args": ["..."]}]}. '
    "Use an empty calls list if no command should run."
)


def llm_planner(complete: Callable[[str], str]) -> Planner:
    """Adapt any text-completion function into a planner.

    `complete(prompt) -> text` is the single seam: a local Llama server, a
    DeepSeek / OpenAI-compatible endpoint, or any other backend fits here, so
    orchestration is not tied to Claude. The returned JSON is parsed leniently
    and, crucially, is still validated + contained by the driver — a model that
    proposes an off-catalog command changes nothing about what can execute."""
    def plan(req: PlanRequest) -> Plan:
        catalog = "\n".join(f"- /{t.name}: {t.usage}" for t in req.catalog)
        history = "\n".join(req.transcript[-8:])
        prompt = (f"{_PLAN_INSTRUCTIONS}\n\nCATALOG:\n{catalog}\n\n"
                  f"CONVERSATION:\n{history}\n\nUSER: {req.instruction}\n\nJSON:")
        try:
            raw = complete(prompt)
        except Exception as exc:
            return Plan(message=f"(planner backend error: {exc})")
        return parse_plan(raw)
    return plan


def parse_plan(raw: str) -> Plan:
    """Leniently parse a planner's JSON reply into a Plan. Malformed output
    degrades to a plain message — never to an unintended command."""
    match = re.search(r"\{.*\}", raw or "", re.DOTALL)
    if not match:
        return Plan(message=(raw or "").strip())
    try:
        obj = json.loads(match.group(0))
    except (ValueError, TypeError):
        return Plan(message=(raw or "").strip())
    calls: list[CommandCall] = []
    for c in obj.get("calls", []) or []:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name", "")).lstrip("/").strip()
        if not name:
            continue
        args = [str(a) for a in (c.get("args") or [])]
        calls.append(CommandCall(name, args))
    return Plan(message=str(obj.get("message", "")).strip(), calls=calls)


def provider_planner(provider) -> Planner:
    """Back an `llm_planner` with a live provider's `complete()`. The single seam
    between the model-agnostic loop and a real backend — Claude, Codex, DeepSeek,
    or a local Llama all fit, since each implements `complete`."""
    return llm_planner(lambda prompt: provider.complete(prompt))


def resolve_planner(config, *, provider=None) -> "tuple[Planner, list[str]]":
    """Pick the planner for a config: a live provider when one is available and
    allowed, else the no-model rule-based planner. Honors the §8 data-governance
    gate — an off-box vendor a sensitive repo hasn't allowed is NOT used, and its
    `complete()` is never called, so nothing is exported to build a plan."""
    from ..providers import resolve_primary, vendor_allowed   # lazy: keep module provider-agnostic

    notes: list[str] = []
    if provider is None:
        provider, warns = resolve_primary(config)
        notes += warns

    ok, reason = vendor_allowed(provider, config)
    if not ok:
        notes.append(f"planner: {reason} — using the no-model planner instead")
        return rule_based_planner, notes
    if not hasattr(provider, "complete") or not provider.available():
        notes.append(f"planner: provider {provider.name!r} can't complete "
                     f"(no SDK/key) — using the no-model planner")
        return rule_based_planner, notes
    notes.append(f"planner: orchestrating with provider {provider.name!r}")
    return provider_planner(provider), notes


def run_agent(
    target: str,
    planner: Planner | None = None,
    *,
    operator_config: str | None = None,
    read: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
    autoscan: bool = True,
) -> AgentDriver:
    """A natural-language REPL, harness-agnostic. Same guarded engine as batch
    mode; the planner decides which commands run, the driver contains them. With
    no planner given, one is resolved from config — a live provider if available
    and allowed, otherwise the no-model rule-based planner."""
    from ..config import load_config

    def _local(t: str) -> bool:
        return "#" not in t and not t.startswith("http")

    config = load_config(target if _local(target) else ".", operator_config=operator_config)
    session = Session(config=config, target=target)
    if planner is None:
        planner, notes = resolve_planner(config)
        for n in notes:
            write(n)
    driver = AgentDriver(session, planner)
    write("cosmo agent — natural language over the guarded command surface. "
          "The model can only run cosmo commands; guardrails are unchanged.")
    if autoscan:
        report = session.scan()
        write(f"initial scan: {len(report.findings)} finding(s) at "
              f"threshold {session.effective_threshold()}")
    while True:
        try:
            line = read("you> ")
        except (EOFError, KeyboardInterrupt):
            break
        line = (line or "").strip()
        if line in ("", "quit", "exit", "/quit", "/exit"):
            break
        write(driver.step(line).render())
    return driver
