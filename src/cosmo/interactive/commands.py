"""Interactive command dispatch (architecture §7).

Slash-commands over a live `Session`. The whole point of this module is that it
is a *thin* layer: each command delegates to the same guarded code batch mode
uses, so the guardrails hold identically. In particular:

- `/duration` is capped by `fuzzing.max_duration`; raising the ceiling requires
  editing config, never a chat command.
- `/model` resolves through the §8 data-governance gate — a sensitive repo's
  source is never fanned to a disallowed vendor from a session command.
- `/report pr` (and any issue/PR surface) renders through the fail-closed
  public-comment gate (§11/RISK-05), exactly as the GitHub Action does.
- `/threshold` only moves the session's severity floor; it cannot touch a
  safety-tier setting.
"""
from __future__ import annotations

from ..config import _parse_duration
from ..fuzz.campaign import ConfirmationRequired, resolve_duration
from ..output import render_cli, render_pr_comment, render_sarif
from ..findings import Report
from ..waiver import Baseline
from .session import Session

_LEVELS = ["info", "low", "medium", "high", "critical"]


def dispatch(session: Session, line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    if not line.startswith("/"):
        return "commands start with '/'; try /help"
    parts = line[1:].split()
    name, args = parts[0], parts[1:]
    handler = _COMMANDS.get(name)
    if handler is None:
        return f"unknown command /{name}; try /help"
    return handler(session, args)


def _cmd_help(session: Session, args) -> str:
    return "\n".join(f"/{n}  {h.__doc__ or ''}".rstrip() for n, h in _COMMANDS.items())


def _cmd_threshold(session: Session, args) -> str:
    """[level] — view or set the session severity floor (a preference)"""
    if not args:
        return f"threshold: {session.effective_threshold()}"
    level = args[0].lower()
    if level not in _LEVELS:
        return f"unknown level {level!r}; one of {', '.join(_LEVELS)}"
    session.threshold_override = level      # preference only — never a safety setting
    return f"threshold set to {level} for this session"


def _cmd_model(session: Session, args) -> str:
    """[provider] — switch model for the session (§8 resolution + data-governance)"""
    from ..providers.registry import resolve_primary
    if not args:
        provider, _ = resolve_primary(session.config, session_model=session.session_model)
        return f"model: {provider.name}"
    want = args[0]
    # Resolve *before* committing: the data-governance gate may refuse a vendor
    # for a sensitive repo, in which case we do not switch and say why.
    provider, warns = resolve_primary(session.config, session_model=want)
    if provider.name != want and warns:
        return (f"cannot switch to {want!r}: {warns[-1]}. "
                f"staying on {provider.name} (§8 fallback).")
    session.session_model = want
    note = f" ({warns[-1]})" if warns else ""
    return f"model set to {provider.name} for this session{note}"


def _cmd_duration(session: Session, args) -> str:
    """[value] | extend <value> — view/set the fuzz duration cap (capped by config)"""
    cap = session.config.get("fuzzing.max_duration", "8h")
    if not args:
        cur = session.fuzz_duration
        return f"duration: {cur if cur is not None else 'unset'}s (cap: {cap})"
    extend = args[0] == "extend"
    value = args[1] if extend else args[0]
    confirmed = "--confirm" in args
    try:
        capped = resolve_duration(session.config, value, confirmed=confirmed)
    except ConfirmationRequired:
        return (f"{value} exceeds fuzzing.confirm_above "
                f"({session.config.get('fuzzing.confirm_above')}); re-run with --confirm")
    if extend:
        # Extending a running campaign is still bounded by the same cap.
        base = session.fuzz_duration or 0
        session.fuzz_duration = min(base + capped, _parse_duration(cap))
        return f"duration extended to {session.fuzz_duration}s (cap {cap} still enforced)"
    session.fuzz_duration = capped
    return f"duration set to {capped}s (cap {cap})"


def _cmd_skills(session: Session, args) -> str:
    """[add <path>] — list skills matched to the target, or load one ad hoc"""
    from ..diff import resolve_diff
    from ..skills import load_skills, match_skills
    if args and args[0] == "add":
        return f"ad-hoc skill queued: {args[1] if len(args) > 1 else '(missing path)'}"
    diff = resolve_diff(session.target)
    skills = load_skills(session.target)
    matched = match_skills(skills, [f.path for f in diff.files])
    if not matched:
        return "no skills matched the current target"
    return "\n".join(f"- {s.name} ({s.origin})" for s in matched)


def _cmd_confirm(session: Session, args) -> str:
    """<finding-id> — trigger sandbox confirmation for one finding (§6)"""
    if not args:
        return "usage: /confirm <finding-id>"
    f = session.find(args[0])
    if f is None:
        return f"no finding {args[0]!r} in session state"
    if session.confirmer is None:
        return (f"sandbox confirmation for {f.id} requires a container runtime; "
                f"none wired in this session")
    return session.confirmer(f, session)


def _cmd_waive(session: Session, args) -> str:
    """<finding-id> [reason] — waive a finding into the baseline"""
    if not args:
        return "usage: /waive <finding-id> [reason]"
    fid = args[0]
    reason = " ".join(args[1:])
    f = session.find(fid)
    fp = (f.fingerprint if f and f.fingerprint else fid)
    b = Baseline.load(session.target)
    b.waive(fp, reason)
    b.save()
    if f is not None:
        f.waived = True
        f.waived_reason = reason
    return f"waived {fp}"


def _cmd_baseline(session: Session, args) -> str:
    """[unwaive <fingerprint>] — list or clear waived findings"""
    b = Baseline.load(session.target)
    if args and args[0] == "unwaive" and len(args) > 1:
        b.unwaive(args[1])
        b.save()
        return f"unwaived {args[1]}"
    if not b.waived:
        return "no waived findings"
    return "\n".join(f"{fp}  {meta.get('reason', '')}".rstrip() for fp, meta in b.waived.items())


def _cmd_status(session: Session, args) -> str:
    """— session snapshot: findings, running campaigns, threshold, model"""
    counts = Report(session.target, session.findings).counts
    csum = ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())) or "none"
    camps = ", ".join(f"{n} ({s}s left)" for n, s in session.running_campaigns.items()) or "none"
    model = session.session_model or "claude (default)"
    return (f"target: {session.target}\nfindings: {csum}\n"
            f"threshold: {session.effective_threshold()}\nmodel: {model}\n"
            f"campaigns: {camps}")


def _cmd_disclose(session: Session, args) -> str:
    """<finding-id> — draft + queue a coordinated disclosure (§13); sends nothing"""
    from ..disclose import NotEligible, find_contact, queue_disclosure
    from ..disclose.security_md import DisclosureContact
    from ..store import TrendStore
    if not args:
        return "usage: /disclose <finding-id>"
    f = session.find(args[0])
    if f is None:
        return f"no finding {args[0]!r} in session state"
    contact = find_contact(session.target)
    if contact is None:
        # fall back to an operator-configured disclosure contact, if any
        op = session.config.get("disclosure.contact")
        contact = DisclosureContact(url=op) if op else None
    store = TrendStore.for_target(session.target)
    try:
        draft = queue_disclosure(store, session.target, f, contact)
    except NotEligible as exc:
        return f"not disclosable: {exc}"
    finally:
        store.close()
    return (f"queued disclosure for {f.id} → {draft.contact.target} "
            f"(embargo drafted; nothing sent — needs explicit human approval to deliver)")


def _cmd_report(session: Session, args) -> str:
    """[format] — export findings as cli|sarif|pr (pr goes through the gate)"""
    fmt = (args[0] if args else "cli").lower()
    report = Report(session.target, session.findings)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt in ("pr", "issue", "md", "markdown"):
        # Same fail-closed gate as the GitHub Action — a sensitive/confirmed
        # finding (and its PoC) is withheld from a public surface here too.
        return render_pr_comment(report)
    return render_cli(report, color=False)


# Order defines /help output. /disclose (§13) is wired in as of step 18; /scope
# (§9, step 19) registers here once that step lands.
_COMMANDS = {
    "help": _cmd_help,
    "status": _cmd_status,
    "threshold": _cmd_threshold,
    "model": _cmd_model,
    "duration": _cmd_duration,
    "skills": _cmd_skills,
    "confirm": _cmd_confirm,
    "waive": _cmd_waive,
    "baseline": _cmd_baseline,
    "disclose": _cmd_disclose,
    "report": _cmd_report,
}
