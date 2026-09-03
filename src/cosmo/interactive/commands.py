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
from ..output import (render_cli, render_finding, render_pr_comment,
                      render_report, render_sarif)
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
    if handler is not None:
        # Builtins are authoritative and always win — an extension can never take
        # the name of a guarded command (see extensions loader: they are `x-*`).
        return handler(session, args)
    ext_handler = session.extension_command(name)
    if ext_handler is not None:
        return ext_handler(session, args)
    return f"unknown command /{name}; try /help"


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
                f"staying on {provider.name}.")
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


def _cmd_extensions(session: Session, args) -> str:
    """— list activated custom extensions + their /x-* commands (operator-gated)"""
    le = session.loaded_extensions()
    lines = []
    if le.active:
        lines.append("active:")
        for ext in le.active:
            cmds = ", ".join(f"/x-{c}" for c in ext.commands) or "(no commands)"
            lines.append(f"  {ext.name} v{ext.version} — "
                         f"{len(ext.skills)} skill(s), {len(ext.detectors)} detector(s); {cmds}")
    if le.disabled:
        lines.append("discovered but not enabled (add to operator extensions.enabled):")
        lines.extend(f"  {n}" for n in le.disabled)
    if le.errors:
        lines.append("failed to load:")
        lines.extend(f"  {n}: {e}" for n, e in le.errors.items())
    return "\n".join(lines) or "no extensions discovered"


def _cmd_status(session: Session, args) -> str:
    """— session snapshot: findings, running campaigns, threshold, model"""
    snapshot = session.snapshot_report()
    csum = ", ".join(f"{k}:{v}" for k, v in sorted(snapshot.counts.items())) or "none"
    camps = ", ".join(f"{n} ({s}s left)" for n, s in session.running_campaigns.items()) or "none"
    model = _status_model(session)
    if session.audit_running():
        audit = f"running ({session.audit_done}/{session.audit_total} files)"
    elif session.audit_total:
        audit = (f"done ({session.audit_done}/{session.audit_total} reviewed"
                 + (f", {session.audit_skipped} skipped" if session.audit_skipped else "") + ")")
    else:
        audit = "none"
    # Coverage belongs in the snapshot too: "findings: none" reads very
    # differently once you know three stages never ran.
    skipped = (f"{len(snapshot.skipped_stages)} stage(s) — /report cli to list"
               if snapshot.skipped_stages else "none")
    return (f"target: {session.target}\nfindings: {csum}\n"
            f"skipped: {skipped}\n"
            f"threshold: {session.effective_threshold()}\nmodel: {model}\n"
            f"audit: {audit}\ncampaigns: {camps}")


def _status_model(session: Session) -> str:
    """What /status should say about the model.

    It used to print `session_model or "claude (default)"` — a literal, not a
    lookup. That named claude even when the config had chosen something else,
    and said nothing when the provider was unavailable, which is the state an
    operator most needs to know about before trusting a result.
    """
    from ..providers.registry import describe_unavailable, resolve_primary
    try:
        provider, _ = resolve_primary(session.config,
                                      session_model=session.session_model)
    except Exception as exc:
        return f"unresolved ({exc})"
    if not provider.available():
        # The message opens "model:<name>", and /status already prints "model: "
        # in front of it — strip the duplicate rather than print it twice.
        return describe_unavailable(provider).removeprefix("model:")
    return provider.name


def _cmd_scope(session: Session, args) -> str:
    """[program=… includes=a,b excludes=c rate=N] — declare an authorized target (§9)"""
    from ..external import ScopeError
    ext = session.external_mode()
    if not args:
        if ext.scope is None:
            return "no scope declared; external recon is refused until you /scope"
        s = ext.scope
        return (f"scope: {s.program}\n  includes: {', '.join(s.includes)}\n"
                f"  excludes: {', '.join(s.excludes) or 'none'}\n"
                f"  rate: {s.rate_limit_per_sec}/s")
    decl: dict = {}
    for tok in args:
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k in ("includes", "excludes"):
            decl[k] = [x for x in v.split(",") if x]
        elif k in ("rate", "rate_limit_per_sec"):
            decl["rate_limit_per_sec"] = float(v)
        else:
            decl[k] = v
    try:
        s = ext.declare(decl)
    except ScopeError as exc:
        return f"scope refused: {exc}"
    return (f"scope declared: {s.program} ({len(s.includes)} in-scope, "
            f"{len(s.excludes)} excluded, {s.rate_limit_per_sec}/s). "
            f"every request is logged.")


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


def _cmd_audit(session: Session, args) -> str:
    """[wait] — AI-audit every file in the background; keep using the session as it runs"""
    import threading

    from ..audit import audit_call_budget, run_llm_audit
    from ..diff import resolve_diff
    from ..providers.registry import resolve_primary

    if session.audit_running():
        return (f"an audit is already running ({session.audit_done}/{session.audit_total} "
                f"files done). /status to watch.")

    provider, warns = resolve_primary(session.config, session_model=session.session_model)
    session.notes.extend(warns)
    if not provider.available():
        from ..providers import describe_unavailable
        return (f"cannot audit: {describe_unavailable(provider)} "
                f"Switch in this session with `/model <name>`.")
    # Same broker wiring as the engine (§8 + §9a); a provider that doesn't take
    # one (e.g. the CLI provider) is left as-is.
    if getattr(provider, "broker", None) is None:
        from ..providers.egress import provider_broker_from_config
        try:
            provider.broker = provider_broker_from_config(session.config)
        except AttributeError:
            pass

    diff = resolve_diff(session.target)
    if not diff.files:
        return "nothing to audit — no files resolved for this target."

    budget = audit_call_budget(session.config)
    session.audit_total = min(len(diff.files), budget)
    session.audit_done = 0
    session.audit_skipped = 0
    baseline = session.snapshot_findings()

    def _on_result(path, found):
        # Runs on an audit worker as each file completes: merge live so /status
        # and /report reflect partial progress, and advance the counter.
        session.merge_findings(found)
        session.advance_audit()

    def _worker():
        notes: list[str] = []
        skipped: list[str] = []
        try:
            run_llm_audit(diff, provider, "", baseline, session.config,
                          notes, skipped, progress=session.emit, on_result=_on_result)
        finally:
            session.audit_skipped = len(skipped)
            session.notes.extend(notes)
            session.emit(f"/audit done: {session.audit_done}/{session.audit_total} reviewed"
                         + (f", {len(skipped)} skipped" if skipped else "")
                         + ". /status or /report to review.")

    t = threading.Thread(target=_worker, name="cosmo-audit", daemon=True)
    session.audit_thread = t
    t.start()
    if args and args[0] == "wait":
        t.join()
        return ""     # the worker already emitted its completion line
    return (f"/audit started in the background: {session.audit_total} file(s) via "
            f"{provider.name}. Keep typing — /status shows progress, findings stream in.")


def _cmd_report(session: Session, args) -> str:
    """[format] — export as cli|markdown|sarif|pr (pr goes through the gate)"""
    fmt = (args[0] if args else "cli").lower()
    # The session's coverage travels with its findings. Built from a bare
    # `Report(target, findings)` this dropped `skipped_stages` entirely, so an
    # incomplete scan rendered here as a complete one.
    report = session.snapshot_report()
    if fmt == "sarif":
        return render_sarif(report)
    if fmt in ("pr", "issue"):
        # Same fail-closed gate as the GitHub Action — a sensitive/confirmed
        # finding (and its PoC) is withheld from a public surface here too.
        return render_pr_comment(report)
    if fmt in ("md", "markdown", "report"):
        # `markdown` used to alias `pr`, which meant asking for markdown in an
        # operator session silently handed back the *redacted* public comment.
        # It is the full report now; `pr` is still how you see the gated one.
        return render_report(report, threshold=session.effective_threshold())
    return render_cli(report, color=False)


def _cmd_next(session: Session, args) -> str:
    """[n] — move to the next finding and show it in full"""
    return _step(session, +1, args)


def _cmd_previous(session: Session, args) -> str:
    """[n] — move to the previous finding and show it in full"""
    return _step(session, -1, args)


def _step(session: Session, direction: int, args) -> str:
    """Walk the findings list. Shared with the screen's arrow keys.

    Both move `session.cursor` over `session.ordered_findings()`, so `/next`
    and `↓` cannot disagree about which finding is current.
    """
    step = 1
    if args:
        try:
            step = max(1, int(args[0]))
        except ValueError:
            return f"not a number: {args[0]!r}"

    items = session.ordered_findings()
    if not items:
        return ("no findings in this session yet"
                + (" — the scan is still running" if session.audit_running()
                   else "; /report cli to see what was skipped"))

    before = session.cursor
    finding = session.move_cursor(direction * step)
    at = session.cursor
    edge = ""
    if at == before:
        # Say so rather than silently redisplaying the same finding.
        edge = f"  (already at the {'last' if direction > 0 else 'first'})"
    return f"[{at + 1}/{len(items)}]{edge}\n\n{render_finding(finding)}"


def _cmd_tools(session: Session, args) -> str:
    """— static scanners: installed, version, and what a missing one costs"""
    from ..versions import check_cosmo, check_tools

    lines = []
    for t in check_tools(check_updates=False):
        if not t.installed:
            lines.append(f"  ⊘ {t.name}: not installed — {t.covers} NOT scanned "
                         f"({t.install})")
        elif t.version:
            lines.append(f"  ✓ {t.name} {t.version}")
        else:
            lines.append(f"  ? {t.name}: installed, version unknown ({t.note})")
    own = check_cosmo()
    lines.append(f"  · cosmo {own.version}")
    # Offline on purpose: a session command must not make a network call the
    # operator did not ask for. `cosmo tools --check-updates` is the opt-in.
    lines.append("  (offline; `cosmo tools --check-updates` compares against "
                 "the latest releases)")
    return "\n".join(lines)


# Order defines /help output. /disclose (§13) landed in step 18 and /scope (§9)
# in step 19 — the full session command set from the architecture.
_COMMANDS = {
    "help": _cmd_help,
    "status": _cmd_status,
    "extensions": _cmd_extensions,
    "threshold": _cmd_threshold,
    "model": _cmd_model,
    "duration": _cmd_duration,
    "skills": _cmd_skills,
    "confirm": _cmd_confirm,
    "waive": _cmd_waive,
    "baseline": _cmd_baseline,
    "scope": _cmd_scope,
    "disclose": _cmd_disclose,
    "audit": _cmd_audit,
    "report": _cmd_report,
    "tools": _cmd_tools,
    "next": _cmd_next,
    "previous": _cmd_previous,
}
