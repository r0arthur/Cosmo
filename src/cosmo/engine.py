"""Core engine (architecture §1, build step 1).

    run_review(target, config) -> Report

The single entry point every trigger adapter calls. Pipeline order follows the
architecture: static pre-filter first (§5), its output handed to the LLM as
context so the model doesn't re-derive it, then dedupe, then waiver suppression
(§11), then the severity floor.
"""
from __future__ import annotations

from .cache import Cache, cache_or_run, diff_file_contents, model_key, static_key
from .config import Config
from .context import ContextItem, apply_prioritization, build_priority_signals, extract_all, fetch_context
from .diff import resolve_diff
from .events import Emitter
from .findings import Finding, Report
from .providers import ModelProvider, resolve_primary
from .severity import Severity, meets_threshold
from .skills import build_skill_context, load_skills, match_skills
from .static import run_static_prefilter
from .waiver import Baseline


def run_review(
    target: str,
    config: Config,
    provider: ModelProvider | None = None,
    context_items: list[ContextItem] | None = None,
    model: str | None = None,
    audit: bool = False,
    progress=None,
    events=None,
) -> Report:
    # An Emitter with no sink is a no-op, so the instrumented path below is the
    # same path an uninstrumented caller takes.
    ev = events if isinstance(events, Emitter) else Emitter(events)
    ev.objective_started(
        f"Security review of {target}",
        target=target, audit=audit, threshold=config.threshold)

    ev.stage_started("resolve")
    diff = resolve_diff(target)
    ev.operation(f"{diff.source} target, {len(diff.files)} file(s) to review",
                 stage="resolve", files=len(diff.files), source=diff.source)
    ev.stage_completed("resolve", f"{len(diff.files)} file(s) from {diff.source}",
                       files=len(diff.files))

    findings: list[Finding] = []
    skipped: list[str] = []
    notes: list[str] = list(config.warnings)  # surface config trust-tier clamps to the operator
    for w in config.warnings:
        ev.warning(w, stage="resolve")

    # Step 12 — incremental cache: only re-run expensive stages when inputs change.
    ev.stage_started("cache")
    cache_on = config.get("incremental", {}).get("enabled", True)
    cache = Cache.load(diff.target, enabled=cache_on)
    file_contents = diff_file_contents(diff)
    if cache_on:
        ev.stage_completed("cache", "incremental cache enabled")
    else:
        ev.stage_skipped("cache", "incremental cache disabled (--no-cache)")

    # Step 6 — static pre-filter (before the LLM stage, §5), cached per changed-file content.
    ev.stage_started("static")
    s_key = static_key(file_contents)
    static_skips: list[str] = []
    static_findings, hit = cache_or_run(
        cache, s_key, lambda: _run_static_recorded(diff.target, static_skips, ev))
    if hit:
        # A cache hit bypasses the runner, and its skipped-stage records would go
        # with it — leaving a cached run claiming coverage it never had. Cache
        # what was skipped alongside what was found, and replay it.
        static_skips = list(cache.get(_skip_key(s_key)) or [])
        for s in static_skips:
            ev.stage_skipped("static", s)
        notes.append("incremental: reused cached static results")
        ev.operation("reused cached static results (inputs unchanged)", stage="static")
    else:
        cache.set(_skip_key(s_key), static_skips)
    skipped += static_skips
    findings += static_findings
    ev.stage_completed("static", f"{len(static_findings)} finding(s)",
                       findings=len(static_findings))

    # Step 1 — LLM review. Provider resolved through the layer (§8): resolution
    # order + data-governance gate + fallback to the Claude default.
    ev.stage_started("provider")
    if provider is None:
        # `model` (the --model flag) enters at the CLI tier of the §8 resolution
        # order, so it outranks the configured default but still passes the
        # data-governance gate.
        provider, resolve_warnings = resolve_primary(config, cli_model=model)
        notes += resolve_warnings
        for w in resolve_warnings:
            ev.warning(w, stage="provider")
    # Route this provider's model-API egress through the broker (§8 + §9a): one
    # audit log, one forbidden-address block. Honors the operator allow-list.
    if getattr(provider, "broker", None) is None:
        from .providers.egress import provider_broker_from_config
        try:
            provider.broker = provider_broker_from_config(config)
        except AttributeError:
            pass  # a provider that doesn't accept a broker (e.g. a test stub)
    _watch_egress(provider, ev)

    if provider.available():
        ev.stage_completed("provider", f"model:{provider.name} ready",
                           provider=provider.name)
        ev.stage_started("context")
        context = _review_context(diff, static_findings, config, notes, ev)
        ev.stage_completed("context", f"{len(context)} chars of review context")

        ev.stage_started("llm")
        if audit:
            # Whole-project audit: review file-by-file under a hard call budget
            # (§ cost guard). Not cached — each file is a distinct model call.
            from .audit import run_llm_audit
            before = len(findings)
            findings += run_llm_audit(
                diff, provider, context, list(findings), config, notes, skipped,
                progress=progress, events=ev)
            ev.stage_completed("llm", f"{len(findings) - before} finding(s) "
                                      f"from a whole-project audit")
        else:
            m_key = model_key(file_contents, provider.name, context)
            try:
                ev.api_request(f"model:{provider.name} — reviewing {len(diff.files)} "
                               f"file(s) in one prompt", stage="llm")
                model_findings, m_hit = cache_or_run(
                    cache, m_key, lambda: provider.review(diff, context, list(findings)))
                findings += model_findings
                if m_hit:
                    notes.append(f"incremental: reused cached model:{provider.name} results")
                    ev.operation(f"reused cached model:{provider.name} results", stage="llm")
                ev.stage_completed("llm", f"{len(model_findings)} finding(s)",
                                   findings=len(model_findings))
            except Exception as exc:  # never silently skip review (§8) — record it
                skipped.append(f"model:{provider.name} (error: {exc})")
                ev.error(f"model:{provider.name} failed: {exc}", stage="llm")
                ev.stage_skipped("llm", f"model:{provider.name} (error: {exc})")
    else:
        reason = f"model:{provider.name} (unavailable — no SDK or ANTHROPIC_API_KEY)"
        skipped.append(reason)
        ev.stage_skipped("provider", reason)
        ev.stage_skipped("context", "no reviewer — context not built")
        ev.stage_skipped("llm", reason)

    if not cache.save() and cache.enabled:
        notes.append("cache: could not write .cosmo cache (read-only/permission) — "
                     "review unaffected, no incremental speedup next run")
        ev.warning("could not write .cosmo cache — no incremental speedup next run",
                   stage="cache")

    # Custom extension detectors (operator-gated). Their output is normalized into
    # the shared Finding shape and joins the same downstream path — dedupe, waiver,
    # and the §11 public-comment gate — with no privileged shortcut.
    ev.stage_started("extensions")
    ext = _run_extension_detectors(diff.target, config, skipped, notes)
    findings += ext
    ev.stage_completed("extensions", f"{len(ext)} finding(s) from custom detectors",
                       findings=len(ext))

    ev.stage_started("dedupe")
    before = len(findings)
    findings = _dedupe(findings)
    ev.stage_completed("dedupe", f"{before} → {len(findings)} after dedupe",
                       removed=before - len(findings))

    # Step 5 — waiver/baseline suppression (fingerprints stamped here).
    ev.stage_started("waiver")
    baseline = Baseline.load(diff.target)
    findings = baseline.apply(findings, diff)
    waived = sum(1 for f in findings if f.waived)
    ev.stage_completed("waiver", f"{waived} finding(s) waived by baseline", waived=waived)

    # Step 11 — context ingestion: prioritize (never create/suppress) findings.
    # _apply_context emits its own terminal event: it either skips the stage or
    # completes it, and emitting both here would mark a skipped stage done.
    ev.stage_started("priority")
    findings = _apply_context(target, diff, findings, config, context_items, notes,
                              skipped, ev)

    # Severity floor (step 2 threshold). Waived findings are kept in the report
    # object (counted, not shown) so `--baseline` can list them.
    ev.stage_started("threshold")
    floor = Severity.parse(config.threshold)
    before = len(findings)
    findings = [f for f in findings if f.waived or meets_threshold(f.severity, floor)]
    ev.stage_completed("threshold",
                       f"{len(findings)} at or above {config.threshold} "
                       f"({before - len(findings)} below the floor)")

    report = Report(target=diff.target, findings=findings, skipped_stages=skipped, notes=notes)
    actionable = [f for f in findings if not f.waived]
    for f in sorted(actionable, key=lambda f: f.severity, reverse=True):
        ev.finding(f"{f.severity} {f.title}", detail=f"{f.file}:{f.line}",
                   severity=str(f.severity), file=f.file, line=f.line,
                   source=f.source)
    ev.objective_completed(
        f"Review complete — {len(actionable)} actionable finding(s)",
        findings=len(actionable), waived=waived, skipped=list(skipped),
        counts=report.counts, target=report.target)
    return report


def _watch_egress(provider, ev: Emitter) -> None:
    """Mirror the broker's egress decisions into the event stream (§9a).

    Reads the same record the broker already writes — the UI observes the audit
    log, it never becomes a second, divergent one.
    """
    if not ev:
        return
    log = getattr(getattr(provider, "broker", None), "log", None)
    if log is None:
        return

    def _observe(rec) -> None:
        if rec.allowed:
            ev.api_request(f"{rec.tool} → {rec.resolved_host}", stage="llm",
                           mode=rec.mode, host=rec.resolved_host)
        else:
            ev.error(f"egress DENIED {rec.tool} → {rec.resolved_host}: {rec.reason}",
                     stage="llm", mode=rec.mode)

    log.observer = _observe


def _run_extension_detectors(target: str, config: Config, skipped: list[str],
                             notes: list[str]) -> list[Finding]:
    """Run operator-enabled extension detectors; normalize their output.

    A broken or misbehaving detector is isolated: it is recorded as skipped, never
    crashing the review, and any non-Finding it returns is rejected by
    `normalize_extension_findings` rather than silently trusted."""
    from .extensions import load_enabled, normalize_extension_findings
    loaded = load_enabled(config)
    for name, err in loaded.errors.items():
        skipped.append(f"ext:{name} (load error: {err})")
    out: list[Finding] = []
    for det_id, detector in loaded.detectors().items():
        ext_name = det_id.split(":", 1)[0]
        try:
            out += normalize_extension_findings(ext_name, detector(target, config))
        except Exception as exc:
            skipped.append(f"ext-detector:{det_id} (error: {exc})")
    if out:
        notes.append(f"extensions: {len(out)} finding(s) from custom detectors")
    return out


def _skip_key(stage_key: str) -> str:
    """Sibling cache key holding a stage's skipped-stage records."""
    return stage_key + ":skipped"


def _run_static_recorded(target: str, skipped: list[str],
                         ev: Emitter | None = None) -> list[Finding]:
    """Run the static pre-filter, appending its skipped-stage notes."""
    ev = ev or Emitter(None)
    static_findings, static_skipped = run_static_prefilter(target, events=ev)
    skipped += static_skipped
    return static_findings


def _static_context(static_findings: list[Finding]) -> str:
    return "\n".join(f"- {f.file}:{f.line} [{f.category or f.source}] {f.title}"
                     for f in static_findings)


def _review_context(diff, static_findings: list[Finding], config: Config,
                    notes: list[str], ev: Emitter | None = None) -> str:
    """Compose the LLM review context: static pre-filter output (§5) + matched
    skills (§10), with org skills trusted and repo skills framed as untrusted."""
    ev = ev or Emitter(None)
    parts: list[str] = []
    sc = _static_context(static_findings)
    if sc:
        parts.append("## Static pre-filter already flagged (do not re-derive):\n" + sc)
        ev.operation(f"handing {len(static_findings)} static finding(s) to the model "
                     f"so it doesn't re-derive them", stage="context")

    skills = load_skills(diff.target, org_dir=config.get("skills.org_dir"))
    # Custom skills contributed by operator-enabled extensions (trust follows
    # activation; reference_only extensions load as untrusted — see extensions §).
    from .extensions import load_enabled
    skills += load_enabled(config).skills()
    matched = match_skills(skills, [f.path for f in diff.files])
    if matched:
        untrusted = sum(1 for s in matched if not s.trusted)
        notes.append(f"skills matched: {len(matched)} "
                     f"({untrusted} repo/untrusted)")
        ev.operation(f"{len(matched)} skill(s) matched the changed files "
                     f"({untrusted} from the repo, injected as untrusted)",
                     stage="context", matched=len(matched), untrusted=untrusted)
        parts.append(build_skill_context(matched))
    return "\n\n".join(parts)


def _apply_context(target, diff, findings, config, context_items, notes, skipped,
                   ev: Emitter | None = None):
    """Fetch (or use injected) context, extract signals, and nudge prioritization.

    Only runs for GitHub targets when enabled; degrades gracefully otherwise.
    Prioritization raises attention on referenced files — it never creates or
    suppresses a finding (§4)."""
    ev = ev or Emitter(None)
    if not config.get("context_ingestion", {}).get("issues", True):
        ev.stage_skipped("priority", "issue ingestion disabled in config")
        return findings
    items = context_items
    if items is None:
        if diff.source != "github":
            ev.stage_skipped("priority", "local target — no issues to read")
            return findings
        ev.operation(f"reading issues/comments for {target}", stage="priority")
        items, ctx_skipped = fetch_context(target)
        skipped += ctx_skipped
    if not items:
        ev.stage_skipped("priority", "no issue context found")
        return findings

    priority = build_priority_signals(extract_all(items), [f.path for f in diff.files])
    if priority.path_boosts:
        notes.append(f"context: prioritized {len(priority.path_boosts)} file(s) from "
                     f"{len(items)} issue(s)")
        ev.operation(f"raised attention on {len(priority.path_boosts)} file(s) named "
                     f"by {len(items)} issue(s)", stage="priority")
    for hint in priority.partial_fix_hints:
        notes.append(hint)
    ev.stage_completed("priority",
                       f"{len(priority.path_boosts)} file(s) prioritized from "
                       f"{len(items)} issue(s)")
    return apply_prioritization(findings, priority)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Coarse dedupe by (file, line, category); the real aggregator (§11) is richer."""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.file, f.line, f.category or f.title)
        cur = seen.get(key)
        if cur is None or f.severity > cur.severity:
            seen[key] = f
    return list(seen.values())
