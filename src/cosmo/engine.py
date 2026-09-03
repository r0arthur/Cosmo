"""Core engine (architecture §1, build step 1).

    run_review(target, config) -> Report

The single entry point every trigger adapter calls. Pipeline order follows the
architecture: static pre-filter first (§5), its output handed to the LLM as
context so the model doesn't re-derive it, then dedupe, then waiver suppression
(§11), then the severity floor.
"""
from __future__ import annotations

from .cache import (Cache, STATIC_VERSION, cache_or_run, diff_file_contents,
                    model_key, static_key)
from .config import Config
from .context import ContextItem, apply_prioritization, build_priority_signals, extract_all, fetch_context
from .diff import resolve_diff
from .events import Emitter
from .findings import Finding, Report
from .providers import ModelProvider, describe_unavailable, resolve_primary
from .severity import Severity, meets_threshold
from .skills import build_skill_context, load_skills, match_skills
from .static import run_static_prefilter, source_family, static_ruleset_id
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
    static_only: bool = False,
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
    # The active tool set is part of the key: enabling a scanner and re-running
    # must not replay the cached findings of the narrower set against unchanged
    # files, presenting the old coverage as the new one.
    s_key = static_key(file_contents,
                       rule_version=f"{STATIC_VERSION}+{static_ruleset_id(config)}")
    static_skips: list[str] = []
    static_findings, hit = cache_or_run(
        cache, s_key,
        lambda: _run_static_recorded(diff.target, static_skips, ev, config))
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
    if provider is None and not static_only:
        # `model` (the --model flag) enters at the CLI tier of the §8 resolution
        # order, so it outranks the configured default but still passes the
        # data-governance gate.
        provider, resolve_warnings = resolve_primary(config, cli_model=model)
        notes += resolve_warnings
        for w in resolve_warnings:
            ev.warning(w, stage="provider")
    # Route this provider's model-API egress through the broker (§8 + §9a): one
    # audit log, one forbidden-address block. Honors the operator allow-list.
    if not static_only and getattr(provider, "broker", None) is None:
        from .providers.egress import provider_broker_from_config
        try:
            provider.broker = provider_broker_from_config(config)
        except AttributeError:
            pass  # a provider that doesn't accept a broker (e.g. a test stub)
    if not static_only:
        # Nothing is going to reach the network, so there is no egress to watch
        # and no provider to wire a broker into.
        _watch_egress(provider, ev)

    if static_only:
        # The caller asked for the scanners and nothing else. Recorded like any
        # other stage that did not run — but with its own reason, because "you
        # did not ask for this" and "it could not run" are different facts and a
        # report that blamed a missing API key here would be a lie.
        reason = ("model review not requested (static scanners only) — "
                  "ask for it to include the model")
        skipped.append(reason)
        ev.stage_skipped("provider", reason)
        ev.stage_skipped("context", "no model review requested — context not built")
        ev.stage_skipped("llm", reason)
    elif provider.available():
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
        elif (size := _single_prompt_size(diff, context)) > MAX_SINGLE_PROMPT_CHARS:
            # A single-prompt review sends the whole target in one message. On a
            # whole-tree scan of a large repo that is tens of megabytes — orders
            # of magnitude past any context window — and the provider rejects it
            # only *after* cosmo has built it and retried with backoff. Refuse
            # up front, and name the flag that does work at this size.
            reason = (f"model:{provider.name} (target too large for a single "
                      f"prompt: ~{size // 1000}k chars over {len(diff.files)} "
                      f"file(s), limit ~{MAX_SINGLE_PROMPT_CHARS // 1000}k — "
                      f"re-run with --audit to review file by file)")
            skipped.append(reason)
            ev.stage_skipped("llm", reason)
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
        # Name the provider actually tried and what *it* is missing, plus the
        # alternatives — a message hard-coded to ANTHROPIC_API_KEY reads as if
        # Claude were the only model cosmo can drive.
        reason = describe_unavailable(provider)
        skipped.append(reason)
        ev.stage_skipped("provider", reason)
        ev.stage_skipped("context", "no reviewer available — review context not built")
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


# Ceiling for the single-prompt review path, in characters (~150k tokens). Well
# under any current context window, and far enough below it that the provider
# fails on content rather than length. `--audit` is the path that scales past it:
# it reviews file by file under its own call budget.
MAX_SINGLE_PROMPT_CHARS = 600_000


def _single_prompt_size(diff, context: str) -> int:
    """Estimate the single-prompt review's size without building it.

    Mirrors `build_review_prompt`: the raw diff when there is one, otherwise the
    added lines it reconstructs, plus the context block.
    """
    if diff.raw:
        return len(diff.raw) + len(context)
    # Per file a "--- {path}" header, per line a "+{lineno}: " prefix. Deliberately
    # an approximation: it exists to catch an overflow that is orders of magnitude
    # past the limit, not to predict the prompt to the byte.
    return len(context) + sum(
        len(f.path) + 5 + sum(len(text) + 8
                              for h in f.hunks for _, text in h.added)
        for f in diff.files
    )


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
                         ev: Emitter | None = None,
                         config: Config | None = None) -> list[Finding]:
    """Run the static pre-filter, appending its skipped-stage notes."""
    ev = ev or Emitter(None)
    static_findings, static_skipped = run_static_prefilter(target, events=ev,
                                                           config=config)
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


# Corroboration is evidence, but a small amount of it: two tools agreeing makes a
# finding more likely real, not certain. Capped so that stacking scanners can
# never push a pattern match up to the confidence of a reproduced one.
CORROBORATION_BONUS = 0.05
MAX_CORROBORATED_CONFIDENCE = 0.95


def _stamp_corroboration(kept: Finding, sources: list[str]) -> Finding:
    """Record the other tools that reported the same thing.

    Without this, running seven scanners looks like running one: the duplicates
    collapse into the highest-severity report and every other tool's agreement
    is thrown away. Agreement is the most useful signal a multi-tool setup
    produces — it is what separates a finding worth opening from a pattern match.
    """
    others: list[str] = []
    for src in sources:
        if src != kept.source and src not in others:
            others.append(src)
    if not others:
        return kept

    # Only *independent* agreement counts toward confidence. opengrep inherits
    # semgrep's rules, so the two firing together is one opinion, not two.
    independent = ({source_family(s) for s in others}
                   - {source_family(kept.source)})
    evidence = kept.evidence
    note = "also reported by: " + ", ".join(others)
    kept.evidence = f"{evidence}\n{note}" if evidence.strip() else note
    if independent:
        kept.confidence = min(MAX_CORROBORATED_CONFIDENCE,
                              kept.confidence + CORROBORATION_BONUS * len(independent))
    return kept


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Coarse dedupe by (file, line, category); the real aggregator (§11) is richer.

    With several scanners running, most duplicates are the *same* vulnerability
    seen by different tools, so the survivor carries their agreement forward
    rather than the run silently discarding it.
    """
    seen: dict[tuple, Finding] = {}
    sources: dict[tuple, list[str]] = {}
    for f in findings:
        key = (f.file, f.line, f.category or f.title)
        sources.setdefault(key, []).append(f.source)
        cur = seen.get(key)
        if cur is None or f.severity > cur.severity:
            seen[key] = f
    return [_stamp_corroboration(f, sources[k]) for k, f in seen.items()]
