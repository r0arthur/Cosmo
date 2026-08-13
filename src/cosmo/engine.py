"""Core engine (architecture §1, build step 1).

    run_review(target, config) -> Report

The single entry point every trigger adapter calls. Pipeline order follows the
architecture: static pre-filter first (§5), its output handed to the LLM as
context so the model doesn't re-derive it, then dedupe, then waiver suppression
(§11), then the severity floor.
"""
from __future__ import annotations

from .config import Config
from .context import ContextItem, apply_prioritization, build_priority_signals, extract_all, fetch_context
from .diff import resolve_diff
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
) -> Report:
    diff = resolve_diff(target)
    findings: list[Finding] = []
    skipped: list[str] = []
    notes: list[str] = list(config.warnings)  # surface config trust-tier clamps to the operator

    # Step 6 — static pre-filter (before the LLM stage, §5).
    static_findings, static_skipped = run_static_prefilter(diff.target)
    findings += static_findings
    skipped += static_skipped

    # Step 1 — LLM review. Provider resolved through the layer (§8): resolution
    # order + data-governance gate + fallback to the Claude default.
    if provider is None:
        provider, resolve_warnings = resolve_primary(config)
        notes += resolve_warnings
    if provider.available():
        context = _review_context(diff, static_findings, config, notes)
        try:
            findings += provider.review(diff, context, list(findings))
        except Exception as exc:  # never silently skip review (§8) — record it
            skipped.append(f"model:{provider.name} (error: {exc})")
    else:
        skipped.append(f"model:{provider.name} (unavailable — no SDK or ANTHROPIC_API_KEY)")

    findings = _dedupe(findings)

    # Step 5 — waiver/baseline suppression (fingerprints stamped here).
    baseline = Baseline.load(diff.target)
    findings = baseline.apply(findings, diff)

    # Step 11 — context ingestion: prioritize (never create/suppress) findings.
    findings = _apply_context(target, diff, findings, config, context_items, notes, skipped)

    # Severity floor (step 2 threshold). Waived findings are kept in the report
    # object (counted, not shown) so `--baseline` can list them.
    floor = Severity.parse(config.threshold)
    findings = [f for f in findings if f.waived or meets_threshold(f.severity, floor)]

    return Report(target=diff.target, findings=findings, skipped_stages=skipped, notes=notes)


def _static_context(static_findings: list[Finding]) -> str:
    return "\n".join(f"- {f.file}:{f.line} [{f.category or f.source}] {f.title}"
                     for f in static_findings)


def _review_context(diff, static_findings: list[Finding], config: Config, notes: list[str]) -> str:
    """Compose the LLM review context: static pre-filter output (§5) + matched
    skills (§10), with org skills trusted and repo skills framed as untrusted."""
    parts: list[str] = []
    sc = _static_context(static_findings)
    if sc:
        parts.append("## Static pre-filter already flagged (do not re-derive):\n" + sc)

    skills = load_skills(diff.target, org_dir=config.get("skills.org_dir"))
    matched = match_skills(skills, [f.path for f in diff.files])
    if matched:
        notes.append(f"skills matched: {len(matched)} "
                     f"({sum(1 for s in matched if not s.trusted)} repo/untrusted)")
        parts.append(build_skill_context(matched))
    return "\n\n".join(parts)


def _apply_context(target, diff, findings, config, context_items, notes, skipped):
    """Fetch (or use injected) context, extract signals, and nudge prioritization.

    Only runs for GitHub targets when enabled; degrades gracefully otherwise.
    Prioritization raises attention on referenced files — it never creates or
    suppresses a finding (§4)."""
    if not config.get("context_ingestion", {}).get("issues", True):
        return findings
    items = context_items
    if items is None:
        if diff.source != "github":
            return findings
        items, ctx_skipped = fetch_context(target)
        skipped += ctx_skipped
    if not items:
        return findings

    priority = build_priority_signals(extract_all(items), [f.path for f in diff.files])
    if priority.path_boosts:
        notes.append(f"context: prioritized {len(priority.path_boosts)} file(s) from "
                     f"{len(items)} issue(s)")
    for hint in priority.partial_fix_hints:
        notes.append(hint)
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
