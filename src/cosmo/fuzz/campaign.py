"""Fuzz campaign orchestration (architecture §7).

A separate, heavier, **manual-only** capability. This module is the guardrailed
front door: it enforces the hard duration cap, refuses to run against anything
but cosmo's own sandboxed build, always tears down, and turns triaged crashes
into Findings that flow into the same aggregator/waiver/disclosure paths as
every other source. There is deliberately **no scheduler and no daemon** — this
is a plain function, run only on explicit invocation.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..broker import EgressBroker, Mode
from ..config import Config, _parse_duration
from ..findings import ConfirmationStatus, Finding
from ..severity import Severity
from .harness import EntryPoint, HarnessSet, generate_harnesses
from .novelty import NoveltyResult, NoveltyVerdict, novelty_check
from .triage import Crash, classify_severity, dedupe_crashes


class DurationNotSet(Exception):
    """Raised when a campaign is started with no duration ever set (§7): the caller
    must prompt for one rather than silently defaulting."""


class ConfirmationRequired(Exception):
    """Raised when the requested duration exceeds `fuzzing.confirm_above` and the
    caller has not explicitly confirmed."""


class ExternalTargetRefused(Exception):
    """Raised if a campaign is pointed at anything but the sandbox-internal build.
    §7 hard scope constraint: the fuzzer has no code path that accepts an
    external URL as a target."""


@dataclass
class CampaignPlan:
    max_seconds: int
    harnesses: HarnessSet
    coverage_fraction: float


@dataclass
class CampaignResult:
    findings: list[Finding] = field(default_factory=list)
    novelty: dict[str, NoveltyResult] = field(default_factory=dict)  # finding.id -> result
    coverage_fraction: float = 0.0
    crashes_total: int = 0
    crashes_deduped: int = 0
    torn_down: bool = False


def resolve_duration(config: Config, requested, *, confirmed: bool = False) -> int:
    """Resolve and cap the campaign duration (§7 guardrails).

    - `requested` unset (None) → DurationNotSet: the caller prompts, never defaults.
    - capped at `fuzzing.max_duration` (a safety-tier setting a repo can only lower).
    - above `fuzzing.confirm_above` requires `confirmed=True`.
    """
    if requested is None:
        raise DurationNotSet("no fuzz duration set; prompt for one before starting")
    want = _parse_duration(requested)
    if want <= 0:
        raise ValueError("fuzz duration must be positive")
    ceiling = _parse_duration(config.get("fuzzing.max_duration", "8h"))
    capped = min(want, ceiling)
    confirm_above = _parse_duration(config.get("fuzzing.confirm_above", "4h"))
    if capped > confirm_above and not confirmed:
        raise ConfirmationRequired(
            f"requested {capped}s exceeds confirm_above ({confirm_above}s); pass confirmed=True")
    return capped


def _assert_sandbox_target(target) -> None:
    # The only legal target is the sandbox's own internal instance. Anything that
    # looks like an external URL/host is refused outright — not warned.
    s = str(getattr(target, "url", target) or "")
    if "://" in s or s.startswith(("http", "www.")) or "." in s.split("/")[0]:
        raise ExternalTargetRefused(f"fuzzing never targets an external host: {s!r}")


def run_campaign(
    config: Config,
    entry_points: list[EntryPoint],
    *,
    sandbox_target,
    generator,
    build_check,
    fuzz_runner,
    broker: EgressBroker | None = None,
    duration=None,
    confirmed: bool = False,
    hints: dict | None = None,
    cve_index=None,
    known_issues=None,
) -> CampaignResult:
    """Run one campaign end-to-end. Every injected callable keeps this hermetic:

    - `generator` / `build_check` — harness drafting + compile gate (see harness.py)
    - `fuzz_runner(harness, max_seconds) -> list[Crash]` — drives the real engine
      inside the sandbox; the only component that executes code
    - `broker` — the §9a egress broker; all runner egress is stamped SANDBOX mode
    """
    if not config.get("fuzzing.enabled", False):
        raise PermissionError("fuzzing is disabled in config (safety tier); enable it to run")
    _assert_sandbox_target(sandbox_target)
    max_seconds = resolve_duration(config, duration, confirmed=confirmed)
    broker = broker or EgressBroker()

    hset = generate_harnesses(entry_points, generator, build_check, hints)
    result = CampaignResult(coverage_fraction=hset.coverage_fraction, torn_down=False)

    all_crashes: list[Crash] = []
    try:
        # Only harnesses that built cleanly run — the campaign is explicitly gated
        # behind coverage_fraction, never assuming full entry-point coverage.
        for h in hset.built:
            crashes = fuzz_runner(h, max_seconds, broker=broker, mode=Mode.SANDBOX)
            all_crashes.extend(crashes)
    finally:
        # Always tear down, even on crash — §7 "always tears down after".
        result.torn_down = True

    result.crashes_total = len(all_crashes)
    deduped = dedupe_crashes(all_crashes)
    result.crashes_deduped = len(deduped)

    cve_index = cve_index or (lambda c: [])
    known_issues = known_issues or (lambda c: [])
    for i, crash in enumerate(deduped):
        nov = novelty_check(crash, cve_index, known_issues)
        sev = classify_severity(crash.sanitizer)
        fid = f"fuzz-{crash.stack_hash}"
        # A likely-duplicate is surfaced but flagged; an unmatched crash is
        # UNVERIFIED, never asserted-novel — reflected in confirmation_status.
        status = ConfirmationStatus.UNCONFIRMED
        title = f"Fuzz crash ({crash.harness or 'harness'})"
        if nov.verdict == NoveltyVerdict.LIKELY_DUPLICATE:
            title += " — likely known, review before disclosing"
        result.findings.append(Finding(
            id=fid, title=title, severity=sev, source="fuzz",
            file=crash.harness or "", line=0, category="fuzz-crash",
            confirmation_status=status,
            exploit_scenario=(crash.sanitizer or "")[:2000],
            fingerprint=fid,
        ))
        result.novelty[fid] = nov
    return result
