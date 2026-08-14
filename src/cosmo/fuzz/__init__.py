"""Zero-day fuzzing campaign (architecture §7, build step 16).

A separate, heavier, **manual-only** capability (`cosmo fuzz`) for surfacing
genuinely unknown vulnerabilities against cosmo's *own sandboxed build*. Never
on any default path; no scheduler, no daemon; a hard duration cap; always tears
down. Load-bearing constraints carried from the design review:

- **Hard scope constraint** — no code path accepts an external URL as a target;
  only the sandbox's internal instance, all egress through the broker (§9a) in
  SANDBOX mode.
- **Novelty is never asserted** — a crash the check can't match a known CVE/issue
  is *unverified-novel*, not "novel"; matches only flag likely duplicates.
- **Coverage is never assumed** — the campaign runs against the fraction of
  entry points whose harness actually built, surfaced explicitly.
- **Duration is never silently defaulted** — an unset duration prompts; the cap
  is a safety-tier config a repo can only lower.
"""
from .campaign import (
    CampaignPlan,
    CampaignResult,
    ConfirmationRequired,
    DurationNotSet,
    ExternalTargetRefused,
    resolve_duration,
    run_campaign,
)
from .corpus import SeedCorpus
from .engines import Engine, NoEngineForLanguage, build_invocation, select_engine
from .harness import EntryPoint, Harness, HarnessSet, generate_harnesses
from .novelty import NoveltyResult, NoveltyVerdict, novelty_check
from .triage import Crash, classify_severity, dedupe_crashes, minimize

__all__ = [
    "run_campaign", "resolve_duration", "CampaignResult", "CampaignPlan",
    "DurationNotSet", "ConfirmationRequired", "ExternalTargetRefused",
    "EntryPoint", "Harness", "HarnessSet", "generate_harnesses",
    "select_engine", "build_invocation", "Engine", "NoEngineForLanguage",
    "SeedCorpus",
    "Crash", "dedupe_crashes", "minimize", "classify_severity",
    "novelty_check", "NoveltyResult", "NoveltyVerdict",
]
