"""Ensemble cross-check (architecture §8).

Optional mode: high-severity findings from the primary reviewer are cross-checked
with a SECOND model, and agreement is required before they're surfaced as
high-confidence. Disagreement doesn't delete the finding — it lowers confidence
and flags it for human review, so a single model's false positive doesn't reach
"high-confidence" on its own and a single model's true positive isn't silently
dropped.

The cross-check provider is subject to the same data-governance gate as the
primary (see registry.vendor_allowed); absent an eligible second provider, the
review stays single-provider rather than fanning source out.
"""
from __future__ import annotations

from ..diff import Diff
from ..findings import Finding
from ..severity import Severity
from .base import CROSS_CHECK, ModelProvider


def _same_finding(a: Finding, b: Finding) -> bool:
    if a.file != b.file:
        return False
    if a.category and b.category:
        return a.category == b.category
    # No category to compare on → treat as agreement if the sinks are close.
    return abs(a.line - b.line) <= 3


def cross_check(
    findings: list[Finding],
    cross_provider: ModelProvider,
    diff: Diff,
    context: str = "",
    *,
    min_severity: Severity = Severity.HIGH,
) -> tuple[list[Finding], list[str]]:
    warnings: list[str] = []
    if CROSS_CHECK not in cross_provider.roles:
        warnings.append(f"provider {cross_provider.name!r} not eligible for cross_check — skipped")
        return findings, warnings
    if not cross_provider.available():
        warnings.append(f"cross-check provider {cross_provider.name!r} unavailable — skipped")
        return findings, warnings

    targets = [f for f in findings if f.severity >= min_severity]
    if not targets:
        return findings, warnings

    try:
        second = cross_provider.review(diff, context, [])
    except Exception as exc:
        warnings.append(f"cross-check provider {cross_provider.name!r} error: {exc} — skipped")
        return findings, warnings

    for f in targets:
        agreed = any(_same_finding(f, s) for s in second)
        if agreed:
            f.confidence = min(1.0, f.confidence + 0.2)
        else:
            f.confidence = max(0.0, f.confidence - 0.2)
            note = f"no cross-model agreement ({cross_provider.name})"
            f.evidence = (f.evidence + " | " + note).strip(" |") if f.evidence else note
    return findings, warnings
