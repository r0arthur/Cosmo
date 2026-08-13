"""Turn extracted signals into prioritization hints (architecture §4).

Two outputs, both prioritization-only — never ground truth:

  * path boosts: files referenced by security-relevant issues get a small
    confidence nudge on findings already located there. Boosts only ever RAISE
    attention; a malicious issue can add noise to an area it names, but can never
    lower confidence, suppress a finding, or create one.
  * partial-fix hints: a closed/fixed issue that touched a changed file is a
    prompt to check whether the same pattern exists elsewhere — a hint, not an
    assumption of vulnerability (§4).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..findings import Finding
from .extract import ExtractedSignal

_MAX_BOOST = 0.15  # cap: context can nudge prioritization, not dominate it


def _path_hits_file(mentioned: str, changed_file: str) -> bool:
    mb, cb = os.path.basename(mentioned), os.path.basename(changed_file)
    return mentioned == changed_file or mb == cb or changed_file.endswith(mentioned)


@dataclass
class PrioritySignals:
    path_boosts: dict[str, float] = field(default_factory=dict)
    path_reasons: dict[str, list[str]] = field(default_factory=dict)
    keywords: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    partial_fix_hints: list[str] = field(default_factory=list)


def build_priority_signals(signals: list[ExtractedSignal], changed_files: list[str]) -> PrioritySignals:
    out = PrioritySignals()
    for sig in signals:
        out.keywords |= sig.keywords
        out.cves |= sig.cve_ids
        weight = sig.security_weight
        if weight <= 0:
            continue
        for mentioned in sig.mentioned_paths:
            for cf in changed_files:
                if _path_hits_file(mentioned, cf):
                    out.path_boosts[cf] = min(_MAX_BOOST, out.path_boosts.get(cf, 0.0) + weight * _MAX_BOOST)
                    out.path_reasons.setdefault(cf, []).append(
                        f"issue #{sig.item_id} ({', '.join(sorted(sig.keywords)) or 'security-relevant'})"
                    )
                    if sig.state == "closed":
                        out.partial_fix_hints.append(
                            f"closed issue #{sig.item_id} referenced {cf}; verify the same "
                            f"pattern isn't present elsewhere (partial-fix check)"
                        )
    return out


def _boost_for(file: str, priority: PrioritySignals) -> tuple[float, list[str]]:
    """Match a finding's file against boosted paths by basename, so a relative
    finding path lines up with an absolute diff path (and vice versa)."""
    best, reasons = 0.0, []
    for path, boost in priority.path_boosts.items():
        if _path_hits_file(file, path) or _path_hits_file(path, file):
            best = max(best, boost)
            reasons += priority.path_reasons.get(path, [])
    return best, reasons


def apply_prioritization(findings: list[Finding], priority: PrioritySignals) -> list[Finding]:
    """Nudge confidence for findings in boosted files. Attention only — never
    suppresses, never creates. Returns findings sorted by prioritized weight."""
    for f in findings:
        boost, reasons = _boost_for(f.file, priority)
        if boost > 0:
            f.confidence = min(1.0, f.confidence + boost)
            note = f"prioritized by context: {'; '.join(reasons)}"
            f.evidence = (f.evidence + " | " + note).strip(" |") if f.evidence else note
    return sorted(findings, key=lambda x: (x.severity, x.confidence), reverse=True)
