"""Comprehensive Markdown report — the artifact you read after the scan.

The other renderers are deliberately lossy. `render_cli` fits a finding into two
or three terminal lines and trims every field to the window; the live UI's
verdict screen shows the top eight titles clipped to a column. Both are progress
displays. Neither is something you can triage from, hand to a maintainer, or
attach to a ticket — which is what this file is for.

Two rules it follows:

* **Nothing is truncated.** Every field the Finding carries is written in full.
  A report that clips the evidence is the problem it exists to solve.
* **Coverage comes before findings.** A reader who scrolls to the findings and
  stops must not be able to mistake "we looked and found ten" for "we ran three
  of eleven stages and found ten". The same honesty contract the CLI keeps.
"""
from __future__ import annotations

import os.path
import time
from datetime import datetime, timezone

from ..findings import Finding, Report
from ..severity import Severity

_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
          Severity.INFO)


def _rel(path: str, target: str) -> str:
    """Display a finding's path relative to the target, which the header names.

    A whole-tree run carries absolute paths; repeated in every location cell and
    every waive command they crowd out the part that identifies the file.
    """
    path = str(path or "")
    base = str(target or "").split("@")[0]
    try:
        if base and os.path.isabs(path) and os.path.commonpath(
                [os.path.abspath(base), path]) == os.path.abspath(base):
            return os.path.relpath(path, os.path.abspath(base))
    except (ValueError, OSError):
        pass
    return path


def _block(text: str) -> str:
    """Multi-line free text as an indented block, so it survives Markdown."""
    body = str(text).strip()
    return "\n".join(f"    {line}" for line in body.splitlines())


def _detail_table(f: Finding, target: str) -> list[str]:
    shown = _rel(f.file, target)
    loc = f"{shown}:{f.line}" if f.line else (shown or "(file-level)")
    rows = [
        ("Location", f"`{loc}`"),
        ("Severity", str(f.severity)),
        ("Source", f"`{f.source}`"),
        ("Confidence", f"{f.confidence:.0%}"),
        ("Status", f.confirmation_status.value),
    ]
    if f.category:
        rows.append(("Category", f.category))
    if f.security_sensitive is None:
        # RISK-05: unknown sensitivity fails closed at the public gate. Say so
        # here, or the reader wonders why a finding never reached a PR comment.
        rows.append(("Sensitivity", "unknown — withheld from public comments"))
    elif f.security_sensitive:
        rows.append(("Sensitivity", "sensitive — withheld from public comments"))
    if f.fingerprint:
        rows.append(("Fingerprint", f"`{f.fingerprint}`"))
    if f.waived:
        rows.append(("Waived", f.waived_reason or "(no reason recorded)"))

    out = ["| | |", "|---|---|"]
    out += [f"| **{k}** | {v} |" for k, v in rows]
    return out


def _finding_section(n: int, f: Finding, target: str) -> list[str]:
    out = [f"### {n}. {str(f.severity).upper()} — {f.title}", ""]
    out += _detail_table(f, target)
    out.append("")

    for label, text in (("Evidence", f.evidence),
                        ("Exploit scenario", f.exploit_scenario),
                        ("Remediation", f.remediation)):
        if str(text).strip():
            out += [f"**{label}**", "", _block(text), ""]

    if f.fingerprint and not f.waived:
        out += ["**If this is a false positive**", "",
                _block(f'cosmo waive {target} {f.fingerprint} --reason "why"'), ""]
    return out


def render_report(report: Report, *, threshold: str = "",
                  elapsed: float | None = None, now: float | None = None) -> str:
    """A full Markdown report. Self-contained: no colour, no terminal width."""
    stamp = datetime.fromtimestamp(now if now is not None else time.time(),
                                   timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    actionable = [f for f in report.findings if not f.waived]
    waived = [f for f in report.findings if f.waived]

    out = ["# cosmo security report", ""]
    meta = [("Target", f"`{report.target}`"), ("Generated", stamp)]
    if threshold:
        meta.append(("Severity floor", threshold))
    if elapsed is not None:
        meta.append(("Elapsed", f"{int(elapsed) // 60:02d}:{int(elapsed) % 60:02d}"))
    meta.append(("Findings", f"{len(actionable)} actionable"
                             + (f", {len(waived)} waived" if waived else "")))
    out += [f"- **{k}:** {v}" for k, v in meta]
    out.append("")

    # --- coverage, before findings ------------------------------------------
    out += ["## Coverage", "",
            "What ran and what did not. A finding count is only as strong as the "
            "stages behind it.", ""]
    if report.skipped_stages:
        out.append(f"**{len(report.skipped_stages)} stage(s) did not run:**")
        out.append("")
        out += [f"- ⊘ {s}" for s in report.skipped_stages]
    else:
        out.append("- ✓ Every stage ran.")
    out.append("")
    if report.notes:
        out += ["**Notes**", ""]
        out += [f"- {n}" for n in report.notes]
        out.append("")

    # --- summary ------------------------------------------------------------
    counts = {}
    for f in actionable:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out += ["## Summary", ""]
    if counts:
        out += ["| Severity | Count |", "|---|---|"]
        out += [f"| {str(sev)} | {counts[sev]} |" for sev in _ORDER if sev in counts]
    else:
        out.append("No findings at or above the configured floor.")
    out.append("")

    # --- findings -----------------------------------------------------------
    if actionable:
        out += ["## Findings", ""]
        # Severity descending, then location ascending — reversing the whole
        # tuple would also sort files Z→A inside a severity band.
        ordered = sorted(actionable, key=lambda f: (-int(f.severity), f.file, f.line))
        for i, f in enumerate(ordered, 1):
            out += _finding_section(i, f, report.target)

    if waived:
        out += ["## Waived", "",
                "Suppressed by the baseline. Listed so a waiver cannot quietly "
                "become permanent.", ""]
        for f in waived:
            shown = _rel(f.file, report.target)
            loc = f"{shown}:{f.line}" if f.line else shown
            out.append(f"- **{str(f.severity).upper()}** {f.title} — `{loc}`"
                       + (f" — {f.waived_reason}" if f.waived_reason else ""))
        out.append("")

    return "\n".join(out).rstrip() + "\n"
