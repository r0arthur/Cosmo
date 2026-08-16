"""CLI text renderer (architecture §12) — the default, operator-facing output.

Local output shows full detail; the public-comment gate does not apply here.
"""
from __future__ import annotations

import sys

from ..findings import Report
from ..severity import Severity

_COLOR = {
    Severity.CRITICAL: "\033[41;97m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def render_cli(report: Report, color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty()

    def c(sev: Severity, text: str) -> str:
        return f"{_COLOR[sev]}{text}{_RESET}" if color else text

    lines: list[str] = [f"cosmo — {report.target}", "=" * 60]
    shown = [f for f in report.findings if not f.waived]
    if not shown:
        lines.append("No findings at or above the configured threshold.")
    for f in sorted(shown, key=lambda x: x.severity, reverse=True):
        tag = c(f.severity, f" {str(f.severity).upper():^8} ")
        lines.append(f"{tag} {f.title}")
        loc = f"{f.file}:{f.line}" if f.line else f.file
        meta = [loc, f.source]
        if f.category:
            meta.append(f.category)
        meta.append(f"conf={f.confidence:.0%}")
        lines.append(f"          {'  ·  '.join(meta)}")
        if f.exploit_scenario:
            lines.append(f"          ↳ {f.exploit_scenario}")
        if f.remediation:
            lines.append(f"          fix: {f.remediation}")
        lines.append("")

    counts = report.counts
    if counts:
        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        lines.append(f"Summary: {summary}")
    waived = sum(1 for f in report.findings if f.waived)
    if waived:
        lines.append(f"({waived} waived, suppressed)")
    for s in report.skipped_stages:
        lines.append(f"  skipped: {s}")
    # Operator-facing notes (coverage, cache reuse, audit budget, clamps). These
    # carry the "what did/didn't run" signal — e.g. the llm-audit coverage line —
    # so they must be visible, not just live on the Report object.
    for n in report.notes:
        lines.append(f"  note: {n}")
    return "\n".join(lines)
