"""PR/issue comment renderer — a PUBLIC channel.

Every finding passes through the public-comment gate (RISK-05) before it can
appear here. Confirmed-exploitable and unknown-sensitivity high-severity
findings are withheld with only a generic acknowledgment; their detail is routed
to coordinated disclosure (build step 18 — out of MVP scope, so here they
are simply withheld and counted).
"""
from __future__ import annotations

from ..findings import Report
from .gate import PublicDecision, public_gate


def render_pr_comment(report: Report) -> str:
    posted, acked, withheld = [], 0, 0
    for f in report.findings:
        if f.waived:
            continue
        decision = public_gate(f)
        if decision is PublicDecision.POST_FULL:
            posted.append(f)
        elif decision is PublicDecision.ACKNOWLEDGE_ONLY:
            acked += 1
        else:
            withheld += 1

    lines = ["## cosmo security review", ""]
    if not posted and not acked and not withheld:
        lines.append("No issues found at or above the configured threshold.")
        return "\n".join(lines)

    for f in sorted(posted, key=lambda x: x.severity, reverse=True):
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        lines.append(f"### {str(f.severity).upper()} — {f.title}")
        lines.append(f"{loc} · {f.source}" + (f" · {f.category}" if f.category else ""))
        if f.exploit_scenario:
            lines.append(f"\n{f.exploit_scenario}")
        if f.remediation:
            lines.append(f"\n**Fix:** {f.remediation}")
        lines.append("")

    gated = acked + withheld
    if gated:
        lines.append("---")
        lines.append(
            f"> {gated} additional finding(s) were withheld from this public comment by the "
            f"disclosure gate and routed to private coordinated disclosure. "
            f"No technical detail, PoC, or severity is shown here by design."
        )
    return "\n".join(lines)
