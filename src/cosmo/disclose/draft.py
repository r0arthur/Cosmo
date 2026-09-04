"""Disclosure draft.

Builds the *private* advisory that would go to the maintainer contact. This is a
private channel to the maintainer, so — unlike the public-comment gate —
the draft includes the technical detail and PoC needed to reproduce and fix. It
is only ever a draft: producing one sends nothing. CVE is left `pending` because
assignment is routed through the maintainer or a CNA, never self-announced.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..findings import Finding
from .security_md import DisclosureContact


@dataclass
class DisclosureDraft:
    finding_id: str
    fingerprint: str
    target: str
    contact: DisclosureContact
    title: str
    body: str
    embargo_until: float
    cve: str = "pending"                 # routed via maintainer/CNA, never self-assigned
    created_at: float = field(default_factory=time.time)
    approved: bool = False               # flips only on explicit human approval


def draft_report(finding: Finding, target: str, contact: DisclosureContact,
                 embargo_days: int = 90, now: float | None = None) -> DisclosureDraft:
    now = now if now is not None else time.time()
    embargo_until = now + embargo_days * 86400
    body = _render(finding, target, embargo_until)
    return DisclosureDraft(
        finding_id=finding.id,
        fingerprint=finding.fingerprint or finding.id,
        target=target,
        contact=contact,
        title=f"[cosmo] {finding.severity} — {finding.title}",
        body=body,
        embargo_until=embargo_until,
    )


def _render(finding: Finding, target: str, embargo_until: float) -> str:
    from datetime import datetime, timezone
    embargo = datetime.fromtimestamp(embargo_until, tz=timezone.utc).date().isoformat()
    lines = [
        f"Private security report for {target}",
        f"Severity: {finding.severity}",
        f"Location: {finding.file}:{finding.line}",
        f"Category: {finding.category or 'n/a'}",
        "",
        "Summary:",
        finding.title,
        "",
        "Details / reproduction:",
        finding.exploit_scenario or finding.evidence or "(see attached reproducer)",
        "",
        "Suggested remediation:",
        finding.remediation or "(to be discussed)",
        "",
        f"Requested embargo until: {embargo} (CVE: pending — please route via CNA).",
        "This report was drafted by cosmo and is being sent only after explicit human approval.",
    ]
    return "\n".join(lines)
