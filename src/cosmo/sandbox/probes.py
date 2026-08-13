"""Targeted confirmation probes and confirmation-status logic (architecture §6, RISK-04).

Probes are **non-destructive** (read/observe only — no write/delete/exfiltrate,
§6.3). That is a guarantee, not a guideline: a probe declared destructive is
rejected at construction.

Because a read-only probe *structurally cannot* exercise write-path,
state-corruption, or destructive-action classes, "didn't reproduce" is the
expected result for those classes — not evidence of a false positive. So each
probe records which classes it is *capable* of triggering, and only a
non-reproduction from a probe that could have triggered the finding's class
feeds the waiver system (§11). Everything else stays UNCONFIRMED at reduced
confidence, never waived (RISK-04).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..findings import ConfirmationStatus, Finding


@dataclass
class Probe:
    finding_id: str
    description: str
    can_trigger_classes: set[str] = field(default_factory=set)  # CWE/OWASP ids it could reproduce
    destructive: bool = False

    def __post_init__(self) -> None:
        if self.destructive:
            raise ValueError("sandbox probes must be non-destructive (§6.3): read/observe only")


@dataclass
class ConfirmationOutcome:
    status: ConfirmationStatus
    confidence_delta: float      # applied to the finding's confidence
    feeds_waiver: bool           # only True for a genuine false-positive signal
    evidence: str = ""


def evaluate(finding: Finding, probe: Probe, reproduced: bool | None, evidence: str = "") -> ConfirmationOutcome:
    """Map a probe result to a confirmation outcome.

    reproduced: True  -> the probe observed the vulnerable behavior
                False -> the probe ran and did NOT observe it
                None  -> the probe could not be run (couldn't safely test)
    """
    if reproduced is True:
        return ConfirmationOutcome(ConfirmationStatus.CONFIRMED, +0.4, feeds_waiver=False, evidence=evidence)

    if reproduced is None:
        # Couldn't safely test (e.g. needs a real third-party dependency).
        return ConfirmationOutcome(ConfirmationStatus.UNCONFIRMED, 0.0, feeds_waiver=False, evidence=evidence)

    # reproduced is False:
    could_have_triggered = bool(finding.category) and finding.category in probe.can_trigger_classes
    if could_have_triggered:
        # A probe that could have reproduced it didn't → genuine false-positive signal.
        return ConfirmationOutcome(
            ConfirmationStatus.NOT_REPRODUCIBLE, -0.3, feeds_waiver=True, evidence=evidence
        )
    # The probe can't reach this class; non-reproduction says nothing. Do not waive.
    return ConfirmationOutcome(
        ConfirmationStatus.UNCONFIRMED, -0.05, feeds_waiver=False,
        evidence=evidence or "probe cannot exercise this vuln class (read-only); left unconfirmed",
    )


def default_probe_for(finding: Finding) -> Probe:
    """A minimal read-only probe scoped to the finding's own class. Real per-class
    probe construction (§6.3) is a v2 spike; this keeps the confirmation contract."""
    classes = {finding.category} if finding.category else set()
    return Probe(
        finding_id=finding.id,
        description=f"read-only probe for {finding.title}",
        can_trigger_classes=classes,
    )
