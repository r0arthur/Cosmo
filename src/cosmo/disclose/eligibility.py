"""Disclosure eligibility.

Coordinated disclosure is only for **confirmed, high-severity, unpatched**
findings — from any source (LLM review, dynamic confirmation, fuzzing, external-
target testing). This gate is deliberately strict: an unconfirmed or low-severity
finding never enters the disclosure workflow, so cosmo does not send a maintainer
an advisory for something it hasn't actually reproduced.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..findings import ConfirmationStatus, Finding
from ..severity import Severity


@dataclass(frozen=True)
class Eligibility:
    eligible: bool
    reason: str

    def __bool__(self) -> bool:
        return self.eligible


def is_disclosable(finding: Finding) -> Eligibility:
    if finding.confirmation_status != ConfirmationStatus.CONFIRMED:
        return Eligibility(False, "not confirmed — disclosure needs a reproduced finding, "
                                  "not a suspicion")
    if finding.severity < Severity.HIGH:
        return Eligibility(False, f"severity {finding.severity} below the HIGH disclosure floor")
    if finding.waived:
        return Eligibility(False, "waived — not an actionable finding")
    return Eligibility(True, "confirmed, high-severity, actionable")
