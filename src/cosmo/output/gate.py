"""Public-comment gate (architecture §12, RISK-05).

Hard constraint on any PUBLIC output (PR/issue comment, Check annotation),
driven automatically by severity + confirmation_status + security_sensitive —
never a per-instance judgment call.

**Fail-closed default (RISK-05):** the "post full detail" path applies only on an
affirmative `security_sensitive is False`. Unknown/uncertain sensitivity
(`None`) is treated as sensitive and withheld. A misclassification therefore
costs a redundant private disclosure, never a public PoC leak.

This gate governs only PUBLIC channels. Local CLI / SARIF output is for the
operator and always shows full detail.
"""
from __future__ import annotations

from enum import Enum

from ..findings import ConfirmationStatus, Finding
from ..severity import Severity


class PublicDecision(str, Enum):
    POST_FULL = "post_full"        # safe to post with full technical detail
    ACKNOWLEDGE_ONLY = "acknowledge_only"  # generic ack, no detail/PoC/severity
    WITHHOLD = "withhold"          # nothing public; route to coordinated disclosure (§13)


def public_gate(f: Finding) -> PublicDecision:
    # Confirmed, exploitable, unpatched → never public (routed to §13). In the MVP
    # nothing reaches CONFIRMED (no sandbox), but the rule is enforced now.
    if f.confirmation_status is ConfirmationStatus.CONFIRMED and f.severity >= Severity.HIGH:
        return PublicDecision.WITHHOLD

    # Fail closed: only an explicit "not sensitive" earns full public detail.
    if f.security_sensitive is False:
        return PublicDecision.POST_FULL

    if f.security_sensitive is None:
        # Unknown sensitivity: withhold high+; low-sev unknowns get a bare ack.
        return PublicDecision.WITHHOLD if f.severity >= Severity.HIGH else PublicDecision.ACKNOWLEDGE_ONLY

    # security_sensitive is True but not (confirmed & high): don't leak detail publicly.
    return PublicDecision.ACKNOWLEDGE_ONLY
