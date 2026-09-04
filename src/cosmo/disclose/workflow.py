"""Coordinated disclosure workflow.

The hard property, from the design review: **cosmo drafts and queues; nothing
leaves the machine without explicit human approval**, and every send routes
through the egress broker in DISCLOSURE mode — so the delivery target must
be an operator-configured disclosure endpoint, not whatever a repo's SECURITY.md
happens to name.

Lifecycle in the findings store: `queued` (drafted, nothing sent) →
`reported` (approved + delivered) → `acknowledged` → `patched` → `disclosed`.
`queued` is cosmo's own pre-approval state; the four the architecture lists all
follow a human action.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..broker import EgressBroker, EgressDenied, Mode
from ..findings import Finding
from .draft import DisclosureDraft, draft_report
from .eligibility import is_disclosable
from .security_md import DisclosureContact

QUEUED = "queued"
REPORTED = "reported"
ACKNOWLEDGED = "acknowledged"
PATCHED = "patched"
DISCLOSED = "disclosed"
_ADVANCE = {ACKNOWLEDGED, PATCHED, DISCLOSED}


class NotEligible(Exception):
    """Finding does not meet the confirmed/high/unpatched bar for disclosure."""


class ApprovalRequired(Exception):
    """A send was attempted without explicit, matching human approval."""


@dataclass(frozen=True)
class HumanApproval:
    """An explicit human decision to send *this* draft. Deliberately not a bool:
    approval is tied to a specific finding and names who approved it, so a stray
    truthy value can never stand in for a person clicking 'send'."""
    finding_id: str
    approver: str


def queue_disclosure(store, target: str, finding: Finding, contact: DisclosureContact,
                     *, embargo_days: int = 90, now: float | None = None) -> DisclosureDraft:
    """Gate on eligibility, draft the advisory, and enqueue it as `queued`.
    Sends nothing. Raises NotEligible for anything below the disclosure bar."""
    elig = is_disclosable(finding)
    if not elig:
        raise NotEligible(elig.reason)
    if contact is None or contact.target is None:
        raise NotEligible("no disclosure contact resolved (SECURITY.md missing / operator unset)")
    draft = draft_report(finding, target, contact, embargo_days=embargo_days, now=now)
    store.upsert(target, finding, now=now)
    store.set_disclosure_status(target, draft.fingerprint, QUEUED)
    return draft


def send_disclosure(draft: DisclosureDraft, *, approval: HumanApproval | None,
                    broker: EgressBroker, store=None, target: str | None = None,
                    transport=None) -> tuple[int, str]:
    """Deliver a queued draft — only with explicit, matching human approval, and
    only through the broker's DISCLOSURE gate.

    Returns (status, resolved_endpoint). Raises ApprovalRequired without a
    matching approval (nothing is sent), or EgressDenied if the broker refuses
    the endpoint (e.g. a SECURITY.md host that is not an operator-configured
    disclosure endpoint)."""
    if approval is None or approval.finding_id != draft.finding_id:
        raise ApprovalRequired(
            f"disclosure of {draft.finding_id} requires explicit human approval for "
            f"this finding; nothing sent")
    endpoint = draft.contact.target
    # The broker enforces DISCLOSURE mode: only operator-configured endpoints,
    # never a forbidden internal address. This is the single guarded path out.
    status, _headers, _body = broker.request(Mode.DISCLOSURE, endpoint,
                                             tool="disclose", transport=transport)
    draft.approved = True
    if store is not None and target is not None:
        store.set_disclosure_status(target, draft.fingerprint, REPORTED)
    return status, endpoint


def advance_status(store, target: str, fingerprint: str, status: str) -> None:
    """Move a disclosure through the human-driven lifecycle states."""
    if status not in _ADVANCE:
        raise ValueError(f"status must be one of {sorted(_ADVANCE)}; got {status!r}")
    store.set_disclosure_status(target, fingerprint, status)
