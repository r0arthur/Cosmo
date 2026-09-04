"""Coordinated disclosure workflow (build step 18).

For confirmed, high-severity, unpatched findings from any source. cosmo **drafts
and queues** a private advisory to the maintainer contact from the repo's
SECURITY.md; **nothing leaves the machine without explicit human approval**, and
every send routes through the egress broker in DISCLOSURE mode so the
delivery target must be an operator-configured endpoint. CVE assignment is routed
via the maintainer/CNA, never self-announced. The queue and its status
(`queued`→`reported`→`acknowledged`→`patched`→`disclosed`) live in the findings
store. Triggered manually with `/disclose <finding-id>` from an interactive
session.
"""
from .draft import DisclosureDraft, draft_report
from .eligibility import Eligibility, is_disclosable
from .security_md import DisclosureContact, find_contact, parse_security_md
from .workflow import (
    ACKNOWLEDGED,
    DISCLOSED,
    PATCHED,
    QUEUED,
    REPORTED,
    ApprovalRequired,
    HumanApproval,
    NotEligible,
    advance_status,
    queue_disclosure,
    send_disclosure,
)

__all__ = [
    "is_disclosable", "Eligibility",
    "DisclosureContact", "parse_security_md", "find_contact",
    "DisclosureDraft", "draft_report",
    "queue_disclosure", "send_disclosure", "advance_status",
    "HumanApproval", "NotEligible", "ApprovalRequired",
    "QUEUED", "REPORTED", "ACKNOWLEDGED", "PATCHED", "DISCLOSED",
]
