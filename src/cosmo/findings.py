"""Normalized finding schema and Report (architecture §11).

Every source normalizes to this one shape regardless of origin, so there is no
N×M adapter problem between sources and output renderers.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

from .severity import Severity


class ConfirmationStatus(str, Enum):
    CONFIRMED = "confirmed"          # reproduced with evidence (needs the sandbox, §6 — v2)
    UNCONFIRMED = "unconfirmed"      # couldn't safely test (the only status the MVP emits)
    NOT_REPRODUCIBLE = "not_reproducible"  # probe ran, didn't match (§6/§11 — v2)


@dataclass
class Finding:
    """One normalized finding. Field order mirrors the §11 schema."""

    id: str
    title: str
    severity: Severity
    source: str                       # static | dynamic | fuzz | external | model:<name>
    file: str
    line: int                         # sink location (or 0 if file-level)

    confidence: float = 0.5           # 0..1
    confirmation_status: ConfirmationStatus = ConfirmationStatus.UNCONFIRMED
    category: Optional[str] = None    # CWE/OWASP, e.g. "CWE-89"
    evidence: str = ""                # request/response, stack trace, crash log
    exploit_scenario: str = ""        # plain language
    remediation: str = ""             # suggested patch or steps

    # Drives the public-comment gate (§12). None = UNKNOWN → gate fails closed (RISK-05).
    security_sensitive: Optional[bool] = None

    fingerprint: Optional[str] = None   # content/AST-based, set by the waiver stage (§11, RISK-07)
    waived: bool = False
    waived_reason: str = ""

    first_seen: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = str(self.severity)
        d["confirmation_status"] = self.confirmation_status.value
        return d


@dataclass
class Report:
    target: str
    findings: list[Finding]
    skipped_stages: list[str] = field(default_factory=list)  # e.g. "static:semgrep (not installed)"
    notes: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[str(f.severity)] = out.get(str(f.severity), 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "skipped_stages": self.skipped_stages,
            "notes": self.notes,
            "counts": self.counts,
        }
