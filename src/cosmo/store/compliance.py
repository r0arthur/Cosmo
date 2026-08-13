"""Compliance mapping (architecture §15).

Maps a finding's CWE (its `category`, when it carries one) to the OWASP Top 10
2021 category, so the trend store can report coverage against a recognised
framework. This is a *reporting* layer only — it never changes a finding's
severity or whether it surfaces. Unmapped CWEs (or non-CWE categories) fall
through to A04 "Insecure Design" rather than being dropped, and the operator can
supply an org framework mapping that is layered on top without editing code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# CWE -> OWASP Top 10 2021 identifier. Deliberately small and legible: the common
# review categories, not an exhaustive MITRE import. Extend via operator config.
_CWE_OWASP: dict[str, str] = {
    # A01 Broken Access Control
    "CWE-22": "A01", "CWE-284": "A01", "CWE-285": "A01", "CWE-639": "A01",
    "CWE-862": "A01", "CWE-863": "A01", "CWE-352": "A01",
    # A02 Cryptographic Failures
    "CWE-259": "A02", "CWE-321": "A02", "CWE-327": "A02", "CWE-328": "A02",
    "CWE-338": "A02", "CWE-798": "A02",
    # A03 Injection
    "CWE-77": "A03", "CWE-78": "A03", "CWE-79": "A03", "CWE-89": "A03",
    "CWE-90": "A03", "CWE-91": "A03", "CWE-94": "A03", "CWE-564": "A03",
    "CWE-943": "A03",
    # A04 Insecure Design (also the fallthrough)
    "CWE-209": "A04", "CWE-256": "A04", "CWE-501": "A04", "CWE-522": "A04",
    # A05 Security Misconfiguration
    "CWE-16": "A05", "CWE-611": "A05", "CWE-614": "A05", "CWE-756": "A05",
    # A06 Vulnerable and Outdated Components
    "CWE-1104": "A06", "CWE-937": "A06",
    # A07 Identification and Authentication Failures
    "CWE-287": "A07", "CWE-297": "A07", "CWE-384": "A07", "CWE-620": "A07",
    # A08 Software and Data Integrity Failures
    "CWE-345": "A08", "CWE-494": "A08", "CWE-502": "A08", "CWE-829": "A08",
    # A09 Security Logging and Monitoring Failures
    "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09", "CWE-778": "A09",
    # A10 Server-Side Request Forgery
    "CWE-918": "A10",
}

_OWASP_NAMES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

_FALLBACK = "A04"
_CWE_RE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def normalize_cwe(category: str | None) -> str | None:
    """Return a canonical 'CWE-<n>' from a category string, or None."""
    if not category:
        return None
    m = _CWE_RE.search(category)
    return f"CWE-{int(m.group(1))}" if m else None


def owasp_for(category: str | None, extra: dict[str, str] | None = None) -> str:
    """Map a finding category (typically a CWE) to an OWASP 2021 id.

    `extra` is an operator-supplied CWE->OWASP override layered on top of the
    built-in table. Anything unmapped falls through to A04 (Insecure Design)
    rather than vanishing from the compliance rollup.
    """
    cwe = normalize_cwe(category)
    if cwe is None:
        return _FALLBACK
    if extra and cwe in extra:
        return extra[cwe]
    return _CWE_OWASP.get(cwe, _FALLBACK)


def owasp_name(owasp_id: str) -> str:
    return _OWASP_NAMES.get(owasp_id, owasp_id)


@dataclass
class ComplianceRow:
    owasp_id: str
    name: str
    count: int


def map_report(findings, extra: dict[str, str] | None = None) -> list[ComplianceRow]:
    """Roll findings up into OWASP Top 10 categories, most-hit first.

    `findings` is any iterable of objects with a `.category` attribute (Finding)
    or of mapping rows with a 'category' key (trend-store rows).
    """
    counts: dict[str, int] = {}
    for f in findings:
        # Finding dataclass (attribute) or a mapping/sqlite3.Row (subscript).
        if hasattr(f, "category"):
            category = f.category
        else:
            try:
                category = f["category"]
            except (KeyError, IndexError, TypeError):
                category = None
        oid = owasp_for(category, extra)
        counts[oid] = counts.get(oid, 0) + 1
    rows = [ComplianceRow(oid, owasp_name(oid), n) for oid, n in counts.items()]
    return sorted(rows, key=lambda r: (-r.count, r.owasp_id))
