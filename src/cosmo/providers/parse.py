"""Shared parsing of a model's JSON finding array into Finding objects.

Every provider returns the same JSON contract, so the parse lives once here
rather than in each provider.
"""
from __future__ import annotations

import json

from ..findings import ConfirmationStatus, Finding
from ..severity import Severity

REVIEW_SYSTEM_PROMPT = (
    "You are a security code reviewer. Review ONLY the added lines in the diff. "
    "Report high-signal security issues (injection, authz, SSRF, secrets, unsafe "
    "deserialization, path traversal, etc.). Do not flag style or pre-existing code. "
    "Respond with a JSON array; each item: "
    '{"title","severity"(critical|high|medium|low|info),"file","line",'
    '"category"(CWE id if known),"exploit_scenario","remediation",'
    '"security_sensitive"(true|false),"confidence"(0..1)}. '
    "Return [] if nothing qualifies."
)


def parse_findings_json(text: str, source: str) -> list[Finding]:
    text = (text or "").strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        return []
    try:
        rows = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return []
    out: list[Finding] = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict):
            continue
        out.append(
            Finding(
                id=f"{source}-{i}",
                title=str(r.get("title", "Unnamed model finding")),
                severity=Severity.parse(r.get("severity", "medium")),
                source=source,
                file=str(r.get("file", "")),
                line=int(r.get("line", 0) or 0),
                confidence=float(r.get("confidence", 0.5) or 0.5),
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category=r.get("category"),
                exploit_scenario=str(r.get("exploit_scenario", "")),
                remediation=str(r.get("remediation", "")),
                security_sensitive=r.get("security_sensitive"),  # None → gate fails closed
            )
        )
    return out


def build_review_prompt(diff, context: str, findings_so_far) -> str:
    already = ", ".join(f"{f.file}:{f.line} {f.title}" for f in findings_so_far)
    raw = diff.raw or "\n".join(
        f"--- {f.path}\n" + "\n".join(f"+{ln}: {txt}" for h in f.hunks for ln, txt in h.added)
        for f in diff.files
    )
    parts = [f"# Diff for {diff.target}", raw]
    if context:
        parts += ["\n# Context", context]
    if already:
        parts += ["\n# Findings so far:", already]
    return "\n".join(parts)
