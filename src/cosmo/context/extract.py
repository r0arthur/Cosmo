"""Signal extraction from ingested context (architecture §4).

Pulls the security-relevant signal out of issue/comment text: keywords, CVE
references, stack-trace indicators, and referenced file paths. Output is
structured data — never raw text passed downstream — so attacker-controlled
prose can't ride into the reviewer's prompt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ingest import ContextItem

SECURITY_KEYWORDS = {
    "crash", "overflow", "injection", "sqli", "xss", "ssrf", "rce", "csrf",
    "bypass", "traversal", "deserialization", "deserialize", "auth", "authz",
    "privilege", "escalation", "leak", "exfil", "exploit", "poc", "cve",
    "unsafe", "sanitize", "validation", "corruption", "use-after-free",
}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# path-ish token: an optional dir path plus a filename with an alpha extension
# (matches both "api/search.py" and a bare "search.py"; alpha ext avoids "1.2.3").
_PATH_RE = re.compile(r"[\w./-]*\w+\.[A-Za-z]{1,5}\b")
_STACK_HINTS = (
    "traceback (most recent call last)", "at java.", ".java:", "panic:",
    "goroutine ", "segmentation fault", "stack backtrace", "\n  at ",
)


@dataclass
class ExtractedSignal:
    item_id: str
    state: str
    keywords: set[str] = field(default_factory=set)
    cve_ids: set[str] = field(default_factory=set)
    has_stack_trace: bool = False
    mentioned_paths: set[str] = field(default_factory=set)

    @property
    def security_weight(self) -> float:
        """How strongly this item signals a security concern (0..~1)."""
        w = 0.2 * len(self.keywords) + 0.3 * len(self.cve_ids)
        if self.has_stack_trace:
            w += 0.2
        return min(1.0, w)


def extract_signal(item: ContextItem) -> ExtractedSignal:
    text = f"{item.title}\n{item.body}"
    low = text.lower()
    return ExtractedSignal(
        item_id=item.id,
        state=item.state,
        keywords={k for k in SECURITY_KEYWORDS if k in low},
        cve_ids={c.upper() for c in _CVE_RE.findall(text)},
        has_stack_trace=any(h in low for h in _STACK_HINTS),
        mentioned_paths=set(_PATH_RE.findall(text)),
    )


def extract_all(items: list[ContextItem]) -> list[ExtractedSignal]:
    return [extract_signal(i) for i in items]
