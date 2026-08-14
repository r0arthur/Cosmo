"""SECURITY.md contact extraction (architecture §13).

The maintainer disclosure contact is read from the repo's SECURITY.md. That file
lives in the *scanned repo*, so it is **untrusted input** (RISK-03): whatever it
yields is a *candidate* delivery target, never an authorization to send. The
candidate still has to pass the egress broker's DISCLOSURE-mode endpoint
allowlist (operator-configured, safety tier) before anything leaves the machine —
a SECURITY.md pointing at an arbitrary host cannot exfiltrate an advisory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL_RE = re.compile(r"https?://[^\s>)\]]+")
_MAILTO_RE = re.compile(r"mailto:([\w.+-]+@[\w-]+\.[\w.-]+)")


@dataclass(frozen=True)
class DisclosureContact:
    email: str | None = None
    url: str | None = None
    source: str = "SECURITY.md"
    trusted: bool = False        # always False — a repo file is never trusted ground truth

    @property
    def target(self) -> str | None:
        """The delivery endpoint a broker request would be authorized against."""
        return self.url or (f"mailto:{self.email}" if self.email else None)


def parse_security_md(text: str) -> DisclosureContact | None:
    mailto = _MAILTO_RE.search(text)
    email = mailto.group(1) if mailto else (_EMAIL_RE.search(text).group(0)
                                            if _EMAIL_RE.search(text) else None)
    url_m = _URL_RE.search(text)
    url = url_m.group(0) if url_m else None
    if not email and not url:
        return None
    return DisclosureContact(email=email, url=url)


def find_contact(repo_dir: str | Path) -> DisclosureContact | None:
    """Look for SECURITY.md in the usual locations. Returns None if absent — the
    workflow then requires an operator-supplied contact rather than guessing."""
    root = Path(repo_dir)
    for rel in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        p = root / rel
        if p.is_file():
            return parse_security_md(p.read_text(errors="replace"))
    return None
