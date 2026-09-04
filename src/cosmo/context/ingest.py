"""Context ingestion — issues/comments/discussions.

Pulls signal from the repo's human-generated history to PRIORITIZE review. Two
boundaries are load-bearing:

  * Reading is unrestricted (same access as cloning the repo); POSTING is gated
    separately, and this module never posts.
  * Issue/comment text is attacker-controllable — anyone can open an issue. So
    ingestion produces a structured *signal set* (keywords, CVEs, referenced
    paths), never ground truth and never raw untrusted text injected into the
    reviewer. It can only raise attention on an area; it can never create or
    suppress a finding.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Callable

_PR_REPO = re.compile(
    r"(?:https://github\.com/(?P<r1>[^/]+/[^/]+)/(?:pull|issues)/\d+"
    r"|(?P<r2>[^/\s#]+/[^/\s#]+)#\d+)"
)

# fetcher(repo, limit) -> list[ContextItem]
Fetcher = Callable[[str, int], "list[ContextItem]"]


@dataclass
class ContextItem:
    kind: str       # issue | comment | discussion
    id: str
    title: str
    body: str
    state: str      # open | closed
    url: str = ""


def repo_of(target: str) -> str | None:
    m = _PR_REPO.search(target.strip())
    if m:
        return m.group("r1") or m.group("r2")
    return None


def fetch_context(target: str, limit: int = 50, fetcher: Fetcher | None = None) -> tuple[list[ContextItem], list[str]]:
    repo = repo_of(target)
    if repo is None:
        return [], ["context: not a GitHub target — skipped"]
    fetcher = fetcher or _gh_fetch
    try:
        return fetcher(repo, limit), []
    except Exception as exc:
        return [], [f"context: fetch failed ({exc})"]


def _gh_fetch(repo: str, limit: int) -> list[ContextItem]:  # pragma: no cover - network
    out = subprocess.run(
        ["gh", "issue", "list", "--repo", repo, "--state", "all",
         "--json", "number,title,body,state,url", "--limit", str(limit)],
        capture_output=True, text=True, check=True,
    ).stdout
    items: list[ContextItem] = []
    for r in json.loads(out or "[]"):
        items.append(ContextItem(
            kind="issue", id=str(r.get("number", "")), title=r.get("title", ""),
            body=r.get("body", "") or "", state=r.get("state", "open").lower(), url=r.get("url", ""),
        ))
    return items
