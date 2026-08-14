"""Novelty check (architecture §7).

Cross-references each deduplicated crash against the NVD/CVE database and the
repo's own issue tracker to **flag likely duplicates** — never to assert
novelty. Stack-hash-to-CVE matching is heuristic, not mechanical: a match means
"possibly already-known, review before disclosing," and a crash the check cannot
match is treated as *unverified-novel*, never asserted-novel. Nothing here is
allowed to stamp a crash as a confirmed new vulnerability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .triage import Crash


class NoveltyVerdict(str, Enum):
    LIKELY_DUPLICATE = "likely_duplicate"     # matched a known CVE / issue — review first
    UNVERIFIED_NOVEL = "unverified_novel"     # no match found — NOT the same as "novel"

    def __str__(self) -> str:
        return self.value


@dataclass
class NoveltyResult:
    verdict: NoveltyVerdict
    matches: list[str] = field(default_factory=list)   # CVE ids / issue refs that hint duplicate
    rationale: str = ""

    @property
    def asserted_novel(self) -> bool:
        # Intentionally always False. There is no code path that asserts novelty;
        # the strongest statement cosmo makes is "unverified-novel, review before
        # disclosing." Kept as an explicit property so callers can't misread the
        # verdict as a novelty claim.
        return False


def novelty_check(
    crash: Crash,
    cve_index,
    known_issues,
) -> NoveltyResult:
    """`cve_index(crash) -> list[str]` and `known_issues(crash) -> list[str]` are
    injected lookups (NVD mirror, `gh` issue search). Both only ever *flag*
    possible duplicates; absence of a match is explicitly weak evidence."""
    matches: list[str] = []
    try:
        matches += list(cve_index(crash) or [])
    except Exception:  # a lookup failure must not upgrade a crash to "novel"
        matches.append("cve-lookup-unavailable")
    try:
        matches += list(known_issues(crash) or [])
    except Exception:
        matches.append("issue-lookup-unavailable")

    real_matches = [m for m in matches if not m.endswith("-unavailable")]
    if real_matches:
        return NoveltyResult(
            NoveltyVerdict.LIKELY_DUPLICATE, matches=real_matches,
            rationale="stack-hash heuristically matched a known CVE/issue; review before disclosing",
        )
    unavailable = [m for m in matches if m.endswith("-unavailable")]
    rationale = "no known match found — unverified-novel, not a novelty claim"
    if unavailable:
        rationale += f" (note: {', '.join(unavailable)}, so 'no match' is weaker than usual)"
    return NoveltyResult(NoveltyVerdict.UNVERIFIED_NOVEL, matches=[], rationale=rationale)
