"""Model provider interface (architecture §8).

Common shape across backends:  review(diff, context, findings_so_far) -> Finding[]

Each provider self-declares:
  * `roles`          — which pipeline roles it's eligible for, so a smaller/local
                       model isn't assumed interchangeable everywhere.
  * `vendor` /
    `exports_source` — the data-governance boundary (§8): enabling a hosted
                       provider exports the target's source to that vendor, which
                       the resolution layer gates on repo/org data sensitivity.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..diff import Diff
from ..findings import Finding

# Pipeline roles a provider can self-declare.
PRIMARY_REVIEW = "primary_review"
CROSS_CHECK = "cross_check"


@runtime_checkable
class ModelProvider(Protocol):
    name: str
    vendor: str            # "anthropic" | "openai" | "deepseek" | "local"
    exports_source: bool   # True if calling it sends the diff off-box to a third party
    roles: set[str]

    def available(self) -> bool:
        """True if this provider can actually run (SDK importable, key present)."""
        ...

    def review(self, diff: Diff, context: str, findings_so_far: list[Finding]) -> list[Finding]:
        ...
