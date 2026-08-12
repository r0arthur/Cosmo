"""Model provider interface (architecture §8).

Common shape across backends:  review(diff, context, findings_so_far) -> Finding[]

The MVP ships only the Claude default (built into build step 1). The full
provider *layer* — hosted alternates, resolution order, ensemble cross-check,
and the data-governance boundary that governs exporting source to third parties
— is build step 9, out of MVP scope.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..diff import Diff
from ..findings import Finding


@runtime_checkable
class ModelProvider(Protocol):
    name: str

    def available(self) -> bool:
        """True if this provider can actually run (SDK importable, key present)."""
        ...

    def review(self, diff: Diff, context: str, findings_so_far: list[Finding]) -> list[Finding]:
        ...
