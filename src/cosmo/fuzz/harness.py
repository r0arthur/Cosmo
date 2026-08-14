"""Fuzz harness generation (architecture §7).

One harness per entry point (exported function, API route, CLI parser, file
parser), LLM-assisted and informed by context-ingestion hints (§4). Scoped
**realistically**: reliable per-entry-point harness generation is OSS-Fuzz-scale
work, so this is a bounded experiment with an expected high failure rate. The
campaign ships gated behind whatever fraction of entry points actually produced
a harness that *builds cleanly* — coverage is never assumed to be complete.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EntryPoint:
    name: str
    kind: str                      # function | route | cli | file_parser
    language: str                  # python | c | cpp | go | jvm
    location: str = ""             # file:line, for the report
    priority: float = 0.0          # from §4 context prioritization


@dataclass
class Harness:
    entry_point: EntryPoint
    source: str
    builds: bool                   # did it compile/import cleanly?
    build_error: str = ""


@dataclass
class HarnessSet:
    """The gated result of a generation pass."""
    built: list[Harness] = field(default_factory=list)
    failed: list[Harness] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.built) + len(self.failed)

    @property
    def coverage_fraction(self) -> float:
        """Fraction of entry points with a cleanly-building harness. The campaign
        runs against `built` only — never against the full entry-point set as if
        every harness worked."""
        return len(self.built) / self.total if self.total else 0.0


def generate_harnesses(
    entry_points: list[EntryPoint],
    generator,
    build_check,
    hints: dict | None = None,
) -> HarnessSet:
    """Generate and gate harnesses.

    `generator(entry_point, hints) -> source` is the (LLM-assisted) drafter and
    `build_check(harness) -> (ok, error)` compiles/imports it. Both are injected
    so this stays hermetic and engine-agnostic. A harness that fails to build is
    recorded in `failed` and never handed to the campaign — the high failure
    rate is expected and surfaced, not hidden.
    """
    hints = hints or {}
    result = HarnessSet()
    # Prioritized entry points first — a bounded budget should spend on the
    # files that context-ingestion (§4) flagged as interesting.
    ordered = sorted(entry_points, key=lambda e: e.priority, reverse=True)
    for ep in ordered:
        try:
            source = generator(ep, hints)
        except Exception as exc:  # a drafter failure is just an unbuilt harness
            result.failed.append(Harness(ep, source="", builds=False,
                                         build_error=f"generation failed: {exc}"))
            continue
        ok, error = build_check(Harness(ep, source=source, builds=False))
        h = Harness(ep, source=source, builds=bool(ok), build_error="" if ok else error)
        (result.built if ok else result.failed).append(h)
    return result
