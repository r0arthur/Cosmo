"""Severity model and threshold logic (build step 2).

One ordered scale used by every source (static, model, …) so the aggregator
and the threshold floor can compare findings uniformly.
"""
from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # noqa: D105
        return self.name.lower()

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper()
        # Common aliases from external tools (semgrep uses WARNING/ERROR, etc.).
        aliases = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "INFO",
            "NOTE": "LOW",
            "MODERATE": "MEDIUM",
        }
        key = aliases.get(key, key)
        try:
            return cls[key]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown severity: {value!r}") from exc


def meets_threshold(sev: Severity, floor: Severity) -> bool:
    """True if `sev` is at or above the configured severity floor."""
    return sev >= floor
