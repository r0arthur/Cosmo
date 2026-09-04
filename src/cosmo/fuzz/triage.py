"""Crash triage + dedup.

Stack-hash deduplication, input minimization to the smallest reproducer, and
severity classification from sanitizer / exception output. This is where a raw
pile of crashes becomes a small set of distinct, minimized, classified findings.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from ..severity import Severity


@dataclass
class Crash:
    reproducer: bytes                 # the input that triggered it
    stack: list[str] = field(default_factory=list)   # top frames, most-recent first
    sanitizer: str = ""               # raw ASan/UBSan block or exception text
    harness: str = ""

    @property
    def stack_hash(self) -> str:
        """Dedup key: the top frames normalized. Deliberately ignores addresses
        and the reproducer bytes so two inputs hitting the same bug collapse."""
        top = [_normalize_frame(f) for f in self.stack[:5]]
        return hashlib.sha256("\n".join(top).encode()).hexdigest()[:16]


_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
_OFFSET_RE = re.compile(r"\+0x[0-9a-fA-F]+|:\d+")


def _normalize_frame(frame: str) -> str:
    f = _ADDR_RE.sub("", frame)
    f = _OFFSET_RE.sub("", f)
    return f.strip()


# Sanitizer/exception class -> severity. Memory-safety corruption outranks a
# plain uncaught exception; this classification is heuristic and conservative.
_SANITIZER_SEVERITY = [
    (re.compile(r"heap-buffer-overflow|stack-buffer-overflow|use-after-free|double-free",
                re.I), Severity.CRITICAL),
    (re.compile(r"global-buffer-overflow|use-after-return|use-after-scope", re.I), Severity.HIGH),
    (re.compile(r"AddressSanitizer|SEGV|SIGSEGV|deadly signal", re.I), Severity.HIGH),
    (re.compile(r"UndefinedBehaviorSanitizer|integer-overflow|shift-exponent", re.I), Severity.MEDIUM),
    (re.compile(r"Uncaught exception|Traceback|panic:", re.I), Severity.MEDIUM),
    (re.compile(r"timeout|OOM|out-of-memory", re.I), Severity.LOW),
]


def classify_severity(sanitizer_output: str) -> Severity:
    for pat, sev in _SANITIZER_SEVERITY:
        if pat.search(sanitizer_output or ""):
            return sev
    return Severity.LOW


def dedupe_crashes(crashes: list[Crash]) -> list[Crash]:
    """Keep one representative per stack hash — the one with the *smallest*
    reproducer, since a minimized input is the more useful artifact."""
    best: dict[str, Crash] = {}
    for c in crashes:
        h = c.stack_hash
        if h not in best or len(c.reproducer) < len(best[h].reproducer):
            best[h] = c
    return list(best.values())


def minimize(crash: Crash, still_crashes) -> Crash:
    """Shrink the reproducer while `still_crashes(candidate_bytes) -> bool` holds.

    A simple, deterministic ddmin-style byte-chunk reduction. The oracle is
    injected so triage never itself executes the SUT — the campaign owns
    execution inside the sandbox; triage only decides *what* to try.
    """
    data = crash.reproducer
    chunk = max(1, len(data) // 2)
    while chunk >= 1:
        i = 0
        while i < len(data):
            candidate = data[:i] + data[i + chunk:]
            if candidate and still_crashes(candidate):
                data = candidate
            else:
                i += chunk
        if chunk == 1:
            break
        chunk //= 2
    return Crash(reproducer=data, stack=crash.stack, sanitizer=crash.sanitizer,
                 harness=crash.harness)
