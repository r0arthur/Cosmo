"""Request log.

Every decision is logged HERE, at the chokepoint, so a tool that forgets to log
cannot sidestep it. This log doubles as the record a bug-bounty program owner
may ask for. Records are append-only; an optional JSONL sink persists them.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .modes import Decision


@dataclass
class LogRecord:
    ts: float
    mode: str
    tool: str
    target: str
    resolved_host: str | None
    allowed: bool
    reason: str


@dataclass
class RequestLog:
    path: Path | None = None
    records: list[LogRecord] = field(default_factory=list)
    # One broker is shared by every concurrent model call (a whole-project audit
    # reviews several files at once), so two threads can land in `record` at the
    # same moment. Unguarded, their JSONL lines can interleave mid-write and
    # corrupt the very record a program owner may ask for.
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )
    # Optional read-only tap for a live UI. It observes the record the broker
    # already wrote — it never becomes a second, divergent log, and an observer
    # that raises must not lose the record, so it runs after the append.
    observer: Optional[Callable[[LogRecord], None]] = field(
        default=None, repr=False, compare=False
    )

    def record(self, decision: Decision, tool: str) -> LogRecord:
        rec = LogRecord(
            ts=time.time(),
            mode=str(decision.mode),
            tool=tool,
            target=decision.target,
            resolved_host=decision.resolved_host,
            allowed=decision.allowed,
            reason=decision.reason,
        )
        with self._lock:
            self.records.append(rec)
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as fh:
                    fh.write(json.dumps(asdict(rec)) + "\n")
        if self.observer is not None:
            try:
                self.observer(rec)
            except Exception:   # a broken UI tap must not fail a guarded request
                pass
        return rec
