"""Request log (architecture §9a / §9).

Every decision is logged HERE, at the chokepoint, so a tool that forgets to log
cannot sidestep it. This log doubles as the record a bug-bounty program owner
may ask for. Records are append-only; an optional JSONL sink persists them.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

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
        self.records.append(rec)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as fh:
                fh.write(json.dumps(asdict(rec)) + "\n")
        return rec
