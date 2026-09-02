"""Structured execution events (the layer the live UI renders).

`run_review` stays pure: it takes an optional `Emitter` and reports what it is
doing, but nothing here can change what it *does*. With no sink attached every
call is a couple of attribute lookups, so the instrumented path and the silent
path are the same code.

The stage list below is the review pipeline as `engine.run_review` actually
executes it — it is the single source of truth the UI draws its workflow from,
so a stage added to the engine without a line here will show up as untracked
rather than silently missing.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Kind(str, Enum):
    """What a line in the activity feed represents."""

    OBJECTIVE_STARTED = "objective_started"
    OBJECTIVE_COMPLETED = "objective_completed"
    STAGE_STARTED = "stage_started"
    STAGE_COMPLETED = "stage_completed"
    STAGE_SKIPPED = "stage_skipped"
    OPERATION = "operation"        # a sub-step inside a stage
    EXECUTE = "execute"            # a subprocess cosmo ran
    OUTPUT = "output"              # what came back
    READ = "read"
    WRITE = "write"
    API_REQUEST = "api_request"    # a model call crossing the broker
    FINDING = "finding"
    WARNING = "warning"
    ERROR = "error"

    def __str__(self) -> str:  # noqa: D105
        return self.value


# The review pipeline, in execution order (engine.run_review). `id` is what the
# engine emits; `label` is what the user reads.
STAGES: tuple[tuple[str, str], ...] = (
    ("resolve", "Resolve target into a reviewable diff"),
    ("cache", "Load incremental cache"),
    ("static", "Static pre-filter (semgrep, gitleaks, bandit, trivy, …)"),
    ("provider", "Resolve model provider + egress broker"),
    ("context", "Build review context (static + skills)"),
    ("llm", "AI security review"),
    ("extensions", "Custom extension detectors"),
    ("dedupe", "Deduplicate findings"),
    ("waiver", "Apply waivers and baseline"),
    ("priority", "Prioritize from issue context"),
    ("threshold", "Apply severity floor"),
)

# A commit-history sweep runs a different pipeline — no tree-level static stage,
# and a reachability pass the review has no equivalent of. Kept separate so the
# UI shows the stages that actually run rather than a review's.
HISTORY_STAGES: tuple[tuple[str, str], ...] = (
    ("select", "Select commits from history"),
    # Reachability is checked per finding inside this stage, not after it — a
    # separate stage here would draw a pass that does not exist.
    ("llm", "Review each commit; check findings against HEAD"),
    ("dedupe", "Deduplicate findings"),
    ("waiver", "Apply waivers and baseline"),
    ("threshold", "Apply severity floor"),
)

# The two pipelines share stage ids — both have "llm", "dedupe", "waiver",
# "threshold" — so a single flat lookup cannot serve both. The review pipeline
# wins here because it is the common path; `history` passes its own label
# explicitly for the one stage whose wording actually differs. Without that, a
# `cosmo review` announced "Review each commit; check findings against HEAD".
STAGE_LABELS: dict[str, str] = dict(HISTORY_STAGES) | dict(STAGES)


@dataclass(frozen=True)
class Event:
    kind: Kind
    message: str
    stage: Optional[str] = None
    detail: str = ""
    ts: float = field(default_factory=time.time)
    data: dict = field(default_factory=dict)


Sink = Callable[[Event], None]


class Emitter:
    """Engine-side handle. `Emitter(None)` is a working no-op, so callers never
    branch on whether anyone is listening.

    A sink may be called from several threads at once — a whole-project audit
    reviews `llm_audit.concurrency` files in parallel — so a sink that touches
    shared state must do its own locking.
    """

    __slots__ = ("_sink",)

    def __init__(self, sink: Sink | None = None) -> None:
        self._sink = sink

    def __bool__(self) -> bool:
        return self._sink is not None

    def emit(self, kind: Kind, message: str, *, stage: str | None = None,
             detail: str = "", **data) -> None:
        if self._sink is None:
            return
        self._sink(Event(kind=kind, message=message, stage=stage,
                         detail=detail, data=data))

    # --- convenience, so engine call sites read as prose --------------------

    def objective_started(self, message: str, **data) -> None:
        self.emit(Kind.OBJECTIVE_STARTED, message, **data)

    def objective_completed(self, message: str, **data) -> None:
        self.emit(Kind.OBJECTIVE_COMPLETED, message, **data)

    def stage_started(self, stage: str, message: str = "", **data) -> None:
        self.emit(Kind.STAGE_STARTED, message or STAGE_LABELS.get(stage, stage),
                  stage=stage, **data)

    def stage_completed(self, stage: str, message: str = "", **data) -> None:
        self.emit(Kind.STAGE_COMPLETED, message or STAGE_LABELS.get(stage, stage),
                  stage=stage, **data)

    def stage_skipped(self, stage: str, message: str, **data) -> None:
        self.emit(Kind.STAGE_SKIPPED, message, stage=stage, **data)

    def operation(self, message: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.OPERATION, message, stage=stage, **data)

    def execute(self, argv: list[str], *, stage: str | None = None, **data) -> None:
        self.emit(Kind.EXECUTE, " ".join(argv), stage=stage, **data)

    def output(self, message: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.OUTPUT, message, stage=stage, **data)

    def read(self, path: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.READ, path, stage=stage, **data)

    def write(self, path: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.WRITE, path, stage=stage, **data)

    def api_request(self, message: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.API_REQUEST, message, stage=stage, **data)

    def finding(self, message: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.FINDING, message, stage=stage, **data)

    def warning(self, message: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.WARNING, message, stage=stage, **data)

    def error(self, message: str, *, stage: str | None = None, **data) -> None:
        self.emit(Kind.ERROR, message, stage=stage, **data)
