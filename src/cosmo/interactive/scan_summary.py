"""What a `/scan` actually did, independent of how it gets displayed.

Before this existed, `/scan`'s only trace was a one-line finding count plus the
raw `skipped_stages` strings — no severity breakdown, no per-scanner
success/failure, no duration, and nothing kept around for `/report` or
`/findings` to read back without re-scanning. This module builds that record
once, from the *same* event stream `run_review` already emits (the live
`--live` review panel and the plugin surface read the identical one) — nothing
new is invented at the data-collection layer, only a place to keep what it
already says.

Two things worth being precise about:

* **A scanner's outcome is a fact about the tool, not about the findings.** A
  scanner that ran cleanly and a scanner that never got the chance to look are
  both "0 findings" if you only count results; `ScannerStatus.state` is what
  tells them apart, and `ScanSummary.scanners_failed`/`scanners_skipped` are
  what keep a crash from silently reading as "clean".
* **`stage="static"` events are shared across every tool.** Only the ones that
  also carry `tool=<name>` in their data are this collector's business — a
  bare `stage_skipped("static", "no dependency scanner ran")` for the
  dep-audit gap, for instance, has no single tool to blame and stays in
  `Report.skipped_stages` instead, same as always.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..ansi import clip, shorten_paths
from ..events import Event, Kind
from ..findings import Finding, Report
from ..severity import Severity

_SEV_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
             Severity.INFO)

OK, FAILED, SKIPPED = "ok", "failed", "skipped"


@dataclass(frozen=True)
class ScannerStatus:
    """One tool's outcome for one scan. Exactly one of these per tool that was
    even considered — including one that was never installed."""

    name: str
    state: str             # OK | FAILED | SKIPPED
    findings: int = 0
    detail: str = ""       # why, for FAILED/SKIPPED


@dataclass
class ScanSummary:
    """A completed `/scan`, kept on the session so `/report` and `/findings`
    can answer from it without re-running anything."""

    target: str
    llm: bool
    started: float
    finished: float
    report: Report
    scanners: list[ScannerStatus] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.finished - self.started)

    @property
    def actionable(self) -> list[Finding]:
        return [f for f in self.report.findings if not f.waived]

    @property
    def waived(self) -> list[Finding]:
        return [f for f in self.report.findings if f.waived]

    @property
    def total(self) -> int:
        return len(self.actionable)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.actionable:
            out[str(f.severity)] = out.get(str(f.severity), 0) + 1
        return out

    @property
    def scanners_run(self) -> int:
        return len(self.scanners)

    @property
    def scanners_succeeded(self) -> int:
        return sum(1 for s in self.scanners if s.state == OK)

    @property
    def scanners_failed(self) -> int:
        return sum(1 for s in self.scanners if s.state == FAILED)

    @property
    def scanners_skipped(self) -> int:
        return sum(1 for s in self.scanners if s.state == SKIPPED)

    def top(self, n: int = 3) -> list[Finding]:
        ordered = sorted(self.actionable,
                         key=lambda f: (-int(f.severity), f.file, f.line))
        return ordered[:n]


class Collector:
    """An event sink that builds per-scanner status while a scan runs, and
    forwards a short human line to `line_sink` (typically `session.emit`) for
    each — the same live-progress channel `/audit` already streams through,
    reused rather than duplicated.

    Kept as a dict rather than an appended list: each tool fires exactly one
    terminal event, but a dict means a stray duplicate overwrites instead of
    double-counting rather than relying on that always being true.
    """

    def __init__(self, line_sink: Optional[Callable[[str], None]] = None):
        self._line_sink = line_sink
        self.by_tool: dict[str, ScannerStatus] = {}

    def __call__(self, event: Event) -> None:
        if event.stage != "static":
            return
        tool = event.data.get("tool") or _tool_in_message(event.message)
        if tool:
            self._record(tool, event)

    def _record(self, tool: str, event: Event) -> None:
        if event.kind is Kind.OUTPUT:
            n = int(event.data.get("findings", 0) or 0)
            self.by_tool[tool] = ScannerStatus(tool, OK, findings=n)
            self._line(f"✓ {tool:<14} {n} finding{'' if n == 1 else 's'}")
        elif event.kind is Kind.ERROR:
            self.by_tool[tool] = ScannerStatus(tool, FAILED, detail=event.message)
            self._line(f"✗ {tool:<14} failed: {event.message}")
        elif event.kind is Kind.STAGE_SKIPPED:
            self.by_tool[tool] = ScannerStatus(tool, SKIPPED, detail=event.message)
            self._line(f"⊘ {tool:<14} skipped")

    def _line(self, text: str) -> None:
        if self._line_sink is not None:
            self._line_sink(text)

    def reconcile(self, report: Report, config=None) -> None:
        """Fill in what the live event stream could not have seen.

        A cache hit skips the runner entirely and replays only the flat
        `skipped_stages` strings — no per-tool OUTPUT event fires, live or
        replayed, for a tool that ran clean. What *does* survive a cache hit
        is `Finding.source` ("static:<tool>") on every restored finding, so a
        tool that found something is recovered from that.

        The one case this cannot close: a tool that ran cleanly (zero
        findings) on the run that got cached is indistinguishable, after a
        cache hit, from a tool that was never selected at all — neither
        leaves a finding to group by source nor a skip line to parse a name
        out of. `ScanSummary.scanners_run` undercounts by exactly that many on
        a cached run; it is not invented here rather than guessed at.
        """
        # Only tools the live event stream already knows about are off limits
        # — checking against `self.by_tool` directly would also block the
        # *second* finding from the same tool this loop is still counting,
        # since the first finding already added that key.
        live = set(self.by_tool)

        for f in report.findings:
            tool = str(f.source or "").removeprefix("static:")
            if not tool or tool == f.source or tool in live:
                continue
            cur = self.by_tool.get(tool)
            self.by_tool[tool] = ScannerStatus(
                tool, OK, findings=(cur.findings if cur else 0) + 1)
        for s in report.skipped_stages:
            tool = _tool_in_message(s)
            if tool and tool not in live and tool not in self.by_tool:
                self.by_tool[tool] = ScannerStatus(tool, SKIPPED, detail=s)


def _tool_in_message(message: str) -> Optional[str]:
    """Best-effort tool name out of a skip/error string that has no
    structured `tool=` — specifically, a cache-replayed skip line
    (`engine.py` replays the flat cached list with no per-tool tag). Every
    such string is generated by this codebase in one of two conventions:
    `static:<name> (...)` or `<name> not installed — ...`; both put the name
    first, so the first word (stripped of the `static:` prefix) is it.
    """
    from ..static import TOOLS_BY_NAME
    text = str(message or "").removeprefix("static:").strip()
    if not text:
        return None
    head = text.split(None, 1)[0].rstrip(":")
    return head if head in TOOLS_BY_NAME else None


def now() -> float:
    return time.monotonic()


# --- rendering ----------------------------------------------------------------

_BOX_W = 42          # a comfortable default width for the usual key: number rows
_BOX_MAX_W = 76       # wide enough for a target path; wider than this, clip it


def _box(title: str, rows: list[tuple[str, str]]) -> list[str]:
    """A bordered panel. Values are clipped to keep the border a fixed width —
    an unbounded target path (this box's one open-ended value) would otherwise
    stretch the border past the value and break the box, in the plain REPL
    where nothing else constrains the line width."""
    label_w = max((len(k) for k, _ in rows), default=0)
    inner = max(_BOX_W, label_w + 12, len(title) + 4)
    inner = min(inner, _BOX_MAX_W)
    value_w = max(1, inner - label_w - 4)
    out = [f"┌─ {title} " + "─" * max(0, inner - len(title) - 3) + "┐"]
    for k, v in rows:
        v = clip(shorten_paths(str(v)), value_w)
        out.append(f"│ {k:<{label_w}}  {v:>{value_w}} │")
    out.append("└" + "─" * inner + "┘")
    return out


def format_report(summary: ScanSummary) -> str:
    """The text `/scan` returns — boxed severity panel, per-scanner status,
    top findings, and how to get more. Identical in the plain REPL and the
    full-screen session: both display whatever `_cmd_scan` returns, so this
    is written once."""
    out: list[str] = []
    mode = "static scanners + model review" if summary.llm else "static scanners only"
    out.append(f"Scan complete — {mode}, {summary.duration:.1f}s")
    out.append("")

    rows = [("Target", summary.target),
            ("Scanners", f"{summary.scanners_run}"),
            ("Succeeded", f"{summary.scanners_succeeded}")]
    if summary.scanners_failed:
        rows.append(("Failed", f"{summary.scanners_failed}"))
    if summary.scanners_skipped:
        rows.append(("Skipped", f"{summary.scanners_skipped}"))
    rows.append(("Findings", f"{summary.total}"))
    for sev in _SEV_ORDER:
        n = summary.counts.get(str(sev), 0)
        if n:
            rows.append((str(sev).upper(), str(n)))
    out += _box("SECURITY SCAN COMPLETE", rows)
    out.append("")

    if summary.scanners_failed:
        out.append("Scanner failures (findings below are still from everything")
        out.append("that succeeded — a crash does not discard the rest):")
        for s in summary.scanners:
            if s.state == FAILED:
                out.append(f"  WARNING: {s.name} failed: {s.detail}")
        out.append("")

    top = summary.top(5)
    if top:
        out.append("Top findings:")
        for f in top:
            loc = shorten_paths(f"{f.file}:{f.line}" if f.line else f.file)
            out.append(f"  {str(f.severity).upper():<8} {clip(f.title, 90)}")
            out.append(f"           {clip(loc, 90)}")
        if summary.total > len(top):
            out.append(f"  … {summary.total - len(top)} more — /findings for all of them")
        out.append("")

    if summary.report.skipped_stages:
        out.append(f"{len(summary.report.skipped_stages)} coverage note(s) — "
                   f"/report cli to list them")
        out.append("")

    out.append("Use /report for the full write-up")
    out.append("Use /findings to browse every finding")
    if not summary.llm:
        out.append("Use /scan llm to add the model review")
    return "\n".join(out).rstrip()
