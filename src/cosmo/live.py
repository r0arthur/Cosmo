"""Live review UI (`cosmo review --live`).

A rendering of `engine.run_review`'s real execution: it subscribes to the event
stream and draws what the engine reports, so it cannot show a stage the engine
did not run. Nothing here can change the review — the emitter it installs is
read-only.

Two properties this file owes the rest of the tool:

* **stderr only.** stdout stays clean so `--format sarif|pr` can still be piped,
  and the CI exit code keeps its meaning.
* **stdlib only.** cosmo ships a .deb whose sole requirement is python3 >= 3.10;
  a UI dependency would break that, so the drawing here is hand-rolled ANSI.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from .events import STAGES, Event, Kind

# --- palette ----------------------------------------------------------------

_C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "gray": "\033[38;5;245m", "faint": "\033[38;5;240m",
    "cyan": "\033[38;5;80m", "blue": "\033[38;5;75m",
    "green": "\033[38;5;77m", "yellow": "\033[38;5;221m",
    "orange": "\033[38;5;215m", "red": "\033[38;5;203m",
    "magenta": "\033[38;5;176m", "white": "\033[38;5;253m",
}

_SEVERITY_COLOR = {
    "critical": "red", "high": "orange", "medium": "yellow",
    "low": "blue", "info": "gray",
}

# Activity-feed gutter per event kind: (glyph, label, color).
_GUTTER: dict[Kind, tuple[str, str, str]] = {
    Kind.STAGE_STARTED:   ("▶", "STAGE", "cyan"),
    Kind.STAGE_COMPLETED: ("✓", "", "green"),
    Kind.STAGE_SKIPPED:   ("⊘", "SKIP", "gray"),
    Kind.OPERATION:       ("→", "", "white"),
    Kind.EXECUTE:         ("→", "EXECUTE", "magenta"),
    Kind.OUTPUT:          ("←", "OUTPUT", "blue"),
    Kind.READ:            ("→", "READ", "blue"),
    Kind.WRITE:           ("→", "WRITE", "magenta"),
    Kind.API_REQUEST:     ("→", "API", "magenta"),
    Kind.FINDING:         ("⚑", "FINDING", "yellow"),
    Kind.WARNING:         ("!", "WARN", "yellow"),
    Kind.ERROR:           ("✗", "ERROR", "red"),
    Kind.OBJECTIVE_STARTED: ("●", "", "cyan"),
    Kind.OBJECTIVE_COMPLETED: ("✓", "", "green"),
}

# The panel was pinned at 110 columns, so on a wide terminal it drew the report
# down the left half of the screen and clipped every finding title to an
# ellipsis — the one part of a finding line that carries the meaning. Use the
# width the terminal actually reports; the cap only stops an ultrawide monitor
# from drawing a rule the eye can't track back.
MAX_PANEL_WIDTH = 200

PENDING, ACTIVE, DONE, SKIPPED = "pending", "active", "done", "skipped"

_STATUS_GLYPH = {
    PENDING: ("○", "faint"), ACTIVE: ("●", "yellow"),
    DONE: ("✓", "green"), SKIPPED: ("⊘", "gray"),
}


@dataclass
class _Line:
    ts: float
    kind: Kind
    message: str
    detail: str = ""


@dataclass
class _State:
    objective: str = "Security review"
    target: str = ""
    audit: bool = False
    threshold: str = ""
    started: float = field(default_factory=time.monotonic)
    stages: tuple = STAGES
    stage_status: dict = field(default_factory=dict)
    current_stage: str | None = None
    current_op: str = ""
    stage_started_at: float = field(default_factory=time.monotonic)
    activity: deque = field(default_factory=lambda: deque(maxlen=400))
    findings: list = field(default_factory=list)
    skips: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    executed: list = field(default_factory=list)
    api_calls: int = 0
    finished: bool = False


class LiveUI:
    """An event sink that draws itself. Pass the instance as `events=`."""

    def __init__(self, stream=None, color: bool | None = None,
                 tick: float = 0.25, stages: tuple = STAGES) -> None:
        self._out = stream or sys.stderr
        self._tty = bool(getattr(self._out, "isatty", lambda: False)())
        if color is None:
            color = self._tty and not os.environ.get("NO_COLOR")
        self._color = bool(color)
        self._lock = threading.RLock()
        self._state = _State(stages=tuple(stages),
                             stage_status={s: PENDING for s, _ in stages})
        self._drawn = 0
        self._tick = tick
        self._ticker: threading.Thread | None = None
        self._stop = threading.Event()

    # --- sink ---------------------------------------------------------------

    def __call__(self, event: Event) -> None:
        """Event sink. Called from worker threads during a whole-project audit."""
        with self._lock:
            self._absorb(event)
            if self._tty:
                self._paint()
            else:
                self._stream_line(event)

    def _absorb(self, e: Event) -> None:
        st = self._state
        st.activity.append(_Line(e.ts, e.kind, e.message, e.detail))

        if e.kind is Kind.OBJECTIVE_STARTED:
            st.objective = e.message
            st.target = e.data.get("target", "")
            st.audit = bool(e.data.get("audit"))
            st.threshold = e.data.get("threshold", "")
        elif e.kind is Kind.STAGE_STARTED and e.stage in st.stage_status:
            st.stage_status[e.stage] = ACTIVE
            st.current_stage = e.stage
            # Cleared, not set to the stage label: the operation line sits under
            # the stage line, and echoing the same text there says nothing.
            st.current_op = ""
            st.stage_started_at = time.monotonic()
        elif e.kind is Kind.STAGE_COMPLETED and e.stage in st.stage_status:
            # A completed stage outranks a partial skip: the static stage still
            # ran even when one of its tools was missing.
            st.stage_status[e.stage] = DONE
        elif e.kind is Kind.STAGE_SKIPPED:
            if e.stage in st.stage_status and st.stage_status[e.stage] != DONE:
                st.stage_status[e.stage] = SKIPPED
            st.skips.append(e.message)
        elif e.kind is Kind.OPERATION:
            st.current_op = e.message
        elif e.kind is Kind.EXECUTE:
            st.executed.append(e.message)
            st.current_op = e.message
        elif e.kind is Kind.API_REQUEST:
            st.api_calls += 1
            st.current_op = e.message
        elif e.kind is Kind.FINDING:
            st.findings.append((e.data.get("severity", "info"), e.message, e.detail))
        elif e.kind is Kind.WARNING:
            st.warnings.append(e.message)
        elif e.kind is Kind.ERROR:
            st.errors.append(e.message)

    # --- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if not self._tty:
            return
        self._out.write("\033[?25l")   # hide cursor while we repaint
        self._out.flush()
        self._ticker = threading.Thread(target=self._tick_loop, name="cosmo-ui",
                                        daemon=True)
        self._ticker.start()

    def _tick_loop(self) -> None:
        # Repaint on a timer as well as on events, so elapsed time keeps moving
        # while a slow model call is in flight.
        while not self._stop.wait(self._tick):
            with self._lock:
                if not self._state.finished:
                    self._paint()

    def finish(self, report=None, exit_code: int | None = None) -> None:
        """Stop the live view and draw the verdict."""
        self._stop.set()
        if self._ticker is not None:
            self._ticker.join(timeout=1)
        with self._lock:
            self._state.finished = True
            if self._tty:
                self._paint()
                self._out.write("\033[?25h")   # cursor back
            self._out.write("\n" + self._final(report, exit_code) + "\n")
            self._out.flush()

    def __enter__(self) -> "LiveUI":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        if not self._state.finished:
            self.finish()

    # --- rendering ----------------------------------------------------------

    def _c(self, text: str, color: str) -> str:
        if not self._color or not text:
            return text
        return f"{_C.get(color, '')}{text}{_C['reset']}"

    def _size(self) -> tuple[int, int]:
        try:
            s = shutil.get_terminal_size((100, 30))
            return max(60, s.columns), max(16, s.lines)
        except Exception:
            return 100, 30

    def _stream_line(self, e: Event) -> None:
        """Non-TTY fallback: one durable line per event, no cursor control."""
        glyph, label, _ = _GUTTER.get(e.kind, ("·", "", "white"))
        stamp = time.strftime("%H:%M:%S", time.localtime(e.ts))
        tag = f" {label}" if label else ""
        detail = f"  {e.detail}" if e.detail else ""
        self._out.write(f"{stamp} {glyph}{tag}  {e.message}{detail}\n")
        self._out.flush()

    def _paint(self) -> None:
        width, height = self._size()
        lines = self._frame(width, height)
        buf = []
        if self._drawn:
            buf.append(f"\033[{self._drawn}A")
        for ln in lines:
            buf.append("\033[2K" + ln + "\n")
        buf.append("\033[J")          # clear anything the last frame left below
        self._out.write("".join(buf))
        self._out.flush()
        self._drawn = len(lines)

    def _frame(self, width: int, height: int) -> list[str]:
        st = self._state
        w = min(width, MAX_PANEL_WIDTH)
        out: list[str] = []
        rule = self._c("─" * w, "faint")

        # --- objective ------------------------------------------------------
        out.append(self._c("OBJECTIVE", "bold"))
        out.append(rule)
        out.append("  " + self._c(_clip(_shorten_paths(st.objective, keep=3), w - 2),
                                  "white"))
        mode = "whole-project audit" if st.audit else "diff review"
        status = self._c("● IN PROGRESS", "yellow")
        if st.finished:
            status = self._c("✓ COMPLETE", "green")
        meta = (f"  {self._c('Target', 'gray')}  {_clip_path(st.target, max(44, w - 66))}"
                f"    {self._c('Mode', 'gray')}  {mode}"
                f"    {self._c('Floor', 'gray')}  {st.threshold or '-'}")
        out.append(meta)
        out.append(f"  {self._c('Status', 'gray')}  {status}"
                   f"    {self._c('Elapsed', 'gray')}  {_dur(time.monotonic() - st.started)}")
        out.append("")

        # --- workflow -------------------------------------------------------
        done = sum(1 for s in st.stage_status.values() if s in (DONE, SKIPPED))
        total = len(st.stages)
        out.append(self._c("WORKFLOW", "bold") +
                   self._c(f"   {done}/{total} stages", "gray"))
        out.append(rule)
        for sid, label in st.stages:
            status = st.stage_status[sid]
            glyph, color = _STATUS_GLYPH[status]
            text = label
            if status == ACTIVE:
                text = self._c(label, "yellow")
            elif status == PENDING:
                text = self._c(label, "faint")
            elif status == SKIPPED:
                text = self._c(label + "  (skipped)", "gray")
            out.append(f"  {self._c(glyph, color)} {text}")
        out.append("")

        # --- progress -------------------------------------------------------
        filled = int(round((done / total) * 28))
        bar = self._c("█" * filled, "green") + self._c("░" * (28 - filled), "faint")
        pct = int(round(done / total * 100))
        out.append(self._c("PROGRESS", "bold"))
        out.append(rule)
        out.append(f"  {bar}  {pct}%   {self._c('workflow stages', 'gray')}")
        if not st.finished and st.current_stage:
            label = dict(st.stages).get(st.current_stage, st.current_stage)
            out.append(f"  {self._c('●', 'yellow')} {label}"
                       f"   {self._c(_dur(time.monotonic() - st.stage_started_at), 'gray')}")
            if st.current_op:
                out.append("    " + self._c(
                    _clip(_shorten_paths(st.current_op), w - 6), "gray"))
        out.append("")

        # --- counters -------------------------------------------------------
        sev = _tally(st.findings)
        chips = [f"{self._c(str(len(st.findings)), 'white')} findings"]
        for name in ("critical", "high", "medium", "low"):
            if sev.get(name):
                chips.append(self._c(f"{sev[name]} {name}", _SEVERITY_COLOR[name]))
        chips.append(f"{self._c(str(st.api_calls), 'white')} model calls")
        chips.append(f"{self._c(str(len(st.executed)), 'white')} commands")
        if st.skips:
            chips.append(self._c(f"{len(st.skips)} skipped", "gray"))
        if st.errors:
            chips.append(self._c(f"{len(st.errors)} errors", "red"))
        out.append("  " + self._c(" · ", "faint").join(chips))
        out.append("")

        # --- activity -------------------------------------------------------
        budget = max(4, height - len(out) - 4)
        rows = list(st.activity)[-budget:]
        out.append(self._c("LIVE ACTIVITY", "bold"))
        out.append(rule)
        for ln in rows:
            out.append(self._activity_row(ln, w))
        return out

    def _activity_row(self, ln: _Line, w: int) -> str:
        glyph, label, color = _GUTTER.get(ln.kind, ("·", "", "white"))
        stamp = self._c(time.strftime("%H:%M:%S", time.localtime(ln.ts)), "faint")
        tag = f" {self._c(label, color)}" if label else ""
        body = _shorten_paths(ln.message + (f"  {ln.detail}" if ln.detail else ""))
        room = w - 14 - (len(label) + 1 if label else 0)
        return f"  {stamp} {self._c(glyph, color)}{tag}  {_clip(body, room)}"

    # --- verdict ------------------------------------------------------------

    def _final(self, report, exit_code: int | None) -> str:
        st = self._state
        w = min(self._size()[0], MAX_PANEL_WIDTH)
        rule = self._c("─" * w, "faint")
        findings = list(getattr(report, "findings", []) or [])
        actionable = [f for f in findings if not f.waived]
        waived = len(findings) - len(actionable)
        skipped = list(getattr(report, "skipped_stages", []) or st.skips)
        ran = sum(1 for s in st.stage_status.values() if s == DONE)

        out: list[str] = []
        # The objective is "review the target", so finding vulnerabilities is a
        # successful outcome, not a failed one. Only an incomplete pipeline is a
        # failure — which is why the headline keys off errors, not findings.
        if st.errors:
            out.append(self._c("✗ REVIEW INCOMPLETE", "red"))
        else:
            out.append(self._c("✓ REVIEW COMPLETE", "green"))
        out.append(rule)
        out.append("  " + self._c(_clip(_shorten_paths(st.objective, keep=3), w - 2),
                                  "white"))
        out.append(f"  {self._c('Target', 'gray')}   {_clip_path(st.target, w - 12)}")
        out.append(f"  {self._c('Elapsed', 'gray')}  {_dur(time.monotonic() - st.started)}"
                   f"    {self._c('Stages run', 'gray')}  {ran}/{len(st.stages)}")
        out.append("")

        out.append("  " + self._c("FINDINGS", "bold"))
        if actionable:
            sev = _tally([(str(f.severity), f.title, "") for f in actionable])
            for name in ("critical", "high", "medium", "low", "info"):
                if sev.get(name):
                    out.append(f"    {self._c('●', _SEVERITY_COLOR[name])} "
                               f"{sev[name]:>3}  {name}")
            out.append("")
            shown = sorted(actionable, key=lambda f: f.severity, reverse=True)[:8]
            # Bound the location column before sizing the title against it: a
            # whole-tree run carries absolute paths, and one 130-character path
            # would otherwise squeeze every title down to a stub.
            loc_w = min(max(len(f"{f.file}:{f.line}") for f in shown),
                        max(24, w // 3))
            title_w = max(24, w - loc_w - 18)
            for f in shown:
                col = _SEVERITY_COLOR.get(str(f.severity), "white")
                # Pad before colouring: escape codes have width on the terminal
                # but length in the format spec, so padding a coloured string
                # misaligns the column.
                label = f"{str(f.severity).upper():<8}"
                where = _clip_path(f"{f.file}:{f.line}", loc_w)
                out.append(f"    {self._c(label, col)}  "
                           f"{_clip(f.title, title_w):<{title_w}}  "
                           f"{self._c(where, 'faint')}")
            if len(actionable) > 8:
                out.append(self._c(f"    … {len(actionable) - 8} more", "faint"))
        else:
            out.append(f"    {self._c('none above the ' + (st.threshold or 'configured') + ' floor', 'green')}")
        if waived:
            out.append(self._c(f"    ({waived} waived by baseline)", "faint"))
        out.append("")

        # Coverage is the honesty contract: a skipped stage is reported, never
        # quietly dropped, so the operator always knows what was not looked at.
        out.append("  " + self._c("COVERAGE", "bold"))
        if skipped:
            for s in skipped:
                out.append(f"    {self._c('⊘', 'gray')} {_clip(s, w - 8)}")
        else:
            out.append(f"    {self._c('✓', 'green')} every stage ran")
        if st.errors:
            out.append("")
            out.append("  " + self._c("ERRORS", "bold"))
            for e in st.errors[:5]:
                out.append(f"    {self._c('✗', 'red')} {_clip(e, w - 8)}")
        out.append("")

        verdict = (f"  {self._c('→', 'gray')} "
                   f"{len(actionable)} actionable finding(s); "
                   f"exit {exit_code if exit_code is not None else (1 if actionable else 0)}")
        out.append(verdict)
        return "\n".join(out)


def _tally(items) -> dict:
    out: dict = {}
    for sev, *_ in items:
        out[sev] = out.get(sev, 0) + 1
    return out


_ABS_PATH = re.compile(r"(?:/[^\s/]+){3,}")


def _shorten_paths(text: str, keep: int = 2) -> str:
    """Collapse absolute paths in a feed line to their identifying tail.

    Whole-tree mode carries absolute paths, which otherwise fill the line with
    the one part of it every row has in common.
    """
    def _sub(m: "re.Match") -> str:
        raw = m.group(0)
        if len(raw) <= 34:
            return raw
        return "…/" + "/".join(raw.strip("/").split("/")[-keep:])
    return _ABS_PATH.sub(_sub, text)


def _clip_path(path: str, width: int) -> str:
    """Clip a path from the left — the tail identifies it, the prefix rarely does."""
    path = str(path or "-")
    return path if len(path) <= width else "…" + path[-(width - 1):]


def _clip(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    if width < 8:
        return text[:width]
    return text if len(text) <= width else text[: width - 1] + "…"


def _dur(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60:02d}:{seconds % 60:02d}"
