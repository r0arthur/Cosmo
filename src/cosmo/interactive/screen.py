"""Full-screen session UI (`cosmo interactive` on a terminal).

A hand-rolled TUI, because cosmo's .deb requires nothing but `python3 >= 3.10`
and a UI dependency would break that. Everything here is `termios`, `select` and
ANSI — no curses, no third-party toolkit.

What it owes the rest of the tool:

* **The terminal is always given back.** Raw mode, the alternate screen buffer
  and the hidden cursor are all restored on a clean exit, on an exception, and
  on Ctrl-Z — a TUI that leaves a wrecked terminal behind is worse than no TUI.
* **It runs no logic of its own.** Every command goes through
  `commands.dispatch` over the shared `Session`, the same guarded registry the
  plain REPL and the Claude Code plugin surface use. The screen can only ever
  show what that layer returns; it cannot relax a threshold, widen a scope, or
  post anything.
* **Coverage stays visible.** The header carries what did *not* run, because a
  findings list is the easiest place in the whole tool to mistake an incomplete
  scan for a clean one.

Non-terminal callers (pipes, tests, CI) never reach this module — `repl.py`
keeps the line-based loop for them.
"""
from __future__ import annotations

import os
import select
import signal
import sys
import termios
import threading
import time
import tty
from dataclasses import dataclass, field

from ..ansi import (C, SEVERITY_COLOR, cell, clip, fit, pad, shorten_paths,
                    width, wrap)
from ..findings import Finding
from .commands import _COMMANDS, dispatch
from .session import Session

# --- keys -------------------------------------------------------------------

UP, DOWN, LEFT, RIGHT = "up", "down", "left", "right"
PGUP, PGDN, HOME, END = "pgup", "pgdn", "home", "end"
ENTER, BACKSPACE, TAB, ESC, EOF = "enter", "backspace", "tab", "esc", "eof"
INTERRUPT, SUSPEND, DELETE = "interrupt", "suspend", "delete"
HIST_PREV, HIST_NEXT = "hist_prev", "hist_next"

_SEQUENCES = {
    b"\x1b[A": UP, b"\x1bOA": UP, b"\x1b[B": DOWN, b"\x1bOB": DOWN,
    b"\x1b[C": RIGHT, b"\x1bOC": RIGHT, b"\x1b[D": LEFT, b"\x1bOD": LEFT,
    b"\x1b[5~": PGUP, b"\x1b[6~": PGDN,
    b"\x1b[H": HOME, b"\x1b[F": END, b"\x1b[1~": HOME, b"\x1b[4~": END,
    b"\x1bOH": HOME, b"\x1bOF": END, b"\x1b[3~": DELETE,
}
_CONTROLS = {
    b"\r": ENTER, b"\n": ENTER, b"\x7f": BACKSPACE, b"\x08": BACKSPACE,
    b"\t": TAB, b"\x03": INTERRUPT, b"\x04": EOF, b"\x1a": SUSPEND,
    b"\x1b": ESC,
    # The arrows drive the findings list, so command history gets the readline
    # bindings instead of fighting them for the same keys.
    b"\x10": HIST_PREV, b"\x0e": HIST_NEXT,      # ^P / ^N
    b"\x01": HOME, b"\x05": END,                # ^A / ^E on the input line
    b"\x15": "kill_line",                        # ^U
}

# --- terminal ---------------------------------------------------------------


class Terminal:
    """Raw mode + alternate screen, restored however we leave.

    Raw mode rather than cbreak on purpose: with ISIG off, Ctrl-C and Ctrl-Z
    arrive as ordinary bytes instead of signals landing mid-repaint, so both are
    handled where the terminal state is known rather than from a handler that
    has to guess what was half-drawn.
    """

    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self.fd = self.stream.fileno()
        self._saved = None
        self.resized = threading.Event()
        self._prev_winch = None

    def __enter__(self) -> "Terminal":
        self._saved = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        self.write("\033[?1049h\033[?25l\033[H\033[2J")   # alt buffer, no cursor
        try:
            self._prev_winch = signal.signal(signal.SIGWINCH, self._on_resize)
        except (ValueError, AttributeError):
            self._prev_winch = None
        return self

    def __exit__(self, *exc) -> None:
        self.restore()

    def restore(self) -> None:
        if self._saved is None:
            return
        if self._prev_winch is not None:
            try:
                signal.signal(signal.SIGWINCH, self._prev_winch)
            except (ValueError, AttributeError):
                pass
            self._prev_winch = None
        self.write("\033[?25h\033[?1049l")     # cursor back, main buffer back
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self._saved)
        self._saved = None

    def _on_resize(self, signum, frame) -> None:
        self.resized.set()

    def size(self) -> tuple[int, int]:
        try:
            s = os.get_terminal_size(self.fd)
            return max(40, s.columns), max(12, s.lines)
        except OSError:
            return 100, 30

    def write(self, text: str) -> None:
        try:
            self.stream.write(text)
            self.stream.flush()
        except (BrokenPipeError, ValueError):
            pass

    def suspend(self) -> None:
        """Hand the terminal back, stop, and take it again on resume."""
        self.restore()
        os.kill(os.getpid(), signal.SIGTSTP)
        self.__enter__()

    def read_key(self, timeout: float = 0.2) -> str | None:
        """One key, or None if nothing arrived before `timeout`.

        Escape sequences are read as a burst: after `\\x1b` the rest of the
        sequence is already in the buffer, so a very short second wait tells an
        arrow key apart from a bare Esc without a visible delay on either.
        """
        if not select.select([self.fd], [], [], timeout)[0]:
            return None
        first = os.read(self.fd, 1)
        if not first:
            return EOF
        if first != b"\x1b":
            if first in _CONTROLS:
                return _CONTROLS[first]
            return self._decode(first)

        seq = first
        while len(seq) < 8 and select.select([self.fd], [], [], 0.02)[0]:
            seq += os.read(self.fd, 1)
            if seq in _SEQUENCES:
                return _SEQUENCES[seq]
        return _SEQUENCES.get(seq, ESC if seq == b"\x1b" else None)

    def _decode(self, first: bytes) -> str | None:
        """Finish a UTF-8 character whose leading byte we already have."""
        need = (4 if first[0] >= 0xF0 else 3 if first[0] >= 0xE0
                else 2 if first[0] >= 0xC0 else 1)
        buf = first
        while len(buf) < need and select.select([self.fd], [], [], 0.02)[0]:
            buf += os.read(self.fd, 1)
        try:
            ch = buf.decode()
        except UnicodeDecodeError:
            return None
        return ch if ch.isprintable() or ch == " " else None


def _model_label(session: Session) -> str:
    """The provider the session would actually use, short enough for a header.

    `session_model or "default"` was a literal rather than a lookup: it said
    "default" whatever the config had chosen, and never showed that the
    provider could not run — the one thing worth knowing before trusting a
    finding list.
    """
    from ..providers.registry import resolve_primary
    try:
        provider, _ = resolve_primary(session.config,
                                      session_model=session.session_model)
    except Exception:
        return "unresolved"
    return provider.name if provider.available() else f"{provider.name} (unavailable)"


# --- application state ------------------------------------------------------

FINDINGS, DETAIL, OUTPUT = "findings", "detail", "output"


@dataclass
class App:
    session: Session
    term: Terminal
    view: str = FINDINGS
    sel: int = 0                     # selected finding
    top: int = 0                     # first visible row of the list
    text: str = ""                   # what is typed on the command line
    caret: int = 0
    out_lines: list[str] = field(default_factory=list)
    out_top: int = 0
    out_title: str = ""
    history: list[str] = field(default_factory=list)
    hist_at: int | None = None
    status: str = ""
    scanning: bool = False
    started: float = field(default_factory=time.monotonic)
    running: bool = True
    _dirty: bool = True
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # --- data ---------------------------------------------------------------

    def findings(self) -> list[Finding]:
        items = self.session.snapshot_findings()
        return sorted(items, key=lambda f: (-int(f.severity), f.file, f.line))

    def selected(self) -> Finding | None:
        items = self.findings()
        return items[self.sel] if 0 <= self.sel < len(items) else None

    def note(self, message: str) -> None:
        self.status = message
        self._dirty = True

    def emit(self, line: str) -> None:
        """Sink for a long-running command's live output (`/audit`)."""
        with self._lock:
            self.out_lines.append(str(line))
        self._dirty = True

    # --- input --------------------------------------------------------------

    def handle(self, key: str) -> None:
        if key is None:
            return
        self._dirty = True
        if key == INTERRUPT:
            self.running = False
            return
        if key == SUSPEND:
            self.term.suspend()
            return
        if key == EOF and not self.text:
            self.running = False
            return
        if key == ESC:
            self.view = FINDINGS
            self.status = ""
            return
        if key in (HOME, END) and self.text:
            self.caret = 0 if key == HOME else len(self.text)
            return
        if key in (UP, DOWN, PGUP, PGDN, HOME, END):
            self._move(key)
            return
        if key == ENTER:
            self._submit()
            return
        if key == TAB:
            self._complete()
            return
        if key in (HIST_PREV, HIST_NEXT):
            self._recall(key)
            return
        if key == "kill_line":
            self.text, self.caret = "", 0
            return
        if key == BACKSPACE:
            if self.caret:
                self.text = self.text[: self.caret - 1] + self.text[self.caret:]
                self.caret -= 1
            return
        if key == DELETE:
            self.text = self.text[: self.caret] + self.text[self.caret + 1:]
            return
        if key == LEFT:
            self.caret = max(0, self.caret - 1)
            return
        if key == RIGHT:
            self.caret = min(len(self.text), self.caret + 1)
            return
        if len(key) == 1:
            self.text = self.text[: self.caret] + key + self.text[self.caret:]
            self.caret += 1

    def _move(self, key: str) -> None:
        _, rows = self.term.size()
        page = max(1, self._body_rows(rows) - 1)
        if self.view == OUTPUT:
            step = {UP: -1, DOWN: 1, PGUP: -page, PGDN: page,
                    HOME: -len(self.out_lines), END: len(self.out_lines)}[key]
            limit = max(0, len(self.out_lines) - self._body_rows(rows))
            self.out_top = max(0, min(limit, self.out_top + step))
            return
        # In the list and the detail view, the arrows move the selection —
        # typing always goes to the command line, so the two never compete.
        total = len(self.findings())
        if not total:
            return
        step = {UP: -1, DOWN: 1, PGUP: -page, PGDN: page,
                HOME: -total, END: total}[key]
        self.sel = max(0, min(total - 1, self.sel + step))

    def _recall(self, key: str) -> None:
        """Walk the command history. ^P back, ^N forward; ^N off the end clears."""
        if not self.history:
            return
        if key == HIST_PREV:
            self.hist_at = (len(self.history) - 1 if self.hist_at is None
                            else max(0, self.hist_at - 1))
        else:
            if self.hist_at is None:
                return
            self.hist_at += 1
            if self.hist_at >= len(self.history):
                self.hist_at, self.text, self.caret = None, "", 0
                return
        self.text = self.history[self.hist_at]
        self.caret = len(self.text)

    def _submit(self) -> None:
        line = self.text.strip()
        if not line:
            # Enter on an empty line opens the selected finding — the obvious
            # gesture in a list, and it keeps the command line for commands.
            if self.view == FINDINGS and self.selected() is not None:
                self.view = DETAIL
            elif self.view != FINDINGS:
                self.view = FINDINGS
            return
        self.text, self.caret, self.hist_at = "", 0, None
        self.history.append(line)
        if line in ("/quit", "/exit"):
            self.running = False
            return
        self._run(line)

    def _run(self, line: str) -> None:
        self.note(f"running {line} …")
        self._paint()
        try:
            result = dispatch(self.session, line)
        except Exception as exc:                # a command must not kill the UI
            result = f"error: {exc}"
        self.show(line, result)

    def show(self, title: str, body: str) -> None:
        with self._lock:
            self.out_lines = str(body).splitlines() or ["(no output)"]
        self.out_title, self.out_top, self.view = title, 0, OUTPUT
        self.status = ""

    def _complete(self) -> None:
        """Complete a slash command from the guarded registry.

        The registry is the only source: a name that completes here is a name
        the enforced dispatcher actually has.
        """
        if not self.text.startswith("/") or " " in self.text:
            return
        stem = self.text[1:]
        matches = sorted(n for n in _COMMANDS if n.startswith(stem))
        if not matches:
            self.note(f"no command starts with /{stem}")
        elif len(matches) == 1:
            self.text = f"/{matches[0]} "
            self.caret = len(self.text)
        else:
            common = os.path.commonprefix(matches)
            self.text = f"/{common}"
            self.caret = len(self.text)
            self.note("  ".join(f"/{m}" for m in matches))

    # --- rendering ----------------------------------------------------------

    def _body_rows(self, rows: int) -> int:
        # title + 2 meta + rule, then rule + input + hints at the foot.
        return max(3, rows - 8)

    def _paint(self) -> None:
        cols, rows = self.term.size()
        w = min(cols, 160)
        lines = self._frame(w, rows)
        buf = ["\033[H"]
        for ln in lines:
            buf.append("\033[2K" + ln + "\r\n")
        buf.append("\033[J")
        self.term.write("".join(buf))

    def _frame(self, w: int, rows: int) -> list[str]:
        inner = w - 2
        out = [self._title(inner)]
        out += self._meta(inner)
        out.append(f"├{'─' * inner}┤")
        body = self._body(inner, self._body_rows(rows))
        out += [f"│{cell(b, inner)}│" for b in body]
        out.append(f"├{'─' * inner}┤")
        out.append(f"│{cell(self._prompt(inner), inner)}│")
        out.append(f"╰{'─' * inner}╯")
        out.append(self._hints(w))
        return out

    def _c(self, text: str, color: str) -> str:
        return f"{C[color]}{text}{C['reset']}" if color in C else text

    def _title(self, inner: int) -> str:
        counts = self.session.snapshot_report().counts
        total = sum(counts.values())
        right = ("scanning…" if self.scanning
                 else f"{total} finding{'' if total == 1 else 's'}")
        left = "─ cosmo "
        gap = max(1, inner - len(left) - len(right) - 2)
        return (f"╭{left}{'─' * gap} {self._c(right, 'gray')} ─")[:0] + \
               f"╭{left}{'─' * gap}{self._c(' ' + right + ' ', 'gray')}╮"

    def _meta(self, inner: int) -> list[str]:
        st = self.session
        snapshot = st.snapshot_report()
        skipped = len(snapshot.skipped_stages)
        rows = [
            [("target", clip(shorten_paths(str(st.target), keep=3), inner - 12))],
            [("floor", st.effective_threshold()),
             ("model", _model_label(st)),
             # Coverage in the header, not buried in /report: a findings list is
             # the easiest place in the tool to read an incomplete scan as clean.
             ("skipped", f"{skipped} stage{'' if skipped == 1 else 's'}")],
        ]
        out = []
        for row in rows:
            cells = "    ".join(
                f"{self._c(k, 'faint')}  {self._c(str(v), 'white')}" for k, v in row)
            out.append(f"│  {cell(cells, inner - 2)}│")
        return out

    def _body(self, inner: int, height: int) -> list[str]:
        if self.view == OUTPUT:
            return self._output_body(inner, height)
        if self.view == DETAIL:
            return self._detail_body(inner, height)
        return self._list_body(inner, height)

    def _list_body(self, inner: int, height: int) -> list[str]:
        items = self.findings()
        if not items:
            middle = "scanning…" if self.scanning else "no findings at this floor"
            return ["", f"  {self._c(middle, 'gray')}"]
        # Keep the selection on screen without snapping it to an edge.
        if self.sel < self.top:
            self.top = self.sel
        elif self.sel >= self.top + height:
            self.top = self.sel - height + 1
        self.top = max(0, min(self.top, max(0, len(items) - height)))

        visible = items[self.top:self.top + height]
        # One location width for the whole frame. Sized per row it made the
        # right-hand column ragged, because each title was padded against a
        # different remainder. Bounded so a single deep path cannot squeeze
        # every title into a stub.
        locs = [shorten_paths(f"{f.file}:{f.line}", keep=2) for f in visible]
        loc_w = min(max((len(x) for x in locs), default=0), max(24, inner // 3))
        title_w = max(16, inner - loc_w - 15)

        out = []
        for offset, f in enumerate(visible):
            i = self.top + offset
            sev = str(f.severity).upper()
            loc = clip(locs[offset], loc_w)
            title = clip(f.title, title_w)
            marker = "▸" if i == self.sel else " "
            # Assembled plain, coloured after: escape codes have length but no
            # width, so padding a coloured string misaligns everything after it.
            row = f" {marker} {sev:<9}{pad(title, title_w)}  {loc:>{loc_w}} "
            if i == self.sel:
                out.append(f"{C['sel_bg']}{cell(row, inner)}{C['reset']}")
            else:
                out.append(f" {marker} {self._c(f'{sev:<9}', SEVERITY_COLOR.get(str(f.severity), 'white'))}"
                           f"{pad(title, title_w)}  "
                           f"{self._c(f'{loc:>{loc_w}}', 'faint')} ")
        return out

    def _detail_body(self, inner: int, height: int) -> list[str]:
        f = self.selected()
        if f is None:
            return ["", "  nothing selected"]
        color = SEVERITY_COLOR.get(str(f.severity), "white")
        out = [""]
        out += [f"  {self._c(str(f.severity).upper(), color)}  {t}"
                for t in wrap(f.title, inner - 14)[:3]]
        out.append("")
        for label, value in (("location", f"{f.file}:{f.line}"),
                             ("source", f.source),
                             ("category", f.category or "—"),
                             ("confidence", f"{f.confidence:.0%}"),
                             ("status", f.confirmation_status.value),
                             ("fingerprint", f.fingerprint or "—")):
            out.append(f"  {self._c(f'{label:<12}', 'faint')}"
                       f"{clip(str(value), inner - 16)}")
        for label, text in (("evidence", f.evidence),
                            ("exploit", f.exploit_scenario),
                            ("fix", f.remediation)):
            if str(text).strip():
                out.append("")
                out.append(f"  {self._c(label.upper(), 'cyan')}")
                out += [f"    {line}" for line in wrap(str(text), inner - 6)]
        if f.fingerprint:
            out.append("")
            out.append(f"  {self._c('/waive ' + f.fingerprint + ' <reason>', 'faint')}")
        return out[:height]

    def _output_body(self, inner: int, height: int) -> list[str]:
        with self._lock:
            lines = list(self.out_lines)
        head = f"  {self._c(self.out_title, 'cyan')}"
        more = max(0, len(lines) - self.out_top - (height - 2))
        window = lines[self.out_top:self.out_top + height - 2]
        out = [head, ""] + [f"  {fit(ln, inner - 4, collapse=False)}" for ln in window]
        if more:
            out = out[:height - 1] + [f"  {self._c(f'… {more} more line(s) — ↑↓ to scroll', 'faint')}"]
        return out[:height]

    def _prompt(self, inner: int) -> str:
        shown = clip(self.text, inner - 6) if width(self.text) > inner - 6 else self.text
        caret = self._c("▏", "cyan")
        body = f"{shown[:self.caret]}{caret}{shown[self.caret:]}"
        return f" {self._c('›', 'cyan')} {body}"

    def _hints(self, w: int) -> str:
        if self.status:
            return " " + self._c(fit(self.status, w - 2), "yellow")
        if self.view == OUTPUT:
            keys = "↑↓ scroll · esc back · /help · ^C quit"
        elif self.view == DETAIL:
            keys = "↑↓ next finding · esc back · /waive · ^C quit"
        else:
            keys = ("↑↓ select · ⏎ detail · tab complete · ^P history · "
                    "/help · ^C quit")
        return " " + self._c(fit(keys, w - 2), "faint")

    # --- loop ---------------------------------------------------------------

    def scan_in_background(self) -> None:
        """Scan off the main thread so the UI is alive while it runs."""
        self.scanning = True

        def work() -> None:
            try:
                self.session.scan()
            except Exception as exc:
                self.note(f"scan failed: {exc}")
            finally:
                self.scanning = False
                self._dirty = True

        threading.Thread(target=work, name="cosmo-scan", daemon=True).start()

    def run(self) -> None:
        while self.running:
            if self.term.resized.is_set():
                self.term.resized.clear()
                self._dirty = True
            if self._dirty:
                self._paint()
                self._dirty = False
            key = self.term.read_key(timeout=0.2)
            if key is not None:
                self.handle(key)
            elif self.scanning:
                self._dirty = True          # keep "scanning…" alive


def run_screen(session: Session, *, autoscan: bool = True,
               stream=None) -> Session:
    """Drive a session full-screen. Restores the terminal whatever happens."""
    with Terminal(stream) as term:
        app = App(session=session, term=term)
        session.writer = app.emit
        if autoscan:
            app.scan_in_background()
        try:
            app.run()
        except KeyboardInterrupt:
            pass
    return session


def usable(stream=None) -> bool:
    """Whether a full-screen UI is possible here.

    Pipes, CI and the test suite all fall through to the line-based REPL, which
    stays the reference implementation of the session.
    """
    stream = stream or sys.stdout
    if os.environ.get("COSMO_NO_TUI"):
        return False
    try:
        return bool(stream.isatty() and sys.stdin.isatty()
                    and termios.tcgetattr(stream.fileno()))
    except Exception:
        return False
