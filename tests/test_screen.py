"""The full-screen session UI (`cosmo interactive` on a terminal).

Hermetic: `App` is driven directly with a fake `Terminal`, so no pty, no raw
mode and no real keyboard. The behaviours that actually matter here are the
ones a broken TUI gets wrong quietly — columns that drift, a selection that
escapes its list, a command that kills the loop, and coverage that stops being
visible the moment findings are on screen.

The terminal-state properties (alternate buffer, raw mode, restore on exit and
on Ctrl-Z, redraw on resize) are verified against a real pty by hand; they
cannot be asserted here because pytest's stdout is not a terminal.
"""
import io

import pytest

from cosmo.ansi import strip, width
from cosmo.config import Config
from cosmo.findings import Finding, Report
from cosmo.interactive.screen import (DETAIL, DOWN, END, ENTER, ESC, FINDINGS,
                                      HIST_NEXT, HIST_PREV, HOME, INTERRUPT,
                                      OUTPUT, PGDN, TAB, UP, App, usable)
from cosmo.interactive.session import Session
from cosmo.severity import Severity


class _FakeTerm:
    """A Terminal that records what was painted instead of owning a tty."""

    def __init__(self, cols=100, rows=30):
        self.cols, self.rows = cols, rows
        self.painted: list[str] = []
        self.suspended = 0

    def size(self):
        return self.cols, self.rows

    def write(self, text):
        self.painted.append(text)

    def suspend(self):
        self.suspended += 1

    def read_key(self, timeout=0.2):
        return None


def _finding(i=0, sev=Severity.HIGH, title=None, file=None, **kw):
    return Finding(id=f"f{i}", title=title or f"finding {i}", severity=sev,
                   source="static:semgrep", file=file or f"src/mod{i}.py",
                   line=10 + i, fingerprint=f"fp{i}", category="CWE-78", **kw)


def _app(findings=(), skipped=(), cols=100, rows=30, **cfg):
    session = Session(config=Config(data=cfg or {}), target="/repo")
    session.findings = list(findings)
    session.skipped_stages = list(skipped)
    return App(session=session, term=_FakeTerm(cols, rows))


def _frame(app):
    cols, rows = app.term.size()
    return app._frame(min(cols, 160), rows)


# --- the frame is well-formed ------------------------------------------------

def test_every_row_is_exactly_the_frame_width():
    """Escape codes have length but no width. A row padded after colouring is
    a row that drags every column after it out of line."""
    app = _app([_finding(i) for i in range(5)], skipped=["static:trivy"])
    rows = _frame(app)
    body = [r for r in rows if strip(r).startswith(("│", "╭", "├", "╰"))]
    assert len(set(width(r) for r in body)) == 1, "frame rows are not flush"


def test_the_frame_fits_a_narrow_terminal():
    app = _app([_finding(i) for i in range(3)], cols=52, rows=16)
    rows = _frame(app)
    assert max(width(r) for r in rows) <= 52


def test_locations_share_one_column_width():
    """Sized per row, the right-hand column came out ragged because each title
    was padded against a different remainder."""
    app = _app([_finding(0, file="a.py"),
                _finding(1, file="deep/nested/path/to/something.py")])
    body = [strip(r) for r in _frame(app) if "mod" not in r and ".py" in strip(r)]
    ends = {len(r.rstrip()) for r in body if r.strip().startswith("│")}
    assert len(ends) <= 1 or max(ends) - min(ends) <= 1


# --- coverage stays visible --------------------------------------------------

def test_the_header_reports_what_did_not_run():
    """A findings list is the easiest place in the tool to read an incomplete
    scan as a clean one."""
    app = _app([_finding()], skipped=["static:trivy", "model:claude"])
    header = strip("\n".join(_frame(app)[:4]))
    assert "skipped" in header and "2 stage" in header


def test_a_single_skipped_stage_is_not_pluralised():
    app = _app([_finding()], skipped=["static:trivy"])
    assert "1 stage " in strip("\n".join(_frame(app)[:4])) + " "


def test_the_header_names_an_unavailable_provider(monkeypatch):
    """"model: default" was a literal, not a lookup — it never showed that the
    provider could not run."""
    import shutil as _shutil
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(_shutil, "which", lambda *_a, **_k: None)
    header = strip("\n".join(_frame(_app([_finding()]))[:4]))
    assert "unavailable" in header


# --- navigation --------------------------------------------------------------

def test_selection_cannot_leave_the_list():
    app = _app([_finding(i) for i in range(3)])
    for _ in range(10):
        app.handle(DOWN)
    assert app.sel == 2
    for _ in range(10):
        app.handle(UP)
    assert app.sel == 0


def test_navigation_on_an_empty_list_is_harmless():
    app = _app([])
    app.handle(DOWN)
    app.handle(END)
    assert app.sel == 0
    assert "no findings" in strip("\n".join(_frame(app)))


def test_the_view_scrolls_to_keep_the_selection_on_screen():
    app = _app([_finding(i) for i in range(80)], rows=20)
    app.handle(END)
    _frame(app)                                  # scrolling happens at draw time
    assert app.top <= app.sel < app.top + app._body_rows(20)


def test_page_down_moves_further_than_one_row():
    app = _app([_finding(i) for i in range(80)])
    app.handle(PGDN)
    assert app.sel > 1


# --- typing and commands -----------------------------------------------------

def test_typing_goes_to_the_command_line_not_the_list():
    """Arrows drive the list, characters drive the input; they never compete."""
    app = _app([_finding(i) for i in range(3)])
    for ch in "/status":
        app.handle(ch)
    assert app.text == "/status"
    assert app.sel == 0


def test_enter_on_an_empty_line_opens_the_selected_finding():
    app = _app([_finding()])
    app.handle(ENTER)
    assert app.view == DETAIL
    assert "CWE-78" in strip("\n".join(_frame(app)))


def test_escape_returns_to_the_list():
    app = _app([_finding()])
    app.handle(ENTER)
    app.handle(ESC)
    assert app.view == FINDINGS


def test_a_command_runs_through_the_guarded_dispatcher():
    app = _app([_finding()])
    for ch in "/status":
        app.handle(ch)
    app.handle(ENTER)
    assert app.view == OUTPUT
    assert "target:" in "\n".join(app.out_lines)
    assert app.text == ""


def test_a_failing_command_does_not_kill_the_ui(monkeypatch):
    import cosmo.interactive.screen as screen

    def boom(session, line):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(screen, "dispatch", boom)
    app = _app([_finding()])
    for ch in "/status":
        app.handle(ch)
    app.handle(ENTER)
    assert app.running
    assert "kaboom" in "\n".join(app.out_lines)


def test_quit_stops_the_loop():
    app = _app([_finding()])
    for ch in "/quit":
        app.handle(ch)
    app.handle(ENTER)
    assert not app.running


# --- completion --------------------------------------------------------------

def test_tab_completes_a_unique_command():
    app = _app()
    for ch in "/too":
        app.handle(ch)
    app.handle(TAB)
    assert app.text == "/tools "


def test_tab_on_an_ambiguous_prefix_shows_the_candidates():
    app = _app()
    for ch in "/s":
        app.handle(ch)
    app.handle(TAB)
    assert app.text.startswith("/s")
    assert "/skills" in app.status and "/status" in app.status


def test_completion_only_offers_real_commands():
    """The registry is the only source, so a name that completes here is a name
    the enforced dispatcher actually has."""
    from cosmo.interactive.commands import _COMMANDS
    app = _app()
    for ch in "/zzz":
        app.handle(ch)
    app.handle(TAB)
    assert "no command" in app.status
    assert set(_COMMANDS) >= {"status", "report", "tools"}


# --- history -----------------------------------------------------------------

def test_history_recall_walks_backwards_and_forwards():
    """The arrows drive the list, so history takes the readline bindings."""
    app = _app()
    for line in ("/status", "/tools"):
        app.text, app.caret = line, len(line)
        app.handle(ENTER)
    app.handle(HIST_PREV)
    assert app.text == "/tools"
    app.handle(HIST_PREV)
    assert app.text == "/status"
    app.handle(HIST_NEXT)
    assert app.text == "/tools"
    app.handle(HIST_NEXT)
    assert app.text == ""            # forward off the end clears the line


def test_history_recall_with_no_history_is_harmless():
    app = _app()
    app.handle(HIST_PREV)
    assert app.text == ""


# --- editing -----------------------------------------------------------------

def test_home_and_end_move_the_caret_while_typing():
    app = _app([_finding(i) for i in range(4)])
    for ch in "/report":
        app.handle(ch)
    app.handle(HOME)
    assert app.caret == 0 and app.sel == 0      # did not move the list
    app.handle(END)
    assert app.caret == len("/report")


def test_home_moves_the_list_when_the_line_is_empty():
    app = _app([_finding(i) for i in range(10)])
    app.handle(END)
    assert app.sel == 9
    app.handle(HOME)
    assert app.sel == 0


def test_kill_line_clears_the_input():
    app = _app()
    for ch in "/status":
        app.handle(ch)
    app.handle("kill_line")
    assert app.text == "" and app.caret == 0


# --- stopping ----------------------------------------------------------------

def test_ctrl_c_stops_the_loop():
    app = _app([_finding()])
    app.handle(INTERRUPT)
    assert not app.running


def test_ctrl_z_hands_the_terminal_back():
    """Raw mode means Ctrl-Z arrives as a byte, not a signal, so it is handled
    where the terminal state is known rather than from a handler mid-repaint."""
    app = _app([_finding()])
    app.handle("suspend")
    assert app.term.suspended == 1
    assert app.running


# --- when a terminal is not available ---------------------------------------

def test_the_tui_is_declined_off_a_terminal():
    """Pipes, CI and the test suite fall through to the line REPL, which stays
    the reference implementation of a session."""
    assert usable(io.StringIO()) is False


def test_the_tui_can_be_switched_off_by_environment(monkeypatch):
    monkeypatch.setenv("COSMO_NO_TUI", "1")
    class _Tty:
        def isatty(self):
            return True

        def fileno(self):
            return 1

    assert usable(_Tty()) is False


# --- the selection and the commands share one cursor ------------------------

def test_arrow_keys_move_the_session_cursor():
    """The screen keeping its own index is how `/next` and `↓` end up
    disagreeing about which finding is current."""
    app = _app([_finding(i) for i in range(5)])
    app.handle(DOWN)
    app.handle(DOWN)
    assert app.session.cursor == 2
    assert app.sel == 2


def test_a_command_that_moves_the_cursor_moves_the_selection():
    app = _app([_finding(i) for i in range(5)])
    for ch in "/next 2":
        app.handle(ch)
    app.handle(ENTER)
    assert app.session.cursor == 2
    assert app.sel == 2


def test_navigation_lands_on_the_finding_not_on_a_page_about_it():
    """Detected by the cursor moving, not by the command's name, so anything
    else that navigates behaves the same way."""
    app = _app([_finding(i) for i in range(5)])
    for ch in "/next":
        app.handle(ch)
    app.handle(ENTER)
    assert app.view == DETAIL
    assert app.view != OUTPUT


def test_a_command_that_does_not_navigate_still_shows_its_output():
    app = _app([_finding(i) for i in range(5)])
    for ch in "/status":
        app.handle(ch)
    app.handle(ENTER)
    assert app.view == OUTPUT


def test_the_severity_badge_is_not_repeated_down_a_wrapped_title():
    """Repeated on every line, one finding read as three."""
    long_title = ("Using variable interpolation with github context data in a run "
                  "step could allow an attacker to inject their own code into the "
                  "runner and steal secrets")
    app = _app([_finding(0, title=long_title)])
    app.handle(ENTER)
    body = strip("\n".join(_frame(app)))
    assert body.count("HIGH") == 1
