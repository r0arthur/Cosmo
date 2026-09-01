"""The live review UI (`cosmo review --live`).

It is a rendering of the engine's event stream, so the tests here check that it
reflects what the engine reported — stages, coverage, verdict — and that it
never writes to stdout or invents a stage of its own.
"""
import io
import threading

from cosmo.events import STAGES, Emitter, Event, Kind
from cosmo.findings import Finding, Report
from cosmo.live import ACTIVE, DONE, PENDING, SKIPPED, LiveUI, _clip, _dur
from cosmo.severity import Severity


def _ui(**kw):
    kw.setdefault("color", False)
    kw.setdefault("tick", 3600)          # no background repaint during tests
    return LiveUI(stream=io.StringIO(), **kw)


def _report(*findings):
    return Report(target=".", findings=list(findings),
                  skipped_stages=["static:semgrep (not installed)"], notes=[])


def _finding(sev=Severity.HIGH, title="SQL injection", waived=False):
    return Finding(id="f1", title=title, severity=sev, source="model:fake",
                   file="app.py", line=12, waived=waived)


# --- it is a usable sink ----------------------------------------------------

def test_ui_is_an_event_sink():
    ui = _ui()
    Emitter(ui).stage_started("static")
    assert "Static pre-filter" in ui._out.getvalue()


def test_non_tty_streams_one_line_per_event():
    ui = _ui()
    ev = Emitter(ui)
    ev.stage_started("static")
    ev.execute(["semgrep", "--config", "auto", "."])
    ev.output("semgrep: 3 finding(s)")
    lines = [ln for ln in ui._out.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 3
    assert "EXECUTE" in lines[1] and "semgrep --config auto ." in lines[1]
    assert "OUTPUT" in lines[2]


def test_no_ansi_when_color_is_off():
    ui = _ui()
    Emitter(ui).error("boom", stage="llm")
    assert "\033[" not in ui._out.getvalue()


# --- stage bookkeeping mirrors the engine -----------------------------------

def test_stage_lifecycle_tracks_status():
    ui = _ui()
    ev = Emitter(ui)
    assert ui._state.stage_status["static"] == PENDING
    ev.stage_started("static")
    assert ui._state.stage_status["static"] == ACTIVE
    ev.stage_completed("static")
    assert ui._state.stage_status["static"] == DONE


def test_completed_stage_outranks_a_partial_skip():
    """The static stage still ran when only one of its tools was missing."""
    ui = _ui()
    ev = Emitter(ui)
    ev.stage_started("static")
    ev.stage_skipped("static", "semgrep not installed")
    ev.stage_completed("static", "0 finding(s)")
    assert ui._state.stage_status["static"] == DONE
    assert "semgrep not installed" in ui._state.skips


def test_a_wholly_skipped_stage_stays_skipped():
    ui = _ui()
    ev = Emitter(ui)
    ev.stage_started("llm")
    ev.stage_skipped("llm", "model:claude unavailable")
    assert ui._state.stage_status["llm"] == SKIPPED


def test_frame_lists_every_declared_stage():
    ui = _ui()
    Emitter(ui).stage_started("static")
    frame = "\n".join(ui._frame(100, 60))
    for _, label in STAGES:
        assert label in frame


def test_frame_shows_objective_workflow_and_activity():
    ui = _ui()
    ev = Emitter(ui)
    ev.objective_started("Security review of ./app", target="./app", threshold="medium")
    ev.stage_started("static")
    ev.execute(["semgrep", "--config", "auto", "./app"])
    frame = "\n".join(ui._frame(100, 60))
    for section in ("OBJECTIVE", "WORKFLOW", "PROGRESS", "LIVE ACTIVITY"):
        assert section in frame
    assert "Security review of ./app" in frame
    assert "./app" in frame
    assert "semgrep" in frame          # the real command, in the feed


def test_progress_counts_real_stages_only():
    ui = _ui()
    ev = Emitter(ui)
    ev.stage_started("resolve")
    ev.stage_completed("resolve")
    frame = "\n".join(ui._frame(100, 60))
    assert f"1/{len(STAGES)} stages" in frame


# --- the verdict ------------------------------------------------------------

def test_final_reports_findings_and_coverage():
    ui = _ui()
    out = ui._final(_report(_finding()), exit_code=1)
    assert "REVIEW COMPLETE" in out
    assert "SQL injection" in out and "app.py:12" in out
    assert "COVERAGE" in out and "semgrep" in out
    assert "exit 1" in out


def test_final_says_clean_when_nothing_survived_the_floor():
    ui = _ui()
    ui._state.threshold = "medium"
    out = ui._final(_report(), exit_code=0)
    assert "none above the medium floor" in out
    assert "exit 0" in out


def test_waived_findings_are_counted_not_listed():
    ui = _ui()
    out = ui._final(_report(_finding(waived=True)), exit_code=0)
    assert "1 waived by baseline" in out
    assert "exit 0" in out


def test_errors_make_the_run_incomplete():
    """Findings are a successful outcome; a broken pipeline is not."""
    ui = _ui()
    Emitter(ui).error("model:claude failed: timeout", stage="llm")
    out = ui._final(_report(), exit_code=0)
    assert "REVIEW INCOMPLETE" in out
    assert "timeout" in out


def test_finish_writes_nothing_to_stdout(capsys):
    ui = _ui()
    Emitter(ui).stage_started("static")
    ui.finish(_report(_finding()), exit_code=1)
    assert capsys.readouterr().out == ""       # stdout stays clean for --format


# --- concurrency ------------------------------------------------------------

def test_sink_is_safe_under_concurrent_emission():
    """Audit workers emit in parallel; no event may be lost or interleaved."""
    ui = _ui()
    ev = Emitter(ui)
    workers, per_worker = 8, 60
    start = threading.Barrier(workers)

    def _spam():
        start.wait(timeout=10)
        for i in range(per_worker):
            ev.output(f"file{i}.py reviewed", stage="llm")

    threads = [threading.Thread(target=_spam) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    lines = [ln for ln in ui._out.getvalue().splitlines() if ln.strip()]
    assert len(lines) == workers * per_worker
    assert all("reviewed" in ln for ln in lines)


# --- helpers ----------------------------------------------------------------

def test_shorten_paths_keeps_the_identifying_tail():
    """Whole-tree mode emits absolute paths; the shared prefix is the useless part."""
    from cosmo.live import _shorten_paths
    long = "/home/me/work/checkout/src/shop/orders.py"
    assert _shorten_paths(f"reviewing {long}") == "reviewing …/shop/orders.py"
    # short paths and non-paths are left alone
    assert _shorten_paths("reviewing src/app.py") == "reviewing src/app.py"
    assert _shorten_paths("3 findings") == "3 findings"


def test_clip_path_keeps_the_tail():
    """Width-clips from the left, so the end of the path survives."""
    from cosmo.live import _clip_path
    out = _clip_path("/a/very/long/path/to/target", 12)
    assert len(out) == 12 and out.startswith("…") and out.endswith("to/target")
    assert _clip_path("short", 12) == "short"


def test_clip_collapses_whitespace_and_truncates():
    assert _clip("a   b\n c", 40) == "a b c"
    assert _clip("x" * 50, 10) == "x" * 9 + "…"


def test_dur_formats_mm_ss():
    assert _dur(0) == "00:00"
    assert _dur(75) == "01:15"
