"""CLI text renderer — the default operator-facing output.

Static-tool messages arrive as full paragraphs (semgrep's run to a couple of
hundred characters), so the renderer has to fit them to the terminal without
mangling the layout or losing the detail SARIF still needs.
"""
from cosmo.findings import Finding, Report
from cosmo.output import render_cli
from cosmo.output.cli_text import _fit
from cosmo.severity import Severity

_LONG = ("Found 'subprocess' function 'run' with 'shell=True'. This is dangerous "
         "because this call will spawn the command using a shell process. Doing "
         "so propagates current shell settings and variables.")


def _report(**kw):
    f = Finding(id="1", title=kw.pop("title", "Short title"),
                severity=kw.pop("severity", Severity.HIGH),
                source="static", file="app.py", line=7, **kw)
    return Report(target=".", findings=[f])


# --- _fit -------------------------------------------------------------------

def test_fit_leaves_short_text_alone():
    assert _fit("already short", 40) == "already short"


def test_fit_truncates_with_an_ellipsis():
    out = _fit("x" * 200, 40)
    assert len(out) == 40 and out.endswith("…")


def test_fit_collapses_tool_prose_by_default():
    """semgrep messages arrive wrapped across lines."""
    assert _fit("wrapped\n  across   lines", 60) == "wrapped across lines"


def test_fit_preserves_deliberate_spacing_when_asked():
    """The meta line composes its own '  ·  ' separators — collapsing them
    would silently restyle output the renderer built on purpose."""
    assert _fit("a  ·  b", 40, collapse=False) == "a  ·  b"


# --- rendering --------------------------------------------------------------

def test_long_titles_do_not_run_off_the_line():
    out = render_cli(_report(title=_LONG), color=False)
    assert max(len(line) for line in out.splitlines()) <= 120
    assert "…" in out


def test_the_full_title_is_kept_on_the_finding():
    """Only the display is trimmed — SARIF and the trend store still get it all."""
    r = _report(title=_LONG)
    render_cli(r, color=False)
    assert r.findings[0].title == _LONG


def test_a_fix_line_appears_only_when_there_is_one():
    with_fix = render_cli(_report(remediation="replace with `False`"), color=False)
    assert "fix: replace with `False`" in with_fix
    assert "fix:" not in render_cli(_report(remediation=""), color=False)


def test_meta_line_keeps_its_separators():
    out = render_cli(_report(category="CWE-78"), color=False)
    assert "app.py:7  ·  static  ·  CWE-78" in out


def test_skipped_stages_are_always_shown():
    """The coverage signal — a clean report must never hide what did not run."""
    r = Report(target=".", findings=[],
               skipped_stages=["static:semgrep (not installed)"])
    out = render_cli(r, color=False)
    assert "No findings at or above the configured threshold." in out
    assert "skipped: static:semgrep (not installed)" in out


def test_color_off_emits_no_escape_codes():
    assert "\033[" not in render_cli(_report(), color=False)
