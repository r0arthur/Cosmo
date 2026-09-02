"""Static pre-filter — mapping tool output into the Finding shape.

Hermetic: feeds the mappers the JSON shapes semgrep and gitleaks actually
return, and stubs the subprocess call, so neither binary is required.
"""
import json
from pathlib import Path

import pytest

from cosmo.static import prefilter
from cosmo.static.prefilter import _run_gitleaks, _semgrep_remediation


def _leak(rule="github-pat", file="config.py", line=1):
    return {"RuleID": rule, "File": file, "StartLine": line,
            "Description": "a token"}


def _stub_gitleaks(monkeypatch, rows_by_mode):
    """Stand in for the gitleaks binary, writing the report it would write.

    `rows_by_mode` maps "tree"/"history" to the rows that pass should return.
    Records each argv so the test can assert how gitleaks was invoked.
    """
    calls = []

    def fake_sh(cmd, ev=None):
        calls.append(cmd)
        mode = "tree" if "--no-git" in cmd else "history"
        path = Path(cmd[cmd.index("--report-path") + 1])
        rows = rows_by_mode.get(mode)
        if rows is not None:                 # None = simulate a failed run
            path.write_text(json.dumps(rows))
        return ""

    monkeypatch.setattr(prefilter, "_sh", fake_sh)
    return calls


def test_prose_guidance_is_used_verbatim():
    meta = {"fix": "Use a parameterized query."}
    assert _semgrep_remediation(meta, {}) == "Use a parameterized query."


def test_autofix_is_labelled_as_a_replacement():
    """`extra.fix` is the text semgrep would substitute, not advice.

    The rule for `subprocess(..., shell=True)` returns the bare string "False",
    which rendered unlabelled reads as "fix: False" — worse than saying nothing.
    """
    assert _semgrep_remediation({}, {"fix": "False"}) == "replace with `False`"


def test_prose_wins_over_autofix():
    out = _semgrep_remediation({"fix": "Pass a list, not a string."},
                               {"fix": "False"})
    assert out == "Pass a list, not a string."


def test_no_fix_of_either_kind_yields_nothing():
    # The renderer only prints a fix line when this is truthy, so "" hides it.
    assert _semgrep_remediation({}, {}) == ""
    assert _semgrep_remediation({"fix": None}, {"fix": None}) == ""
    assert _semgrep_remediation({"fix": "   "}, {"fix": ""}) == ""


def test_non_string_fix_is_ignored():
    """Guards the shape, not just the value: a bool or dict must not be
    stringified into remediation advice."""
    assert _semgrep_remediation({"fix": True}, {}) == ""
    assert _semgrep_remediation({}, {"fix": {"replacement": "x"}}) == ""


# --- gitleaks: the working tree must be scanned, not just history -----------

def test_non_git_target_is_scanned_on_disk(monkeypatch, tmp_path):
    """`gitleaks detect` alone walks commits. On a directory with no history it
    scanned nothing, exited 0, and cosmo reported no findings over a plaintext
    key — so the filesystem pass is the one that must always run."""
    calls = _stub_gitleaks(monkeypatch, {"tree": [_leak()]})
    found = _run_gitleaks(str(tmp_path))
    assert len(calls) == 1 and "--no-git" in calls[0]     # no .git → tree only
    assert [f.title for f in found] == ["Secret leaked: github-pat"]


def test_git_target_is_scanned_both_ways(monkeypatch, tmp_path):
    """A secret uncommitted in the tree and one deleted but still in history are
    different failures; neither pass alone catches both."""
    (tmp_path / ".git").mkdir()
    calls = _stub_gitleaks(monkeypatch, {
        "tree": [_leak(file="uncommitted.py")],
        "history": [_leak(file="deleted.py")],
    })
    found = _run_gitleaks(str(tmp_path))
    assert len(calls) == 2
    assert "--no-git" in calls[0] and "--no-git" not in calls[1]
    assert {f.file for f in found} == {"uncommitted.py", "deleted.py"}


def test_a_secret_in_both_passes_is_reported_once(monkeypatch, tmp_path):
    """The passes overlap on anything committed and still on disk."""
    (tmp_path / ".git").mkdir()
    _stub_gitleaks(monkeypatch, {"tree": [_leak()], "history": [_leak()]})
    assert len(_run_gitleaks(str(tmp_path))) == 1


def test_a_failed_scan_is_raised_not_reported_as_clean(monkeypatch, tmp_path):
    """gitleaks exits 1 on leaks found, so the exit code cannot distinguish
    success from failure — a missing report is the signal that it did not run.
    Swallowing that would present an empty result as a clean scan."""
    _stub_gitleaks(monkeypatch, {"tree": None})
    with pytest.raises(RuntimeError, match="no report"):
        _run_gitleaks(str(tmp_path))


def test_leaks_are_marked_security_sensitive(monkeypatch, tmp_path):
    """A live credential must reach the public-comment gate as withholdable."""
    _stub_gitleaks(monkeypatch, {"tree": [_leak()]})
    f = _run_gitleaks(str(tmp_path))[0]
    assert f.security_sensitive is True
    assert f.category == "CWE-798"


def test_report_file_is_cleaned_up(monkeypatch, tmp_path):
    _stub_gitleaks(monkeypatch, {"tree": [_leak()]})
    _run_gitleaks(str(tmp_path))
    assert not list(tmp_path.glob(".cosmo-gitleaks*"))
