"""Static pre-filter — mapping tool output into the Finding shape.

Hermetic: feeds the mappers the JSON shapes semgrep and gitleaks actually
return, and stubs the subprocess call, so neither binary is required.
"""
import json
import subprocess
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

    def fake_sh(cmd, ev=None, timeout=None):
        calls.append(cmd)
        mode = "tree" if "--no-git" in cmd else "history"
        rows = rows_by_mode.get(mode)
        if isinstance(rows, Exception):      # simulate a timeout / crash
            raise rows
        path = Path(cmd[cmd.index("--report-path") + 1])
        if rows is not None:                 # None = ran but wrote no report
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


def test_history_timeout_keeps_tree_results_and_reports_the_shortfall(
        monkeypatch, tmp_path):
    """The history pass walks every commit, and on a partial clone each blob is
    a network fetch — it can run for minutes. Timing out must not discard the
    tree findings, nor pass tree-only coverage off as a full scan.
    """
    (tmp_path / ".git").mkdir()
    _stub_gitleaks(monkeypatch, {
        "tree": [_leak(file="live.py")],
        "history": subprocess.TimeoutExpired(cmd="gitleaks", timeout=60),
    })
    skipped: list[str] = []
    found = _run_gitleaks(str(tmp_path), None, skipped)

    assert [f.file for f in found] == ["live.py"]     # tree results survive
    assert any("history pass timed out" in s for s in skipped)
    assert not list(tmp_path.glob(".cosmo-gitleaks*"))   # still cleaned up


def test_a_timeout_does_not_sink_the_stage(monkeypatch, tmp_path):
    """A partial result is not a failed one — the caller records `skipped`
    itself, so nothing should propagate out of the runner."""
    (tmp_path / ".git").mkdir()
    _stub_gitleaks(monkeypatch, {
        "tree": [],
        "history": subprocess.TimeoutExpired(cmd="gitleaks", timeout=60),
    })
    assert _run_gitleaks(str(tmp_path), None, []) == []   # no exception


# --- evidence has to be triageable ------------------------------------------

def test_semgrep_evidence_is_built_from_fields_that_actually_carry_data():
    """`extra.lines` — the matched source — reads "requires login" on the OSS
    engine, so evidence built on it would print that string instead of code."""
    from cosmo.static.prefilter import _semgrep_evidence

    meta = {
        "cwe": ["CWE-502: Deserialization of Untrusted Data"],
        "owasp": ["A08:2021 - Software and Data Integrity Failures"],
        "confidence": "MEDIUM", "impact": "HIGH", "likelihood": "MEDIUM",
        "shortlink": "https://sg.run/NwQy",
        "references": ["https://blog.trailofbits.com/never-a-dill-moment/"],
    }
    out = _semgrep_evidence("trailofbits.python.pickles-in-pytorch", meta)
    assert "trailofbits.python.pickles-in-pytorch" in out
    assert "confidence=MEDIUM" in out and "impact=HIGH" in out
    assert "CWE-502: Deserialization of Untrusted Data" in out
    assert "https://sg.run/NwQy" in out
    assert "requires login" not in out


def test_semgrep_evidence_survives_a_bare_rule():
    from cosmo.static.prefilter import _semgrep_evidence
    assert _semgrep_evidence("some.rule", {}) == "semgrep rule: some.rule"


def test_a_secret_is_never_copied_into_the_evidence():
    """A report is a file that gets attached to tickets. Copying the credential
    into it mints a second live copy of the thing the finding says to rotate."""
    from cosmo.static.prefilter import _gitleaks_evidence

    secret = "phc_aBzNGHzlOy2C8n1BBDtH7d4qQsIw9d8T0unVlnKfdxB"
    out = _gitleaks_evidence({
        "RuleID": "generic-api-key", "Description": "Generic API Key",
        "Match": f"KEY = '{secret}'", "Secret": secret, "Entropy": "5.01"})
    assert secret not in out
    assert "phc_aB" in out          # ...but enough to recognise a PostHog key
    assert "generic-api-key" in out
    assert "5.01" in out


def test_a_short_secret_is_redacted_wholesale():
    from cosmo.static.prefilter import _gitleaks_evidence
    out = _gitleaks_evidence({"RuleID": "r", "Secret": "abc123", "Match": "k=abc123"})
    assert "abc123" not in out
    assert "redacted" in out


def test_commit_provenance_reaches_the_evidence():
    from cosmo.static.prefilter import _gitleaks_evidence
    out = _gitleaks_evidence({
        "RuleID": "jwt", "Secret": "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaa.bbbb",
        "Commit": "9f1c2d3e4b5a6789", "Author": "Test Dev",
        "Date": "2023-04-01T10:00:00Z"})
    assert "9f1c2d3e4b5a" in out
    assert "Test Dev" in out
    assert "2023-04-01" in out


def test_overlapping_passes_keep_the_row_that_knows_the_commit(monkeypatch, tmp_path):
    """The tree pass runs first and reports no commit. Dropping the later
    duplicate would throw away when the secret entered the repo."""
    from cosmo.static import prefilter

    (tmp_path / ".git").mkdir()
    tree_row = {"RuleID": "jwt", "File": "a.py", "StartLine": "3",
                "Secret": "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaa.bbbb", "Commit": ""}
    hist_row = dict(tree_row, Commit="abc123def456")

    calls = []

    def fake_scan(root, mode_args, tag, ev=None, timeout=None):
        calls.append(tag)
        return [tree_row] if tag == "tree" else [hist_row]

    monkeypatch.setattr(prefilter, "_gitleaks_scan", fake_scan)
    out = prefilter._run_gitleaks(str(tmp_path))
    assert calls == ["tree", "history"]
    assert len(out) == 1                       # still deduped
    assert "abc123def456" in out[0].evidence   # ...to the richer row
