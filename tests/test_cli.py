"""CLI adapter behavior (architecture §2) — thin, but a few guards matter."""
import json

from cosmo.cli import main


def test_review_nonexistent_local_target_errors_cleanly(capsys):
    # A bogus local path (e.g. an unset $VAR expanding to garbage) must fail fast
    # with a clear message, not scan the wrong tree or crash writing a cache.
    code = main(["review", "/no/such/path/really-xyz"])
    out = capsys.readouterr().out
    assert code == 2
    assert "does not exist" in out


def test_review_pr_ref_skips_local_path_check(monkeypatch):
    # A PR ref is remote, so the existence check must not reject it. Stub the
    # engine so no network/gh is touched.
    import cosmo.cli as cli
    from cosmo.findings import Report
    monkeypatch.setattr(cli, "run_review",
                        lambda *a, **k: Report(target="o/r#1", findings=[], skipped_stages=[], notes=[]))
    assert main(["review", "owner/repo#1"]) == 0


# --- the report is the result; the live panel is only a summary -------------

def _stub_engine(monkeypatch, findings=()):
    import cosmo.cli as cli
    from cosmo.findings import Report
    report = Report(target=".", findings=list(findings),
                    skipped_stages=["static:semgrep (not installed)"], notes=[])
    monkeypatch.setattr(cli, "run_review", lambda *a, **k: report)
    return report


def _finding():
    from cosmo.findings import Finding
    from cosmo.severity import Severity
    return Finding(id="f1", title="hardcoded credential", severity=Severity.HIGH,
                   source="static", file="app.py", line=3, fingerprint="deadbeef")


def test_live_does_not_suppress_the_text_report(monkeypatch, capsys, tmp_path):
    """`--live` used to skip render_cli on a TTY, so a live run finished with
    only the verdict panel — eight clipped titles and nothing to triage from."""
    _stub_engine(monkeypatch, [_finding()])
    monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
    assert main(["review", str(tmp_path), "--live", "--no-color"]) == 1
    assert "hardcoded credential" in capsys.readouterr().out


def test_report_flag_writes_a_markdown_file(monkeypatch, capsys, tmp_path):
    _stub_engine(monkeypatch, [_finding()])
    dest = tmp_path / "report.md"
    assert main(["review", str(tmp_path), "--report", str(dest)]) == 1
    text = dest.read_text()
    assert "# cosmo security report" in text
    assert "hardcoded credential" in text
    assert "cosmo waive" in text
    # The path is announced on stderr, so a piped --format sarif stays clean.
    err = capsys.readouterr().err
    assert str(dest) in err


def test_report_dash_goes_to_stdout(monkeypatch, capsys, tmp_path):
    _stub_engine(monkeypatch, [_finding()])
    assert main(["review", str(tmp_path), "--report", "-"]) == 1
    assert "# cosmo security report" in capsys.readouterr().out


def test_report_records_what_did_not_run(monkeypatch, tmp_path):
    """The coverage contract has to survive into the file, or a report becomes
    the one place an incomplete run looks complete."""
    _stub_engine(monkeypatch, [_finding()])
    dest = tmp_path / "r.md"
    main(["review", str(tmp_path), "--report", str(dest)])
    assert "static:semgrep (not installed)" in dest.read_text()


# --- `cosmo tools` ----------------------------------------------------------

def test_version_flag_prints_the_version(capsys):
    """`cosmo --version` did not exist; it exited 2 with a usage error."""
    import pytest

    from cosmo import __version__
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def _stub_tools(monkeypatch, *statuses):
    import cosmo.cli as cli
    from cosmo.versions import Status
    monkeypatch.setattr(cli, "_cmd_tools", cli._cmd_tools)   # keep the real one
    import cosmo.versions as versions
    monkeypatch.setattr(versions, "check_tools",
                        lambda check_updates=False, tools=None: list(statuses))
    monkeypatch.setattr(versions, "check_cosmo",
                        lambda check_updates=False, source="": Status(
                            name="cosmo", installed=True, version="9.9.9",
                            state="unchecked"))


def test_tools_lists_what_is_installed(monkeypatch, capsys):
    from cosmo.versions import Status
    _stub_tools(monkeypatch,
                Status(name="semgrep", installed=True, version="1.176.0",
                       state="unchecked", covers="rules", install="pip install semgrep"))
    assert main(["tools"]) == 0
    out = capsys.readouterr().out
    assert "semgrep" in out and "1.176.0" in out
    assert "--check-updates" in out          # tells you how to compare


def test_tools_exits_nonzero_when_a_scanner_is_missing(monkeypatch, capsys):
    """Usable as a CI gate: a missing scanner is missed coverage on every run."""
    from cosmo.versions import Status
    _stub_tools(monkeypatch,
                Status(name="trivy", installed=False, state="missing",
                       covers="CVEs", install="https://example.invalid"))
    assert main(["tools"]) == 1
    out = capsys.readouterr().out
    assert "not installed" in out
    assert "https://example.invalid" in out


def test_an_unknown_version_is_not_a_failure(monkeypatch, capsys):
    """Not knowing is a fact about the tool, not a verdict on it."""
    from cosmo.versions import Status
    _stub_tools(monkeypatch,
                Status(name="gitleaks", installed=True, state="unknown",
                       note="this build reports no version string",
                       covers="secrets", install="x"))
    assert main(["tools"]) == 0
    assert "no version string" in capsys.readouterr().out


def test_tools_json_is_machine_readable(monkeypatch, capsys):
    from cosmo.versions import Status
    _stub_tools(monkeypatch,
                Status(name="bandit", installed=True, version="1.9.4",
                       state="current", latest="1.9.4"))
    main(["tools", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tools"][0]["name"] == "bandit"
    assert payload["cosmo"]["version"] == "9.9.9"


# --- stopping a run cleanly -------------------------------------------------

def test_ctrl_c_is_not_a_crash(monkeypatch, capsys):
    """Ctrl-C during a scan dumped a ThreadPoolExecutor traceback, which reads
    as "cosmo broke" when what happened is "you stopped it"."""
    import cosmo.cli as cli

    def interrupted(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_main", interrupted)
    assert main(["review", "."]) == cli.INTERRUPTED == 130
    err = capsys.readouterr().err
    assert "interrupted" in err
    assert "Traceback" not in err
    assert "no report written" in err       # says what state it left behind


def test_the_interrupt_code_is_distinct_from_a_finding(monkeypatch, tmp_path):
    """A CI job must be able to tell "stopped" from "found something"."""
    import cosmo.cli as cli
    assert cli.INTERRUPTED not in (0, 1, 2)


def test_interactive_rejects_a_target_that_does_not_exist(capsys):
    """`cosmo interactive /typo` opened a session on nothing: scans returned
    zero findings and the scanners failed against an absent path, which reads
    as "your code is clean"."""
    assert main(["interactive", "/no/such/path/really-xyz"]) == 2
    assert "does not exist" in capsys.readouterr().out


def test_agent_rejects_a_target_that_does_not_exist(capsys):
    assert main(["agent", "/no/such/path/really-xyz"]) == 2
    assert "does not exist" in capsys.readouterr().out
