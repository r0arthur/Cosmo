"""CLI adapter behavior (architecture §2) — thin, but a few guards matter."""
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
