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
