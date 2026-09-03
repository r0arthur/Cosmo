"""End-to-end smoke test: the pipeline runs with no external tools / no API key.

Static runners are skipped (not installed in CI), the Claude provider is
unavailable (no key) — both recorded, not fatal. A Report is still produced.
"""
from cosmo.config import load_config
from cosmo.engine import run_review


def test_pipeline_runs_without_tools_or_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / "app.py").write_text("password = 'hunter2'\n")

    cfg = load_config(tmp_path)
    report = run_review(str(tmp_path), cfg)

    assert report.target == str(tmp_path)
    # The stages that couldn't run are surfaced, never silently dropped.
    assert any("dep-audit" in s for s in report.skipped_stages)
    assert any("model:claude" in s for s in report.skipped_stages)


def test_injected_provider_findings_flow_through(tmp_path, monkeypatch):
    from cosmo.findings import Finding
    from cosmo.severity import Severity

    (tmp_path / "app.py").write_text("+ os.system(x)\n")

    class FakeProvider:
        name = "claude"

        def available(self):
            return True

        def review(self, diff, context, findings_so_far):
            return [Finding(id="m0", title="Command injection", severity=Severity.CRITICAL,
                            source="model:claude", file="app.py", line=1,
                            security_sensitive=True)]

    cfg = load_config(tmp_path)
    report = run_review(str(tmp_path), cfg, provider=FakeProvider())
    titles = [f.title for f in report.findings]
    assert "Command injection" in titles
    # Fingerprint got stamped by the waiver stage.
    assert all(f.fingerprint for f in report.findings)


def test_static_only_never_reaches_the_model(tmp_path):
    """`/scan` (without `llm`) must not send anything to a provider — and must
    say it did not, rather than blaming a missing key."""
    from cosmo.config import Config
    from cosmo.engine import run_review

    (tmp_path / "app.py").write_text("import os\nos.system(cmd)\n")
    calls = []

    class _Provider:
        name = "fake"
        vendor = "local"
        exports_source = True
        roles = {"primary_review"}

        def available(self):
            return True

        def review(self, diff, context, findings_so_far):
            calls.append(1)
            return []

    cfg = Config(data={"incremental": {"enabled": False}})
    report = run_review(str(tmp_path), cfg, provider=_Provider(), static_only=True)
    assert calls == []
    reason = next(s for s in report.skipped_stages if "model review" in s)
    assert "not requested" in reason
    assert "unavailable" not in reason      # it was available; we did not ask
