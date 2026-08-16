"""Whole-project LLM audit — chunked per-file review with a hard call budget.

Hermetic: a fake provider counts calls; no real model is invoked. The
load-bearing property is that the audit NEVER exceeds `llm_audit.max_files`, and
un-audited files are surfaced rather than silently dropped.
"""
from cosmo.audit import audit_call_budget, chunk_by_file, run_llm_audit
from cosmo.config import Config, load_config
from cosmo.diff.resolver import Diff, DiffFile, Hunk
from cosmo.engine import run_review
from cosmo.findings import Finding
from cosmo.severity import Severity


def _diff(n_files: int) -> Diff:
    files = []
    for i in range(n_files):
        h = Hunk(header="@@", added=[(1, f"secret_{i} = 'x'")])
        files.append(DiffFile(path=f"f{i}.py", hunks=[h]))
    return Diff(source="local", target=".", files=files)


class _CountingProvider:
    name = "fake"
    vendor = "local"
    exports_source = False
    roles = {"primary_review"}

    def __init__(self):
        self.calls = 0
        self.seen_paths = []

    def available(self):
        return True

    def review(self, diff, context, findings_so_far):
        self.calls += 1
        path = diff.files[0].path
        self.seen_paths.append(path)
        # one finding per file, tagged with the file so we can check aggregation
        return [Finding(id=f"m-{path}", title=f"issue in {path}", severity=Severity.MEDIUM,
                        source="model:fake", file=path, line=1)]


# --- chunking ---------------------------------------------------------------

def test_chunk_is_one_file_each():
    chunks = chunk_by_file(_diff(4))
    assert len(chunks) == 4
    assert all(len(c.files) == 1 for c in chunks)
    assert [c.files[0].path for c in chunks] == ["f0.py", "f1.py", "f2.py", "f3.py"]

def test_chunk_clears_raw_for_per_file_prompt():
    assert all(c.raw == "" for c in chunk_by_file(_diff(3)))


# --- the hard call budget (load-bearing) ------------------------------------

def test_audit_never_exceeds_budget():
    cfg = Config(data={"llm_audit": {"max_files": 3}})
    p = _CountingProvider()
    notes, skipped = [], []
    out = run_llm_audit(_diff(10), p, "", [], cfg, notes, skipped)
    assert p.calls == 3                       # exactly the budget, not 10
    assert p.seen_paths == ["f0.py", "f1.py", "f2.py"]
    assert len(out) == 3                       # findings aggregated across chunks

def test_unaudited_remainder_is_reported_not_dropped():
    cfg = Config(data={"llm_audit": {"max_files": 2}})
    notes, skipped = [], []
    run_llm_audit(_diff(5), _CountingProvider(), "", [], cfg, notes, skipped)
    joined = " ".join(notes)
    assert "reviewed 2/5" in joined
    assert "3 file(s) NOT audited" in joined

def test_progress_is_reported_per_file():
    lines = []
    cfg = Config(data={"llm_audit": {"max_files": 50}})
    run_llm_audit(_diff(3), _CountingProvider(), "", [], cfg, [], [],
                  progress=lines.append)
    joined = "\n".join(lines)
    assert "[1/3] f0.py" in joined
    assert "[2/3] f1.py" in joined
    assert "[3/3] f2.py" in joined       # each file announced before its review

def test_under_budget_reviews_all():
    cfg = Config(data={"llm_audit": {"max_files": 50}})
    p = _CountingProvider()
    run_llm_audit(_diff(4), p, "", [], cfg, [], [])
    assert p.calls == 4

def test_default_budget_when_unset():
    assert audit_call_budget(Config(data={})) == 50


# --- a per-file error is isolated, doesn't sink the audit -------------------

def test_one_file_error_is_recorded_and_audit_continues():
    class _Flaky(_CountingProvider):
        def review(self, diff, context, findings_so_far):
            self.calls += 1
            path = diff.files[0].path
            if path == "f1.py":
                raise RuntimeError("boom")
            return [Finding(id=f"m-{path}", title="ok", severity=Severity.LOW,
                            source="model:fake", file=path, line=1)]
    p = _Flaky()
    notes, skipped = [], []
    out = run_llm_audit(_diff(3), p, "", [], Config(data={"llm_audit": {"max_files": 50}}),
                        notes, skipped)
    assert p.calls == 3                        # kept going past the failure
    assert len(out) == 2                        # f0, f2 succeeded
    assert any("audit f1.py (error" in s for s in skipped)


# --- config trust tier: a repo may only LOWER the budget --------------------

def test_repo_can_lower_budget(tmp_path):
    (tmp_path / "cosmo.yaml").write_text("llm_audit:\n  max_files: 5\n")
    cfg = load_config(str(tmp_path))            # operator default is 50
    assert audit_call_budget(cfg) == 5

def test_repo_cannot_raise_budget_above_operator(tmp_path):
    (tmp_path / "cosmo.yaml").write_text("llm_audit:\n  max_files: 9999\n")
    cfg = load_config(str(tmp_path))            # operator ceiling 50 → clamped
    assert audit_call_budget(cfg) == 50
    assert any("max_files" in w for w in cfg.warnings)


# --- engine integration -----------------------------------------------------

def test_run_review_audit_routes_through_per_file_path(monkeypatch, tmp_path):
    import cosmo.engine as engine
    monkeypatch.setattr(engine, "resolve_diff", lambda target: _diff(3))
    p = _CountingProvider()
    cfg = Config(data={"llm_audit": {"max_files": 50}, "threshold": "info",
                       "incremental": {"enabled": False}})
    report = run_review(str(tmp_path), cfg, provider=p, audit=True)
    assert p.calls == 3                                    # one call per file
    assert sorted(p.seen_paths) == ["f0.py", "f1.py", "f2.py"]
    assert any("llm-audit: reviewed 3/3" in n for n in report.notes)

def test_run_review_without_audit_is_single_call(monkeypatch, tmp_path):
    import cosmo.engine as engine
    monkeypatch.setattr(engine, "resolve_diff", lambda target: _diff(3))
    p = _CountingProvider()
    cfg = Config(data={"threshold": "info", "incremental": {"enabled": False}})
    run_review(str(tmp_path), cfg, provider=p, audit=False)
    assert p.calls == 1                                    # whole diff in one prompt
