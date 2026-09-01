"""Whole-project LLM audit — chunked per-file review with a hard call budget.

Hermetic: a fake provider counts calls; no real model is invoked. The
load-bearing property is that the audit NEVER exceeds `llm_audit.max_files`, and
un-audited files are surfaced rather than silently dropped.
"""
import threading

from cosmo.audit import (
    audit_call_budget,
    audit_concurrency,
    chunk_by_file,
    run_llm_audit,
)
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
        # The audit reviews several files at once, so the bookkeeping this fake
        # does is itself concurrent — unguarded `+= 1` would lose calls.
        self._lock = threading.Lock()

    def available(self):
        return True

    def _record(self, path):
        with self._lock:
            self.calls += 1
            self.seen_paths.append(path)

    def review(self, diff, context, findings_so_far):
        path = diff.files[0].path
        self._record(path)
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
    # The budget truncates from the front, so *which* files is fixed; the order
    # they're reviewed in is not, since reviews run concurrently.
    assert sorted(p.seen_paths) == ["f0.py", "f1.py", "f2.py"]
    assert len(out) == 3                       # findings aggregated across chunks

def test_unaudited_remainder_is_reported_not_dropped():
    cfg = Config(data={"llm_audit": {"max_files": 2}})
    notes, skipped = [], []
    run_llm_audit(_diff(5), _CountingProvider(), "", [], cfg, notes, skipped)
    joined = " ".join(notes)
    assert "reviewed 2/5" in joined
    assert "3 file(s) NOT audited" in joined

def test_progress_is_reported_per_file():
    """Every file gets a progress line and the counter runs 1..N.

    Which file carries which number is deliberately not asserted: reviews finish
    out of order, so the count is a completion count, not an input index.
    """
    lines = []
    cfg = Config(data={"llm_audit": {"max_files": 50}})
    run_llm_audit(_diff(3), _CountingProvider(), "", [], cfg, [], [],
                  progress=lines.append)
    joined = "\n".join(lines)
    for path in ("f0.py", "f1.py", "f2.py"):
        assert path in joined
    for n in (1, 2, 3):
        assert f"[{n}/3]" in joined

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


# --- concurrency -------------------------------------------------------------

def test_reviews_actually_run_concurrently():
    """Four reviews must be in flight at once.

    The barrier only releases when all four threads are inside `review`
    simultaneously — a sequential loop would block on the first `wait()` and
    fail the run rather than pass slowly.
    """
    barrier = threading.Barrier(4, timeout=10)

    class _Barrier(_CountingProvider):
        def review(self, diff, context, findings_so_far):
            barrier.wait()
            return super().review(diff, context, findings_so_far)

    cfg = Config(data={"llm_audit": {"max_files": 50, "concurrency": 4}})
    out = run_llm_audit(_diff(4), _Barrier(), "", [], cfg, [], [])
    assert len(out) == 4


def test_concurrency_one_reviews_in_file_order():
    cfg = Config(data={"llm_audit": {"max_files": 50, "concurrency": 1}})
    p = _CountingProvider()
    run_llm_audit(_diff(4), p, "", [], cfg, [], [])
    assert p.seen_paths == ["f0.py", "f1.py", "f2.py", "f3.py"]


def test_findings_keep_input_order_when_completion_order_is_reversed():
    """Completion order must not leak into the report.

    f0 is held until f3 has finished, so the *last* file to complete is the one
    whose findings must still come first.
    """
    f3_done = threading.Event()

    class _F0Last(_CountingProvider):
        def review(self, diff, context, findings_so_far):
            path = diff.files[0].path
            if path == "f0.py":
                assert f3_done.wait(timeout=10), "f3 never completed"
            out = super().review(diff, context, findings_so_far)
            if path == "f3.py":
                f3_done.set()
            return out

    cfg = Config(data={"llm_audit": {"max_files": 50, "concurrency": 4}})
    out = run_llm_audit(_diff(4), _F0Last(), "", [], cfg, [], [])
    assert [f.file for f in out] == ["f0.py", "f1.py", "f2.py", "f3.py"]


def test_budget_still_holds_under_concurrency():
    """Concurrency changes the rate, never the number of calls."""
    cfg = Config(data={"llm_audit": {"max_files": 3, "concurrency": 8}})
    p = _CountingProvider()
    run_llm_audit(_diff(20), p, "", [], cfg, [], [])
    assert p.calls == 3


def test_each_review_sees_only_the_stable_baseline():
    """One file's review never sees another's findings.

    That cross-file accumulator is exactly what would make the result depend on
    scheduling — and it grew the prompt with every file reviewed.
    """
    seen = []
    seen_lock = threading.Lock()

    class _Recorder(_CountingProvider):
        def review(self, diff, context, findings_so_far):
            with seen_lock:
                seen.append([f.id for f in findings_so_far])
            return super().review(diff, context, findings_so_far)

    base = [Finding(id="b1", title="baseline", severity=Severity.LOW,
                    source="static", file="x.py", line=1)]
    cfg = Config(data={"llm_audit": {"max_files": 50, "concurrency": 4}})
    run_llm_audit(_diff(4), _Recorder(), "", base, cfg, [], [])
    assert seen == [["b1"]] * 4


def test_error_in_one_file_is_isolated_under_concurrency():
    class _Flaky(_CountingProvider):
        def review(self, diff, context, findings_so_far):
            if diff.files[0].path == "f2.py":
                self._record("f2.py")
                raise RuntimeError("boom")
            return super().review(diff, context, findings_so_far)

    cfg = Config(data={"llm_audit": {"max_files": 50, "concurrency": 4}})
    skipped = []
    out = run_llm_audit(_diff(5), _Flaky(), "", [], cfg, [], skipped)
    assert [f.file for f in out] == ["f0.py", "f1.py", "f3.py", "f4.py"]
    assert any("audit f2.py (error" in s for s in skipped)


def test_default_concurrency_when_unset():
    assert audit_concurrency(Config(data={})) == 4


def test_concurrency_floor_is_one():
    # 0 would reach ThreadPoolExecutor, which rejects it.
    assert audit_concurrency(Config(data={"llm_audit": {"concurrency": 0}})) == 1


def test_repo_can_lower_concurrency(tmp_path):
    (tmp_path / "cosmo.yaml").write_text("llm_audit:\n  concurrency: 2\n")
    assert audit_concurrency(load_config(str(tmp_path))) == 2


def test_repo_cannot_raise_concurrency_above_operator(tmp_path):
    (tmp_path / "cosmo.yaml").write_text("llm_audit:\n  concurrency: 64\n")
    cfg = load_config(str(tmp_path))            # operator ceiling 4 → clamped
    assert audit_concurrency(cfg) == 4
    assert any("concurrency" in w for w in cfg.warnings)


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
