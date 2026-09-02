"""The structured event layer the live UI renders (`cosmo review --live`).

The properties that matter: instrumentation cannot change the review, the stage
list stays in step with what the engine actually runs, and a cached run reports
the same coverage as a cold one.
"""
import subprocess
import threading

from cosmo.config import Config
from cosmo.engine import run_review
from cosmo.events import STAGES, Emitter, Event, Kind
from cosmo.findings import Finding
from cosmo.severity import Severity


class _Provider:
    name = "fake"
    vendor = "local"
    exports_source = False
    roles = {"primary_review"}

    def available(self):
        return True

    def review(self, diff, context, findings_so_far):
        return [Finding(id="m-1", title="hardcoded credential", severity=Severity.HIGH,
                        source="model:fake", file="app.py", line=1)]


def _target(tmp_path):
    (tmp_path / "app.py").write_text("password = 'hunter2'\n")
    return str(tmp_path)


def _cfg(**over):
    data = {"threshold": "info", "incremental": {"enabled": False}}
    data.update(over)
    return Config(data=data)


def _collect(tmp_path, **kw):
    seen: list[Event] = []
    report = run_review(_target(tmp_path), _cfg(), provider=_Provider(),
                        events=seen.append, **kw)
    return report, seen


# --- the emitter is inert without a sink ------------------------------------

def test_emitter_without_sink_is_a_noop():
    ev = Emitter(None)
    assert not ev
    ev.stage_started("static")          # must not raise
    ev.error("boom", stage="llm")


def test_emitter_forwards_to_its_sink():
    seen = []
    ev = Emitter(seen.append)
    assert ev
    ev.stage_started("static")
    ev.finding("SQL injection", detail="app.py:4", severity="high")
    assert [e.kind for e in seen] == [Kind.STAGE_STARTED, Kind.FINDING]
    assert seen[1].data["severity"] == "high"


# --- instrumentation must not change the review -----------------------------

def test_events_do_not_change_the_report(tmp_path):
    silent = run_review(_target(tmp_path), _cfg(), provider=_Provider())
    loud, _ = _collect(tmp_path)
    assert [f.title for f in silent.findings] == [f.title for f in loud.findings]
    assert silent.skipped_stages == loud.skipped_stages


# --- the stage list is the engine's, not a parallel invention ---------------

def test_every_emitted_stage_is_a_declared_stage(tmp_path):
    """Guards against the engine growing a stage the UI can't place."""
    _, seen = _collect(tmp_path)
    declared = {sid for sid, _ in STAGES}
    emitted = {e.stage for e in seen if e.stage}
    assert emitted <= declared, f"undeclared stage(s): {emitted - declared}"


def test_shared_stage_ids_resolve_to_the_review_wording():
    """`review` and `history` share four stage ids, and only one flat label map
    serves both. Review wins it, because a review is the common path — a
    `cosmo review` once announced "Review each commit; check findings against
    HEAD". History passes its own wording explicitly instead.
    """
    from cosmo.events import HISTORY_STAGES, STAGE_LABELS
    shared = set(dict(STAGES)) & set(dict(HISTORY_STAGES))
    assert "llm" in shared
    for sid in shared:
        assert STAGE_LABELS[sid] == dict(STAGES)[sid]

    seen: list[Event] = []
    Emitter(seen.append).stage_started("llm")
    assert seen[0].message == "AI security review"


def test_history_stage_keeps_its_own_wording(tmp_path):
    """The explicit label in the sweep must survive the shared-id collision."""
    from cosmo.history import Selection, run_history_sweep

    (tmp_path / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for cmd in (["config", "user.email", "t@t.test"], ["config", "user.name", "t"],
                ["add", "a.py"], ["commit", "-q", "-m", "one"]):
        subprocess.run(["git", "-C", str(tmp_path), *cmd], check=True)

    seen: list[Event] = []
    cfg = Config(data={"history": {"max_commits": 5}})
    run_history_sweep(str(tmp_path), _Provider(), cfg,
                      selection=Selection(), events=seen.append)
    started = [e.message for e in seen
               if e.kind is Kind.STAGE_STARTED and e.stage == "llm"]
    assert started == ["Review each commit; check findings against HEAD"]


def test_objective_brackets_the_run(tmp_path):
    _, seen = _collect(tmp_path)
    assert seen[0].kind is Kind.OBJECTIVE_STARTED
    assert seen[-1].kind is Kind.OBJECTIVE_COMPLETED
    assert seen[-1].data["findings"] == 1


def test_pipeline_reports_the_stages_it_ran(tmp_path):
    _, seen = _collect(tmp_path)
    started = [e.stage for e in seen if e.kind is Kind.STAGE_STARTED]
    # The spine of the pipeline, in engine order.
    for stage in ("resolve", "static", "provider", "llm", "dedupe", "waiver", "threshold"):
        assert stage in started


def test_findings_are_emitted_with_their_location(tmp_path):
    _, seen = _collect(tmp_path)
    found = [e for e in seen if e.kind is Kind.FINDING]
    assert len(found) == 1
    assert found[0].detail == "app.py:1"
    assert found[0].data["severity"] == "high"


def test_unavailable_provider_is_reported_as_skipped_not_silent(tmp_path):
    class _Down(_Provider):
        def available(self):
            return False

    seen = []
    run_review(_target(tmp_path), _cfg(), provider=_Down(), events=seen.append)
    skips = [e for e in seen if e.kind is Kind.STAGE_SKIPPED]
    assert any(e.stage == "llm" for e in skips)


# --- an oversized target must be refused, not attempted ---------------------

def test_a_target_too_big_for_one_prompt_is_refused_up_front(tmp_path):
    """Whole-tree mode sends every file in a single prompt. On a real repo that
    reached 33MB — 42x a 200k-token window — and the provider only rejected it
    after cosmo had built it and retried three times with backoff. The refusal
    has to happen before the call, and has to name the flag that does work.
    """
    from cosmo.engine import MAX_SINGLE_PROMPT_CHARS

    big = "x" * 2000 + "\n"
    for i in range(MAX_SINGLE_PROMPT_CHARS // 2000 + 10):
        (tmp_path / f"f{i}.py").write_text(big)

    class _MustNotBeCalled(_Provider):
        def review(self, diff, context, findings_so_far):
            raise AssertionError("the model was called with an oversized prompt")

    seen: list[Event] = []
    report = run_review(str(tmp_path), _cfg(), provider=_MustNotBeCalled(),
                        events=seen.append)
    reason = next(s for s in report.skipped_stages if "too large" in s)
    assert "--audit" in reason                      # names the way forward
    assert any(e.kind is Kind.STAGE_SKIPPED and e.stage == "llm" for e in seen)


def test_a_normal_target_is_not_refused(tmp_path):
    """The guard must not fire on anything of ordinary size."""
    _, seen = _collect(tmp_path)
    assert not any("too large" in (e.message or "") for e in seen)


def test_prompt_size_estimate_tracks_the_builder(tmp_path):
    """The estimate stands in for a prompt we deliberately never build.

    It only has to be right to an order of magnitude — its job is catching a
    target 42x past the window, not predicting the prompt to the byte. Measured
    on real content rather than a toy input, where the fixed
    "# Diff for {target}" header would dominate and prove nothing.
    """
    from cosmo.diff import resolve_diff
    from cosmo.engine import _single_prompt_size
    from cosmo.providers.parse import build_review_prompt

    for i in range(20):
        (tmp_path / f"f{i}.py").write_text("".join(
            f"value_{n} = compute(n={n})\n" for n in range(50)))
    d = resolve_diff(str(tmp_path))
    actual = len(build_review_prompt(d, "ctx", []))
    estimate = _single_prompt_size(d, "ctx")
    assert actual > 20_000                       # enough content to be meaningful
    assert 0.8 * actual <= estimate <= 1.2 * actual


# --- a cached run must report the same coverage as a cold one ---------------

def test_cached_static_run_still_reports_what_was_skipped(tmp_path):
    """A cache hit bypasses the static runner; its skipped-stage records must be
    replayed, or a warm run claims coverage it never had."""
    cfg = Config(data={"threshold": "info", "incremental": {"enabled": True}})
    target = _target(tmp_path)
    cold = run_review(target, cfg, provider=_Provider())
    warm = run_review(target, cfg, provider=_Provider())
    assert sorted(cold.skipped_stages) == sorted(warm.skipped_stages)
    assert any("dep-audit" in s for s in warm.skipped_stages)


# --- sinks are called from audit worker threads -----------------------------

def test_sink_receives_events_from_concurrent_workers(tmp_path):
    """A whole-project audit reviews several files at once, so the sink is a
    shared object touched by every worker."""
    for i in range(6):
        (tmp_path / f"f{i}.py").write_text(f"token_{i} = 'x'\n")
    seen = []
    lock = threading.Lock()

    def sink(e):
        with lock:
            seen.append(e)

    cfg = Config(data={"threshold": "info", "incremental": {"enabled": False},
                       "llm_audit": {"max_files": 50, "concurrency": 4}})
    run_review(str(tmp_path), cfg, provider=_Provider(), audit=True, events=sink)
    api = [e for e in seen if e.kind is Kind.API_REQUEST]
    assert len(api) >= 6          # one per audited file, none lost
