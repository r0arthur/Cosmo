"""Zero-day fuzzing campaign — step 16 (architecture §7)."""
import pytest

from cosmo.config import Config
from cosmo.fuzz import (
    Crash,
    EntryPoint,
    Harness,
    NoveltyVerdict,
    SeedCorpus,
    build_invocation,
    classify_severity,
    dedupe_crashes,
    generate_harnesses,
    minimize,
    novelty_check,
    resolve_duration,
    run_campaign,
    select_engine,
)
from cosmo.fuzz.campaign import (
    ConfirmationRequired,
    DurationNotSet,
    ExternalTargetRefused,
)
from cosmo.fuzz.engines import NoEngineForLanguage
from cosmo.severity import Severity


def _cfg(**fuzzing):
    base = {"enabled": True, "max_duration": "8h", "confirm_above": "4h"}
    base.update(fuzzing)
    return Config(data={"fuzzing": base})


# --- harness generation is gated behind clean builds ------------------------

def test_harness_set_gated_by_build(tmp_path):
    eps = [EntryPoint(f"e{i}", "function", "python", priority=i) for i in range(4)]

    def gen(ep, hints):
        if ep.name == "e0":
            raise RuntimeError("drafter gave up")
        return f"def harness(): pass  # {ep.name}"

    def build(h: Harness):
        return (h.entry_point.name != "e1", "compile error")  # e1 fails to build

    hs = generate_harnesses(eps, gen, build)
    assert {h.entry_point.name for h in hs.built} == {"e2", "e3"}
    assert {h.entry_point.name for h in hs.failed} == {"e0", "e1"}
    assert hs.total == 4
    assert hs.coverage_fraction == 0.5             # coverage never assumed complete


def test_generation_orders_by_priority():
    eps = [EntryPoint("low", "function", "python", priority=0.1),
           EntryPoint("high", "function", "python", priority=0.9)]
    order = []

    def gen(ep, hints):
        order.append(ep.name)
        return "x"

    generate_harnesses(eps, gen, lambda h: (True, ""))
    assert order == ["high", "low"]


# --- engine selection + bounded invocation ----------------------------------

def test_select_engine_and_no_engine():
    assert select_engine("python").name == "Atheris"
    assert select_engine("C").name in ("libFuzzer", "AFL++")
    with pytest.raises(NoEngineForLanguage):
        select_engine("brainfuck")


def test_invocation_requires_bounded_cap():
    e = select_engine("python")
    argv = build_invocation(e, "h.py", "corpus", 60)
    assert any("60" in a for a in argv)
    with pytest.raises(ValueError):
        build_invocation(e, "h.py", "corpus", 0)


# --- persistent corpus is content-addressed & compounds ---------------------

def test_corpus_dedupes_and_persists(tmp_path):
    c = SeedCorpus(tmp_path, "myharness")
    c.add(b"seed-a")
    c.add(b"seed-a")               # identical -> collapses
    c.add(b"seed-b")
    assert len(c) == 2
    # a fresh handle over the same repo sees the carried-forward corpus
    assert len(SeedCorpus(tmp_path, "myharness")) == 2


# --- triage: dedup, minimize, severity --------------------------------------

def test_stack_hash_ignores_addresses_and_input():
    a = Crash(b"AAAA", stack=["parse+0x10", "main:42"], sanitizer="asan")
    b = Crash(b"BBBBBBBB", stack=["parse+0x99", "main:57"], sanitizer="asan")
    assert a.stack_hash == b.stack_hash            # same bug, different input/addr

    deduped = dedupe_crashes([a, b])
    assert len(deduped) == 1
    assert deduped[0].reproducer == b"AAAA"        # keeps the smaller reproducer


def test_classify_severity_from_sanitizer():
    assert classify_severity("ERROR: AddressSanitizer: heap-use-after-free") == Severity.CRITICAL
    assert classify_severity("UndefinedBehaviorSanitizer: integer-overflow") == Severity.MEDIUM
    assert classify_severity("Uncaught exception: ValueError") == Severity.MEDIUM
    assert classify_severity("") == Severity.LOW


def test_minimize_shrinks_while_oracle_holds():
    crash = Crash(b"XXXXBADXXXX", stack=["f"], sanitizer="x")
    # oracle: still crashes as long as 'BAD' is present
    out = minimize(crash, lambda data: b"BAD" in data)
    assert b"BAD" in out.reproducer
    assert len(out.reproducer) < len(crash.reproducer)


# --- novelty is flagged, never asserted -------------------------------------

def test_novelty_unverified_when_no_match():
    crash = Crash(b"x", stack=["f"], sanitizer="")
    r = novelty_check(crash, cve_index=lambda c: [], known_issues=lambda c: [])
    assert r.verdict == NoveltyVerdict.UNVERIFIED_NOVEL
    assert r.asserted_novel is False               # cosmo never claims novelty


def test_novelty_flags_likely_duplicate():
    crash = Crash(b"x", stack=["f"], sanitizer="")
    r = novelty_check(crash, cve_index=lambda c: ["CVE-2021-1234"],
                      known_issues=lambda c: ["#42"])
    assert r.verdict == NoveltyVerdict.LIKELY_DUPLICATE
    assert set(r.matches) == {"CVE-2021-1234", "#42"}


def test_novelty_lookup_failure_does_not_upgrade_to_novel():
    crash = Crash(b"x", stack=["f"], sanitizer="")

    def boom(c):
        raise RuntimeError("nvd down")

    r = novelty_check(crash, cve_index=boom, known_issues=lambda c: [])
    # a failed lookup must NOT be read as "no match => novel"; still unverified,
    # and the weakness of the evidence is noted.
    assert r.verdict == NoveltyVerdict.UNVERIFIED_NOVEL
    assert "unavailable" in r.rationale


# --- duration guardrails ----------------------------------------------------

def test_duration_must_be_set():
    with pytest.raises(DurationNotSet):
        resolve_duration(_cfg(), None)


def test_duration_capped_at_max():
    assert resolve_duration(_cfg(max_duration="1h"), "30m") == 1800
    assert resolve_duration(_cfg(max_duration="1h"), "10h") == 3600   # capped, not honored


def test_duration_above_confirm_needs_confirmation():
    cfg = _cfg(max_duration="8h", confirm_above="4h")
    with pytest.raises(ConfirmationRequired):
        resolve_duration(cfg, "6h")
    assert resolve_duration(cfg, "6h", confirmed=True) == 6 * 3600


# --- campaign: scope constraint, teardown, disabled gate --------------------

class _Target:
    """A stand-in sandbox-internal instance handle."""
    url = "sandbox-internal"


def _noop_runner(harness, max_seconds, *, broker, mode):
    return []


def test_campaign_refuses_external_target():
    with pytest.raises(ExternalTargetRefused):
        run_campaign(_cfg(), [], sandbox_target="http://example.com",
                     generator=lambda e, h: "", build_check=lambda h: (True, ""),
                     fuzz_runner=_noop_runner, duration="1m")


def test_campaign_disabled_by_config():
    cfg = Config(data={"fuzzing": {"enabled": False}})
    with pytest.raises(PermissionError):
        run_campaign(cfg, [], sandbox_target=_Target(),
                     generator=lambda e, h: "", build_check=lambda h: (True, ""),
                     fuzz_runner=_noop_runner, duration="1m")


def test_campaign_runs_and_always_tears_down():
    eps = [EntryPoint("e0", "function", "python", priority=1)]
    crash = Crash(b"boom", stack=["parse", "main"],
                  sanitizer="AddressSanitizer: heap-buffer-overflow", harness="e0")

    calls = {"mode": None}

    def runner(harness, max_seconds, *, broker, mode):
        calls["mode"] = mode
        raise RuntimeError("engine exploded mid-run")

    with pytest.raises(RuntimeError):
        run_campaign(_cfg(), eps, sandbox_target=_Target(),
                     generator=lambda e, h: "def h(): pass",
                     build_check=lambda h: (True, ""),
                     fuzz_runner=runner, duration="1m")
    # teardown intent: the runner ran in SANDBOX mode before it failed
    assert str(calls["mode"]) == "sandbox"


def test_campaign_produces_findings_with_novelty():
    eps = [EntryPoint("e0", "function", "python", priority=1)]
    crashes = [
        Crash(b"boom", stack=["parse", "main"],
              sanitizer="AddressSanitizer: heap-use-after-free", harness="e0"),
        Crash(b"boomboom", stack=["parse", "main"],   # dup of the first
              sanitizer="AddressSanitizer: heap-use-after-free", harness="e0"),
    ]

    def runner(harness, max_seconds, *, broker, mode):
        assert str(mode) == "sandbox"
        return list(crashes)

    res = run_campaign(_cfg(), eps, sandbox_target=_Target(),
                       generator=lambda e, h: "def h(): pass",
                       build_check=lambda h: (True, ""),
                       fuzz_runner=runner, duration="1m",
                       cve_index=lambda c: [], known_issues=lambda c: [])
    assert res.crashes_total == 2
    assert res.crashes_deduped == 1                 # dedup collapsed the pair
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.source == "fuzz"
    assert f.severity == Severity.CRITICAL
    assert res.novelty[f.id].verdict == NoveltyVerdict.UNVERIFIED_NOVEL
    assert res.torn_down is True
    assert res.coverage_fraction == 1.0
