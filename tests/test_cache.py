"""Incremental scanning cache — step 12."""
from cosmo.cache import (
    Cache,
    cache_or_run,
    dynamic_key,
    finding_from_dict,
    finding_to_dict,
    model_key,
    static_key,
)
from cosmo.config import Config
from cosmo.engine import run_review
from cosmo.findings import ConfirmationStatus, Finding
from cosmo.severity import Severity


# --- key design (the flagged soundness issue) -------------------------------

def test_static_key_stable_and_content_sensitive():
    a = {"x.py": "code A"}
    assert static_key(a) == static_key({"x.py": "code A"})   # stable
    assert static_key(a) != static_key({"x.py": "code B"})   # content-sensitive


def test_model_key_includes_model_and_context():
    files = {"x.py": "c"}
    assert model_key(files, "claude", "ctx") != model_key(files, "codex", "ctx")
    assert model_key(files, "claude", "ctx1") != model_key(files, "claude", "ctx2")


def test_dynamic_key_is_composite_not_just_file_hash():
    files = {"x.py": "c"}
    base = dynamic_key(files, lockfile_hash="L1", toolchain_version="py3.11")
    # An UNCHANGED file must still miss the cache when the lockfile moves...
    assert base != dynamic_key(files, lockfile_hash="L2", toolchain_version="py3.11")
    # ...or the toolchain moves.
    assert base != dynamic_key(files, lockfile_hash="L1", toolchain_version="py3.12")
    # Same everything → same key.
    assert base == dynamic_key({"x.py": "c"}, "L1", "py3.11")


def test_dynamic_and_static_keys_never_collide():
    files = {"x.py": "c"}
    assert static_key(files) != dynamic_key(files, "L", "t")


# --- finding roundtrip ------------------------------------------------------

def test_finding_roundtrip_preserves_fields():
    f = Finding(id="1", title="t", severity=Severity.CRITICAL, source="model:claude",
                file="a.py", line=9, category="CWE-89", security_sensitive=True,
                confirmation_status=ConfirmationStatus.NOT_REPRODUCIBLE, confidence=0.8)
    g = finding_from_dict(finding_to_dict(f))
    assert g.severity is Severity.CRITICAL
    assert g.confirmation_status is ConfirmationStatus.NOT_REPRODUCIBLE
    assert g.security_sensitive is True and g.category == "CWE-89" and g.confidence == 0.8


# --- store ------------------------------------------------------------------

def test_cache_roundtrip_persists(tmp_path):
    c = Cache.load(str(tmp_path))
    c.set("k", [{"a": 1}])
    assert c.save() is True
    reloaded = Cache.load(str(tmp_path))
    assert reloaded.get("k") == [{"a": 1}]
    assert reloaded.get("missing") is None


def test_save_is_best_effort_on_unwritable_target():
    # An unwritable/nonexistent target must not crash the review (regression: a
    # bogus path like an unset $VAR expanding to '/wp-includes' raised PermissionError).
    c = Cache.load("/nonexistent-root-xyz/deep/path")
    c.set("k", [1])
    assert c.save() is False        # skipped, no exception raised


def test_disabled_cache_never_hits(tmp_path):
    c = Cache.load(str(tmp_path), enabled=False)
    c.set("k", [1])
    assert c.get("k") is None


def test_cache_or_run_runs_once_then_reuses():
    c = Cache.load(".", enabled=True)
    c.path = None  # in-memory only
    calls = {"n": 0}

    def run():
        calls["n"] += 1
        return [Finding(id="1", title="t", severity=Severity.LOW, source="static",
                        file="a.py", line=1)]

    out1, hit1 = cache_or_run(c, "key", run)
    out2, hit2 = cache_or_run(c, "key", run)
    assert calls["n"] == 1 and hit1 is False and hit2 is True
    assert out2[0].title == "t"


# --- engine integration -----------------------------------------------------

class CountingProvider:
    name = "claude"

    def __init__(self):
        self.calls = 0

    def available(self):
        return True

    def review(self, diff, context, findings_so_far):
        self.calls += 1
        return [Finding(id="m0", title="SQLi", severity=Severity.HIGH, source="model:claude",
                        file="app.py", line=1, category="CWE-89", security_sensitive=False)]


def test_engine_reuses_model_result_on_unchanged_rescan(tmp_path):
    (tmp_path / "app.py").write_text("q = build_sql(user)\n")
    cfg = Config(data={"threshold": "low"})
    p = CountingProvider()

    run_review(str(tmp_path), cfg, provider=p)   # miss → provider called
    run_review(str(tmp_path), cfg, provider=p)   # unchanged → cache hit, not called
    assert p.calls == 1

    # Change the file → cache miss → provider called again.
    (tmp_path / "app.py").write_text("q = build_sql(other_user)\n")
    run_review(str(tmp_path), cfg, provider=p)
    assert p.calls == 2


def test_engine_no_cache_when_disabled(tmp_path):
    (tmp_path / "app.py").write_text("q = 1\n")
    cfg = Config(data={"threshold": "low", "incremental": {"enabled": False}})
    p = CountingProvider()
    run_review(str(tmp_path), cfg, provider=p)
    run_review(str(tmp_path), cfg, provider=p)
    assert p.calls == 2                          # no caching → called each time
