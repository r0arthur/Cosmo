"""Interactive command layer — step 17 (architecture §7).

The through-line under test: the command layer cannot bypass the guardrails that
batch mode enforces — fuzz duration cap, data-governance gate, public-comment
gate — and preference commands only move preferences.
"""
from cosmo.config import Config
from cosmo.findings import ConfirmationStatus, Finding
from cosmo.interactive import Session, dispatch, run_repl
from cosmo.severity import Severity


def _session(tmp_path, data=None, findings=None):
    (tmp_path / "app.py").write_text("x = 1\n")
    s = Session(config=Config(data=data or {}), target=str(tmp_path))
    s.findings = findings or []
    return s


# --- help / status / threshold ---------------------------------------------

def test_help_lists_commands(tmp_path):
    out = dispatch(_session(tmp_path), "/help")
    for cmd in ("/duration", "/model", "/threshold", "/report", "/status"):
        assert cmd in out


def test_unknown_and_bare_input(tmp_path):
    s = _session(tmp_path)
    assert "unknown command" in dispatch(s, "/nope")
    assert "start with '/'" in dispatch(s, "hello")


def test_threshold_is_preference_only(tmp_path):
    s = _session(tmp_path, data={"threshold": "medium"})
    assert "medium" in dispatch(s, "/threshold")
    assert "high" in dispatch(s, "/threshold high")
    assert s.effective_threshold() == "high"
    # it only set the session floor — never wrote a safety-tier key
    assert "sandbox" not in s.config.data and "fuzzing" not in s.config.data
    assert "unknown level" in dispatch(s, "/threshold bogus")


# --- /duration is capped by config (cannot be bypassed) ---------------------

def test_duration_capped_by_config(tmp_path):
    s = _session(tmp_path, data={"fuzzing": {"enabled": True, "max_duration": "1h",
                                             "confirm_above": "4h"}})
    out = dispatch(s, "/duration 10h")
    assert s.fuzz_duration == 3600            # capped to the 1h ceiling, not 10h
    assert "3600" in out


def test_duration_above_confirm_needs_flag(tmp_path):
    s = _session(tmp_path, data={"fuzzing": {"enabled": True, "max_duration": "8h",
                                             "confirm_above": "2h"}})
    out = dispatch(s, "/duration 6h")
    assert "confirm" in out.lower()
    assert s.fuzz_duration is None            # not set until confirmed
    dispatch(s, "/duration 6h --confirm")
    assert s.fuzz_duration == 6 * 3600


def test_duration_extend_still_capped(tmp_path):
    s = _session(tmp_path, data={"fuzzing": {"enabled": True, "max_duration": "1h",
                                             "confirm_above": "4h"}})
    dispatch(s, "/duration 30m")
    dispatch(s, "/duration extend 40m")
    assert s.fuzz_duration == 3600            # 30m+40m clamped to the 1h cap


# --- /model routes through the §8 data-governance gate ----------------------

def test_model_switch_refused_for_sensitive_repo(tmp_path):
    # A sensitive repo with no accepted vendors must not fan source to deepseek.
    s = _session(tmp_path, data={"providers_policy": {"data_sensitivity": "sensitive",
                                                      "sensitive_allowed_vendors": []}})
    out = dispatch(s, "/model deepseek")
    assert "cannot switch" in out.lower()
    assert s.session_model is None            # stayed on the safe default


def test_model_view_default(tmp_path):
    assert "claude" in dispatch(_session(tmp_path), "/model").lower()


# --- /report honors the fail-closed public-comment gate (RISK-05) -----------

def test_report_pr_withholds_sensitive(tmp_path):
    findings = [
        Finding(id="pub", title="Public CSRF note", severity=Severity.MEDIUM,
                source="model:claude", file="a.py", line=1, security_sensitive=False,
                exploit_scenario="csrf detail"),
        Finding(id="sec", title="Hardcoded AWS key", severity=Severity.HIGH,
                source="static", file="b.py", line=2, security_sensitive=True,
                exploit_scenario="SECRET POC"),
    ]
    s = _session(tmp_path, findings=findings)
    body = dispatch(s, "/report pr")
    assert "Public CSRF note" in body
    assert "Hardcoded AWS key" not in body    # sensitive → withheld, same as batch
    assert "SECRET POC" not in body


def test_report_cli_shows_everything(tmp_path):
    f = Finding(id="sec", title="Hardcoded AWS key", severity=Severity.HIGH,
                source="static", file="b.py", line=2, security_sensitive=True)
    s = _session(tmp_path, findings=[f])
    # the local cli report is not a public surface — it may show detail
    assert "Hardcoded AWS key" in dispatch(s, "/report cli")


# --- /waive + /baseline -----------------------------------------------------

def test_waive_and_baseline_roundtrip(tmp_path):
    f = Finding(id="f1", title="t", severity=Severity.LOW, source="static",
                file="a.py", line=1, fingerprint="fp-1")
    s = _session(tmp_path, findings=[f])
    assert "waived fp-1" in dispatch(s, "/waive f1 false positive")
    assert f.waived is True
    assert "fp-1" in dispatch(s, "/baseline")
    dispatch(s, "/baseline unwaive fp-1")
    assert "no waived findings" in dispatch(s, "/baseline")


# --- /confirm needs a real runtime; never silently "confirms" ---------------

def test_confirm_without_runtime(tmp_path):
    f = Finding(id="f1", title="t", severity=Severity.HIGH, source="model:claude",
                file="a.py", line=1)
    s = _session(tmp_path, findings=[f])
    out = dispatch(s, "/confirm f1")
    assert "requires a container runtime" in out
    assert f.confirmation_status == ConfirmationStatus.UNCONFIRMED  # unchanged


def test_confirm_uses_injected_confirmer(tmp_path):
    f = Finding(id="f1", title="t", severity=Severity.HIGH, source="model:claude",
                file="a.py", line=1)
    s = _session(tmp_path, findings=[f])
    s.confirmer = lambda finding, session: f"confirmed {finding.id}"
    assert dispatch(s, "/confirm f1") == "confirmed f1"
    assert "no finding" in dispatch(s, "/confirm nope")


# --- /status snapshot -------------------------------------------------------

def test_status_snapshot(tmp_path):
    f = Finding(id="f1", title="t", severity=Severity.HIGH, source="static",
                file="a.py", line=1)
    s = _session(tmp_path, findings=[f])
    s.running_campaigns = {"fuzz-e0": 1200}
    out = dispatch(s, "/status")
    assert "high:1" in out
    assert "fuzz-e0 (1200s left)" in out


# --- the REPL loop drives dispatch over the shared session ------------------

def test_repl_loop_runs_commands(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    lines = iter(["/threshold high", "/status", ""])
    outputs = []

    # autoscan off so the loop is exercised without a live provider.
    s = run_repl(str(tmp_path), read=lambda prompt: next(lines),
                 write=outputs.append, autoscan=False)
    assert s.effective_threshold() == "high"
    assert any("threshold: high" in o for o in outputs)


# --- /audit — whole-project AI audit inside a live session -----------------

def _fake_provider():
    from cosmo.severity import Severity

    class _P:
        name = "fake"
        vendor = "local"
        exports_source = False
        roles = {"primary_review"}
        broker = None

        def available(self):
            return True

        def review(self, diff, context, findings_so_far):
            p = diff.files[0].path
            return [Finding(id="m-0", title=f"vuln in {p}", severity=Severity.HIGH,
                            source="model:fake", file=p, line=1)]
    return _P()


def test_audit_runs_in_background_and_merges(tmp_path, monkeypatch):
    # two files → two per-file reviews on a background thread; findings land in
    # session state and the REPL stays responsive (dispatch returns immediately).
    (tmp_path / "a.py").write_text("import os\n")
    (tmp_path / "b.py").write_text("import sys\n")
    s = Session(config=Config(data={"llm_audit": {"max_files": 50}}), target=str(tmp_path))
    streamed = []
    s.writer = streamed.append
    import cosmo.providers.registry as reg
    monkeypatch.setattr(reg, "resolve_primary", lambda *a, **k: (_fake_provider(), []))
    out = dispatch(s, "/audit")
    assert "started in the background" in out          # returned without blocking
    assert s.audit_thread is not None
    s.audit_thread.join(timeout=5)                     # let it finish for the assert
    joined = "\n".join(streamed)
    assert "[1/2]" in joined and "[2/2]" in joined
    assert len(s.findings) == 2                         # merged live per file
    assert s.audit_done == 2 and not s.audit_running()

def test_audit_wait_blocks_until_done(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("import os\n")
    s = Session(config=Config(data={}), target=str(tmp_path))
    s.writer = lambda m: None
    import cosmo.providers.registry as reg
    monkeypatch.setattr(reg, "resolve_primary", lambda *a, **k: (_fake_provider(), []))
    dispatch(s, "/audit wait")                          # synchronous variant
    assert not s.audit_running() and len(s.findings) == 1

def test_status_reports_audit_state(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("import os\n")
    s = Session(config=Config(data={}), target=str(tmp_path))
    s.writer = lambda m: None
    import cosmo.providers.registry as reg
    monkeypatch.setattr(reg, "resolve_primary", lambda *a, **k: (_fake_provider(), []))
    dispatch(s, "/audit wait")
    assert "audit: done" in dispatch(s, "/status")

def test_second_audit_refused_while_running(tmp_path, monkeypatch):
    import threading
    (tmp_path / "a.py").write_text("import os\n")
    s = Session(config=Config(data={}), target=str(tmp_path))
    s.writer = lambda m: None
    gate = threading.Event()
    from cosmo.severity import Severity

    class _Slow:
        name = "fake"; vendor = "local"; exports_source = False
        roles = {"primary_review"}; broker = None
        def available(self): return True
        def review(self, diff, context, findings_so_far):
            gate.wait(2)                                 # hold the thread open
            return [Finding(id="m-0", title="v", severity=Severity.HIGH,
                            source="model:fake", file=diff.files[0].path, line=1)]
    import cosmo.providers.registry as reg
    monkeypatch.setattr(reg, "resolve_primary", lambda *a, **k: (_Slow(), []))
    dispatch(s, "/audit")                                # starts, thread blocks on gate
    second = dispatch(s, "/audit")                       # should be refused
    gate.set()
    s.audit_thread.join(timeout=5)
    assert "already running" in second


def test_audit_refuses_when_provider_unavailable(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x=1\n")
    s = Session(config=Config(data={}), target=str(tmp_path))
    import cosmo.providers.registry as reg

    class _Down(_fake_provider().__class__):
        def available(self):
            return False
    monkeypatch.setattr(reg, "resolve_primary", lambda *a, **k: (_Down(), []))
    out = dispatch(s, "/audit")
    assert "cannot audit" in out and "claude-cli" in out
    assert s.findings == []          # nothing ran


def test_audit_listed_in_help(tmp_path):
    assert "/audit" in dispatch(_session(tmp_path), "/help")
