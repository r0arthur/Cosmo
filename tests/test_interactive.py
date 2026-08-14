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
