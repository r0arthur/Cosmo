"""Interactive command layer — step 17 (architecture §7).

The through-line under test: the command layer cannot bypass the guardrails that
batch mode enforces — fuzz duration cap, data-governance gate, public-comment
gate — and preference commands only move preferences.
"""
import threading

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

    # Opening a session no longer scans, so the loop is exercised without a
    # live provider by default.
    s = run_repl(str(tmp_path), read=lambda prompt: next(lines),
                 write=outputs.append)
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

def test_advance_audit_loses_no_updates_under_contention(tmp_path):
    """Every audit worker advances this counter, so it cannot be a bare `+= 1`
    (read-modify-write from N threads drops updates)."""
    s = Session(config=Config(data={}), target=str(tmp_path))
    workers, per_worker = 8, 500
    start = threading.Barrier(workers)

    def _bump():
        start.wait(timeout=10)      # all threads hit the increment together
        for _ in range(per_worker):
            s.advance_audit()

    threads = [threading.Thread(target=_bump) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert s.audit_done == workers * per_worker


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


# --- the session must report its coverage, not just its findings ------------

def _report(target, findings=(), skipped=(), notes=()):
    from cosmo.findings import Report
    return Report(target=target, findings=list(findings),
                  skipped_stages=list(skipped), notes=list(notes))


def test_a_scan_s_skipped_stages_survive_into_the_session(tmp_path):
    """Dropped once, which let `/report` render an incomplete scan as a complete
    one — the single thing every other surface in cosmo is built to prevent."""
    s = _session(tmp_path)
    s.scanner = lambda *a, **k: _report(
        str(tmp_path), skipped=["model:claude unavailable"],
        notes=["reused cached static results"])
    s.scan()
    assert "model:claude unavailable" in s.skipped_stages
    assert "reused cached static results" in s.notes


def test_report_cli_shows_what_did_not_run(tmp_path):
    s = _session(tmp_path)
    s.scanner = lambda *a, **k: _report(str(tmp_path),
                                        skipped=["static:trivy (not installed)"])
    s.scan()
    out = dispatch(s, "/report cli")
    assert "skipped: static:trivy (not installed)" in out


def test_coverage_accumulates_across_scans_without_duplicating(tmp_path):
    """A re-scan re-reports the same skips; the operator wants the union of what
    went unchecked, not the last run's slice and not three copies of it."""
    s = _session(tmp_path)
    s.scanner = lambda *a, **k: _report(str(tmp_path), skipped=["static:trivy"])
    s.scan()
    s.scan()
    s.scanner = lambda *a, **k: _report(str(tmp_path), skipped=["static:bandit"])
    s.scan()
    assert s.skipped_stages == ["static:trivy", "static:bandit"]


def test_status_counts_skipped_stages(tmp_path):
    """"findings: none" reads very differently once you know three stages never
    ran, so /status says how many."""
    s = _session(tmp_path)
    s.scanner = lambda *a, **k: _report(str(tmp_path), skipped=["a", "b"])
    s.scan()
    assert "skipped: 2 stage(s)" in dispatch(s, "/status")


# --- /report markdown must not hand back the redacted public comment --------

def test_markdown_is_the_full_report_not_the_gated_comment(tmp_path):
    """`markdown` aliased `pr`, so asking for markdown in an operator session
    silently returned the version with sensitive findings withheld."""
    sensitive = Finding(id="f1", title="live AWS key", severity=Severity.CRITICAL,
                        source="static:gitleaks", file="a.py", line=1,
                        fingerprint="abc123", security_sensitive=True,
                        confirmation_status=ConfirmationStatus.CONFIRMED)
    s = _session(tmp_path, findings=[sensitive])
    md = dispatch(s, "/report markdown")
    assert "# cosmo security report" in md
    assert "live AWS key" in md                 # the operator sees it in full
    assert "abc123" in md                       # ...with the waive fingerprint

    gated = dispatch(s, "/report pr")
    assert "live AWS key" not in gated          # the public surface still hides it


def test_report_defaults_and_sarif_still_work(tmp_path):
    s = _session(tmp_path, findings=[
        Finding(id="f1", title="t", severity=Severity.HIGH, source="static:semgrep",
                file="a.py", line=1)])
    assert "cosmo — " in dispatch(s, "/report")
    assert '"version": "2.1.0"' in dispatch(s, "/report sarif")


# --- /tools -----------------------------------------------------------------

def test_tools_lists_scanners_without_touching_the_network(tmp_path, monkeypatch):
    """A session command must not make a network call nobody asked for."""
    import cosmo.versions as versions

    def forbidden(url):
        raise AssertionError(f"unexpected network call to {url}")

    monkeypatch.setattr(versions, "_get_json", forbidden)
    out = dispatch(_session(tmp_path), "/tools")
    assert "cosmo" in out
    assert "--check-updates" in out          # names the opt-in
    for name in ("semgrep", "gitleaks", "trivy"):
        assert name in out


def test_tools_is_in_the_guarded_registry(tmp_path):
    """The plugin surface derives from this registry, so a command missing here
    cannot be exposed there either."""
    from cosmo.interactive.commands import _COMMANDS
    assert "tools" in _COMMANDS
    assert "/tools" in dispatch(_session(tmp_path), "/help")


# --- /status must resolve the model, not print a literal --------------------

def test_status_names_an_unavailable_provider(tmp_path, monkeypatch):
    """It printed `session_model or "claude (default)"` — a literal, not a
    lookup — so it said claude whatever the config chose, and never said the
    provider could not run."""
    import shutil as _shutil
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(_shutil, "which", lambda *_a, **_k: None)

    out = dispatch(_session(tmp_path), "/status")
    line = next(ln for ln in out.splitlines() if ln.startswith("model:"))
    assert "unavailable" in line
    assert "ANTHROPIC_API_KEY" in line
    assert "model: model:" not in line        # the prefix is not doubled


# --- /next and /previous ----------------------------------------------------

def _walkable(tmp_path, n=5):
    from cosmo.severity import Severity
    s = _session(tmp_path)
    s.findings = [
        Finding(id=f"f{i}", title=f"issue {i}",
                severity=Severity.HIGH if i < 2 else Severity.LOW,
                source="static:semgrep", file=f"a{i}.py", line=i,
                fingerprint=f"fp{i}", category="CWE-78")
        for i in range(n)]
    return s


def test_next_and_previous_walk_the_list(tmp_path):
    s = _walkable(tmp_path)
    assert dispatch(s, "/next").startswith("[2/5]")
    assert dispatch(s, "/next").startswith("[3/5]")
    assert dispatch(s, "/previous").startswith("[2/5]")


def test_a_step_count_is_accepted(tmp_path):
    s = _walkable(tmp_path)
    assert dispatch(s, "/next 3").startswith("[4/5]")
    assert dispatch(s, "/previous 2").startswith("[2/5]")


def test_walking_past_the_end_says_so_rather_than_repeating_silently(tmp_path):
    s = _walkable(tmp_path)
    dispatch(s, "/next 99")
    out = dispatch(s, "/next")
    assert "already at the last" in out
    dispatch(s, "/previous 99")
    assert "already at the first" in dispatch(s, "/previous")


def test_a_bad_step_count_is_rejected_not_guessed(tmp_path):
    assert "not a number" in dispatch(_walkable(tmp_path), "/next two")


def test_walking_an_empty_session_is_harmless(tmp_path):
    out = dispatch(_session(tmp_path), "/next")
    assert "no findings" in out


def test_the_finding_is_shown_in_full_with_its_waive_command(tmp_path):
    """`/next` exists to be acted on, not scanned — unlike a list row, nothing
    is trimmed and the waive command is right there."""
    s = _walkable(tmp_path)
    out = dispatch(s, "/next")
    for expected in ("a1.py:1", "static:semgrep", "CWE-78", "fingerprint",
                     "/waive fp1"):
        assert expected in out, expected


def test_severity_orders_the_walk(tmp_path):
    """`/next` and the screen's ↓ must agree, so both use one ordering."""
    s = _walkable(tmp_path)
    order = [f.id for f in s.ordered_findings()]
    assert order[:2] == ["f0", "f1"]          # the two HIGHs first
    assert set(order[2:]) == {"f2", "f3", "f4"}


# --- scanning is something you ask for --------------------------------------

def test_opening_a_session_does_not_scan(tmp_path):
    """Opening a session used to run a full review — model call included —
    before the user had typed anything. "Open a session" and "send my code to a
    vendor" should not be the same gesture."""
    (tmp_path / "app.py").write_text("x = 1\n")
    called = []
    s = run_repl(str(tmp_path), read=lambda p: "", write=lambda m: None)
    assert not s.scanned
    assert s.findings == []


def test_scan_runs_the_static_scanners_without_a_provider(tmp_path):
    s = _session(tmp_path, data={"incremental": {"enabled": False}})
    seen = {}

    def scanner(target, cfg, provider=None, static_only=False):
        seen["provider"], seen["static_only"] = provider, static_only
        return _report(target, skipped=["model review not requested"])

    s.scanner = scanner
    out = dispatch(s, "/scan")
    assert seen["static_only"] is True
    assert seen["provider"] is None          # not even resolved
    assert "scan complete" in out
    assert s.scanned


def test_scan_llm_asks_for_the_model(tmp_path, monkeypatch):
    import cosmo.providers.registry as registry

    class _Ready:
        name = "fake"
        vendor = "local"
        exports_source = True
        roles = {"primary_review"}

        def available(self):
            return True

    monkeypatch.setattr(registry, "resolve_primary",
                        lambda cfg, **kw: (_Ready(), []))
    s = _session(tmp_path, data={"incremental": {"enabled": False}})
    seen = {}

    def scanner(target, cfg, provider=None, static_only=False):
        seen["static_only"] = static_only
        return _report(target)

    s.scanner = scanner
    announced: list[str] = []
    s.writer = announced.append
    dispatch(s, "/scan llm")
    assert seen["static_only"] is False
    # The moment the target's source leaves the machine is announced before it
    # happens, and names the provider it goes to.
    assert any("source is sent" in m and "model:fake" in m for m in announced)


def test_a_static_scan_says_nothing_leaves_the_machine(tmp_path):
    s = _session(tmp_path, data={"incremental": {"enabled": False}})
    s.scanner = lambda *a, **k: _report(str(tmp_path))
    announced: list[str] = []
    s.writer = announced.append
    dispatch(s, "/scan")
    assert any("no model, no egress" in m for m in announced)


def test_scan_llm_refuses_when_no_provider_can_run(tmp_path, monkeypatch):
    """Better to say why than to silently produce a static-only result the
    operator believes was reviewed by a model."""
    import shutil as _shutil
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(_shutil, "which", lambda *_a, **_k: None)

    s = _session(tmp_path)
    out = dispatch(s, "/scan llm")
    assert "cannot run the model review" in out
    assert "ANTHROPIC_API_KEY" in out
    assert "/scan on its own" in out         # names the thing that does work
    assert not s.scanned


def test_scan_reports_what_it_skipped(tmp_path):
    """The coverage contract holds at the moment the operator is looking."""
    s = _session(tmp_path)
    s.scanner = lambda *a, **k: _report(str(tmp_path),
                                        skipped=["static:trivy (not installed)"])
    out = dispatch(s, "/scan")
    assert "skipped: static:trivy (not installed)" in out


def test_an_unknown_scan_argument_is_rejected(tmp_path):
    assert "unknown argument" in dispatch(_session(tmp_path), "/scan bogus")


def test_status_says_nothing_has_been_scanned(tmp_path):
    out = dispatch(_session(tmp_path), "/status")
    assert "not scanned yet" in out
    assert "/scan llm" in out


def test_a_rescan_resets_the_cursor(tmp_path):
    """The old cursor pointed into a list that no longer exists."""
    s = _walkable(tmp_path)
    dispatch(s, "/next 3")
    assert s.cursor == 3
    s.scanner = lambda *a, **k: _report(str(tmp_path))
    dispatch(s, "/scan")
    assert s.cursor == 0
