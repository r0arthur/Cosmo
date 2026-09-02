"""The comprehensive Markdown report (`cosmo review --report FILE`).

The live panel and the CLI text renderer are both lossy by design — eight titles
clipped to a column, fields trimmed to the terminal. A real run against a live
repo produced ten HIGH findings that could not be triaged from either: no rule
id, no evidence, no fingerprint to waive with. This is the artifact that closes
that, so the properties tested here are the ones that make it triageable:
nothing truncated, coverage before findings, and a waive command that works.
"""
from cosmo.findings import ConfirmationStatus, Finding, Report
from cosmo.output import render_report
from cosmo.severity import Severity

LONG_TITLE = ("Using variable interpolation ${{...}} with github context data in a "
              "run: step could allow an attacker to inject their own code into the "
              "runner, which would let them steal secrets and alter the release")
LONG_EVIDENCE = ("semgrep rule: yaml.github-actions.security.run-shell-injection\n"
                 "semgrep rating: confidence=MEDIUM  impact=HIGH  likelihood=HIGH\n"
                 "CWE: CWE-94: Improper Control of Generation of Code\n"
                 "https://sg.run/pPzk")


def _f(**kw):
    base = dict(id="f1", title="hardcoded credential", severity=Severity.HIGH,
                source="static", file="app/api.py", line=12,
                fingerprint="abc123def456", category="CWE-798")
    base.update(kw)
    return Finding(**base)


def _report(*findings, target="/repo", skipped=(), notes=()):
    return Report(target=target, findings=list(findings),
                  skipped_stages=list(skipped), notes=list(notes))


# --- nothing is truncated ---------------------------------------------------

def test_long_title_and_evidence_survive_intact():
    """The panel clipped these to `Using variable interpolation ${{...}} …`,
    which names no file, no rule and no reason."""
    out = render_report(_report(_f(title=LONG_TITLE, evidence=LONG_EVIDENCE)))
    assert LONG_TITLE in out
    for line in LONG_EVIDENCE.splitlines():
        assert line in out
    assert "…" not in out


def test_every_populated_field_reaches_the_report():
    out = render_report(_report(_f(
        evidence="gitleaks rule: generic-api-key",
        exploit_scenario="An attacker reading the repo obtains a live key.",
        remediation="Rotate the secret and purge it from history.",
        confidence=0.9, confirmation_status=ConfirmationStatus.UNCONFIRMED)))
    for expected in ("gitleaks rule: generic-api-key",
                     "An attacker reading the repo obtains a live key.",
                     "Rotate the secret and purge it from history.",
                     "app/api.py:12", "CWE-798", "90%", "unconfirmed",
                     "abc123def456"):
        assert expected in out, expected


def test_empty_fields_are_omitted_not_rendered_blank():
    out = render_report(_report(_f(evidence="", remediation="")))
    assert "**Evidence**" not in out
    assert "**Remediation**" not in out


# --- coverage is not optional -----------------------------------------------

def test_coverage_precedes_findings():
    """A reader who stops at the findings must already have seen what did not
    run — the same contract the CLI renderer keeps."""
    out = render_report(_report(_f(), skipped=["model:claude unavailable"]))
    assert out.index("## Coverage") < out.index("## Findings")
    assert "model:claude unavailable" in out


def test_a_clean_run_still_reports_its_coverage():
    out = render_report(_report(skipped=["static:semgrep (not installed)"]))
    assert "static:semgrep (not installed)" in out
    assert "No findings at or above the configured floor." in out


def test_a_complete_run_says_so_explicitly():
    out = render_report(_report(_f()))
    assert "Every stage ran" in out


def test_notes_are_carried_through():
    out = render_report(_report(_f(), notes=["llm-audit reviewed 50 of 2098 files"]))
    assert "llm-audit reviewed 50 of 2098 files" in out


# --- triage affordances -----------------------------------------------------

def test_each_finding_carries_a_working_waive_command():
    out = render_report(_report(_f(), target="/repo"))
    assert 'cosmo waive /repo abc123def456 --reason "why"' in out


def test_a_waived_finding_is_listed_separately_not_counted():
    out = render_report(_report(
        _f(), _f(id="f2", title="known issue", waived=True,
                 waived_reason="test fixture")))
    assert "1 actionable, 1 waived" in out
    assert "## Waived" in out
    assert "test fixture" in out
    # A waived finding must not offer a waive command it already has.
    assert out.count("cosmo waive") == 1


def test_unknown_sensitivity_is_named_as_fail_closed():
    """RISK-05: unknown sensitivity is withheld from public comments. Without
    this line the reader cannot tell why a finding never reached a PR."""
    out = render_report(_report(_f(security_sensitive=None)))
    assert "withheld from public comments" in out


# --- ordering and paths -----------------------------------------------------

def test_findings_are_ordered_by_severity_then_location():
    out = render_report(_report(
        _f(id="a", title="low one", severity=Severity.LOW, file="z.py"),
        _f(id="b", title="crit one", severity=Severity.CRITICAL, file="m.py"),
        _f(id="c", title="high b", severity=Severity.HIGH, file="b.py"),
        _f(id="d", title="high a", severity=Severity.HIGH, file="a.py")))
    order = [out.index(t) for t in ("crit one", "high a", "high b", "low one")]
    assert order == sorted(order)


def test_paths_are_shown_relative_to_the_target():
    """Whole-tree runs carry absolute paths; repeated in every cell they crowd
    out the part that identifies the file."""
    out = render_report(_report(
        _f(file="/repo/ee/tabby-ui/lib/posthog.tsx"), target="/repo"))
    assert "ee/tabby-ui/lib/posthog.tsx:12" in out
    assert "/repo/ee/tabby-ui" not in out.split("## Findings")[1]


def test_a_path_outside_the_target_is_left_alone():
    out = render_report(_report(_f(file="/elsewhere/x.py"), target="/repo"))
    assert "/elsewhere/x.py:12" in out


def test_history_target_suffix_does_not_break_relativisation():
    out = render_report(_report(_f(file="/repo/app/api.py"),
                                target="/repo@history"))
    assert "app/api.py:12" in out


# --- header -----------------------------------------------------------------

def test_header_states_target_floor_and_counts():
    out = render_report(_report(_f(), target="/repo"), threshold="high",
                        elapsed=125, now=0)
    assert "**Target:** `/repo`" in out
    assert "**Severity floor:** high" in out
    assert "1970-01-01" in out          # `now` honoured, so output is testable
    assert "02:05" in out               # elapsed rendered mm:ss
