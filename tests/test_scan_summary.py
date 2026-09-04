"""The structured scan summary (`cosmo/interactive/scan_summary.py`).

Built to fix a real gap: `/scan` on a 155-finding repo returned a one-line
finding count and nothing else — no severity breakdown, no per-scanner
success/failure, no duration, and nothing kept around for `/report` to answer
from without re-scanning. These tests are about the two properties that make
the summary trustworthy rather than merely decorative: a scanner's *outcome*
(ran clean / failed / never got the chance) is tracked separately from its
*finding count*, and a crash in one scanner never discards what the others
found.
"""
import time

import pytest

from cosmo.events import Emitter
from cosmo.findings import Finding, Report
from cosmo.interactive.scan_summary import (FAILED, OK, SKIPPED, Collector,
                                             ScannerStatus, ScanSummary,
                                             format_report)
from cosmo.severity import Severity


def _finding(i=0, sev=Severity.HIGH, source="static:semgrep", waived=False, **kw):
    kw.setdefault("file", f"a{i}.py")
    kw.setdefault("line", i + 1)
    return Finding(id=f"f{i}", title=f"finding {i}", severity=sev, source=source,
                   waived=waived, **kw)


def _summary(findings=(), scanners=(), llm=False, skipped=()):
    report = Report(target="/repo", findings=list(findings),
                    skipped_stages=list(skipped))
    return ScanSummary(target="/repo", llm=llm, started=0.0, finished=1.5,
                       report=report, scanners=list(scanners))


# --- the collector watches the live event stream -----------------------------

def test_collector_records_a_successful_scanner():
    lines = []
    c = Collector(lines.append)
    ev = Emitter(c)
    ev.output("semgrep: 3 finding(s)", stage="static", tool="semgrep", findings=3)
    assert c.by_tool["semgrep"] == ScannerStatus("semgrep", OK, findings=3)
    assert any("semgrep" in l and "3" in l for l in lines)


def test_a_failed_scanner_does_not_erase_a_succeeded_one():
    """The bug this exists to prevent: one scanner crashing must not read as
    "0 findings" for the whole scan, and must not cost the others their
    results either."""
    c = Collector()
    ev = Emitter(c)
    ev.output("gitleaks: 2 finding(s)", stage="static", tool="gitleaks", findings=2)
    ev.error("trivy failed: exit 137", stage="static", tool="trivy")
    assert c.by_tool["gitleaks"].state == OK and c.by_tool["gitleaks"].findings == 2
    assert c.by_tool["trivy"].state == FAILED
    assert "exit 137" in c.by_tool["trivy"].detail


def test_a_timeout_is_recorded_as_skipped_not_failed():
    c = Collector()
    Emitter(c).stage_skipped("static", "gitleaks timed out after 60s", tool="gitleaks")
    assert c.by_tool["gitleaks"].state == SKIPPED


def test_events_off_the_static_stage_are_ignored():
    """A `provider`/`llm`-stage event must not be mistaken for a scanner."""
    c = Collector()
    Emitter(c).output("model:claude ready", stage="provider", tool="claude")
    assert c.by_tool == {}


def test_an_event_with_no_tool_and_no_parseable_name_is_ignored():
    c = Collector()
    Emitter(c).stage_skipped("static", "no dependency scanner ran")
    assert c.by_tool == {}


# --- reconciliation: what a cache hit does not emit live ---------------------

def test_reconcile_recovers_a_tool_from_finding_source_on_a_cache_hit():
    """A cache hit replays only the flat skip-string list — no per-tool OUTPUT
    event fires, live or replayed. What survives caching is `Finding.source`
    on every restored finding, and that is enough to recover a tool that
    found something."""
    c = Collector()
    report = Report(target="/repo",
                    findings=[_finding(0, source="static:gitleaks"),
                             _finding(1, source="static:gitleaks"),
                             _finding(2, source="static:semgrep")])
    c.reconcile(report)
    assert c.by_tool["gitleaks"] == ScannerStatus("gitleaks", OK, findings=2)
    assert c.by_tool["semgrep"] == ScannerStatus("semgrep", OK, findings=1)


def test_reconcile_parses_a_tool_name_out_of_a_replayed_skip_line():
    """`engine.py`'s cache-hit path replays `skipped_stages` with no `tool=`
    tag at all — the only structure left is the message's own wording."""
    c = Collector()
    report = Report(target="/repo", findings=[], skipped_stages=[
        "static:trivy (not installed — dependency CVEs NOT scanned; install: x)",
        "bandit not installed — Python AST security checks not scanned",
    ])
    c.reconcile(report)
    assert c.by_tool["trivy"].state == SKIPPED
    assert c.by_tool["bandit"].state == SKIPPED


def test_reconcile_does_not_overwrite_a_live_event():
    """Live data, when there is any, is authoritative — reconciliation only
    fills gaps the event stream left."""
    c = Collector()
    Emitter(c).output("gitleaks: 5 finding(s)", stage="static", tool="gitleaks",
                      findings=5)
    report = Report(target="/repo", findings=[_finding(0, source="static:gitleaks")])
    c.reconcile(report)
    assert c.by_tool["gitleaks"].findings == 5      # not overwritten to 1


def test_reconcile_leaves_an_unrecoverable_gap_alone_rather_than_guessing():
    """A tool that ran clean (zero findings) on the run that got cached is
    genuinely unrecoverable after a cache hit — no finding to group by source,
    no skip line to parse a name out of. Documented, not silently invented."""
    c = Collector()
    report = Report(target="/repo", findings=[], skipped_stages=[])
    c.reconcile(report)
    assert c.by_tool == {}


# --- ScanSummary's derived counts --------------------------------------------

def test_counts_match_the_actual_findings_not_a_separate_tally():
    """The summary's numbers must be *computed from* the findings, not kept as
    an independent counter that can drift from what is actually in the list."""
    findings = [_finding(0, Severity.CRITICAL), _finding(1, Severity.HIGH),
               _finding(2, Severity.HIGH), _finding(3, Severity.MEDIUM),
               _finding(4, Severity.LOW, waived=True)]
    s = _summary(findings)
    assert s.total == 4                     # the waived one excluded
    assert s.counts == {"critical": 1, "high": 2, "medium": 1}
    assert sum(s.counts.values()) == s.total


def test_scanner_tallies_are_independent_categories():
    scanners = [ScannerStatus("a", OK, findings=3), ScannerStatus("b", OK, findings=0),
               ScannerStatus("c", FAILED, detail="boom"),
               ScannerStatus("d", SKIPPED, detail="not installed")]
    s = _summary(scanners=scanners)
    assert s.scanners_run == 4
    assert s.scanners_succeeded == 2
    assert s.scanners_failed == 1
    assert s.scanners_skipped == 1


def test_duration_is_the_wall_clock_span():
    s = ScanSummary(target="/repo", llm=False, started=10.0, finished=22.4,
                    report=Report(target="/repo", findings=[]))
    assert s.duration == pytest.approx(12.4)


def test_top_orders_by_severity_then_location():
    findings = [_finding(0, Severity.LOW, file="z.py"),
               _finding(1, Severity.CRITICAL, file="m.py"),
               _finding(2, Severity.HIGH, file="a.py")]
    s = _summary(findings)
    top = s.top(2)
    assert [f.file for f in top] == ["m.py", "a.py"]


# --- the rendered report ------------------------------------------------------

def test_format_report_shows_a_failure_as_a_warning_not_a_silent_zero():
    scanners = [ScannerStatus("trivy", FAILED, detail="exit 137"),
               ScannerStatus("gitleaks", OK, findings=1)]
    s = _summary([_finding(0, source="static:gitleaks")], scanners=scanners)
    out = format_report(s)
    assert "WARNING: trivy failed: exit 137" in out
    assert "1" in out                       # gitleaks' finding still counted


def test_format_report_box_holds_at_a_long_target_path():
    """A box row that only pads, never clips, breaks its own border the
    moment a value is wider than the box — this is a plain-text renderer with
    no terminal width to save it."""
    long_target = "/" + "/".join(f"segment{i}" for i in range(12))
    s = ScanSummary(target=long_target, llm=False, started=0, finished=1,
                    report=Report(target=long_target, findings=[]))
    out = format_report(s)
    box_lines = [l for l in out.splitlines() if l.startswith(("┌", "│", "└"))]
    assert len(set(len(l) for l in box_lines)) == 1, "box rows are not flush"


def test_format_report_names_the_next_commands():
    s = _summary([_finding(0)])
    out = format_report(s)
    assert "/report" in out and "/findings" in out and "/scan llm" in out


def test_format_report_does_not_suggest_scan_llm_when_already_used():
    s = _summary([_finding(0)], llm=True)
    assert "/scan llm" not in format_report(s)
