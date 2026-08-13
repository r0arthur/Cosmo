"""Trend + findings store and compliance mapping — step 15 (architecture §14/§15)."""
from cosmo.findings import ConfirmationStatus, Finding
from cosmo.severity import Severity
from cosmo.store import TrendStore, map_report, owasp_for, owasp_name


def _f(fp, category="CWE-89", severity=Severity.HIGH, waived=False, title="SQLi"):
    return Finding(id=fp, title=title, severity=severity, source="model:claude",
                   file="app.py", line=1, category=category, fingerprint=fp, waived=waived)


def _store(tmp_path):
    return TrendStore(tmp_path / ".cosmo" / "trends.db")


# --- lifecycle --------------------------------------------------------------

def test_introduced_then_fixed(tmp_path):
    store = _store(tmp_path)
    s1 = store.record_scan("t", [_f("a"), _f("b")], now=1000.0)
    assert (s1.introduced, s1.fixed, s1.open_total) == (2, 0, 2)

    # b disappears from the next scan → marked fixed.
    s2 = store.record_scan("t", [_f("a")], now=2000.0)
    assert (s2.introduced, s2.fixed, s2.open_total) == (0, 1, 1)
    assert {r["fingerprint"] for r in store.open_findings("t")} == {"a"}


def test_reopened(tmp_path):
    store = _store(tmp_path)
    store.record_scan("t", [_f("a")], now=1000.0)
    store.record_scan("t", [], now=2000.0)          # a fixed
    s3 = store.record_scan("t", [_f("a")], now=3000.0)  # a comes back
    assert s3.reopened == 1
    assert s3.introduced == 0
    assert s3.open_total == 1


def test_waived_excluded_from_open_total(tmp_path):
    store = _store(tmp_path)
    s = store.record_scan("t", [_f("a"), _f("b", waived=True)], now=1000.0)
    assert s.introduced == 2
    assert s.open_total == 1                          # waived doesn't count as open
    assert {r["fingerprint"] for r in store.open_findings("t")} == {"a"}


def test_targets_are_isolated(tmp_path):
    store = _store(tmp_path)
    store.record_scan("t1", [_f("a")], now=1000.0)
    s = store.record_scan("t2", [_f("b")], now=1000.0)
    assert s.introduced == 1                          # t2's own count, not t1's
    assert store.open_findings("t2")[0]["fingerprint"] == "b"


def test_findings_without_fingerprint_skipped(tmp_path):
    store = _store(tmp_path)
    nofp = Finding(id="x", title="t", severity=Severity.LOW, source="static",
                   file="app.py", line=1, category="CWE-79")
    s = store.record_scan("t", [nofp, _f("a")], now=1000.0)
    assert s.introduced == 1


# --- weekly trend & noisiest rules -----------------------------------------

def test_weekly_trend_buckets(tmp_path):
    store = _store(tmp_path)
    store.record_scan("t", [_f("a")], now=1_600_000_000.0)   # some iso-week
    trend = store.weekly_trend("t")
    assert sum(d["introduced"] for d in trend.values()) == 1


def test_noisiest_rules(tmp_path):
    store = _store(tmp_path)
    findings = [_f(f"n{i}", category="CWE-79", waived=(i < 2)) for i in range(4)]
    findings.append(_f("q", category="CWE-89"))
    store.record_scan("t", findings, now=1000.0)
    noisy = store.noisiest_rules("t", min_samples=3)
    # only CWE-79 has >=3 samples; 2 of 4 waived → 0.5
    assert len(noisy) == 1
    assert noisy[0][0] == "CWE-79"
    assert abs(noisy[0][2] - 0.5) < 1e-9


# --- disclosure queue (§13) -------------------------------------------------

def test_disclosure_queue(tmp_path):
    store = _store(tmp_path)
    store.record_scan("t", [_f("a")], now=1000.0)
    assert store.disclosure_queue("t") == []
    store.set_disclosure_status("t", "a", "reported")
    q = store.disclosure_queue("t")
    assert len(q) == 1 and q[0]["disclosure_status"] == "reported"


# --- compliance mapping (§15) ----------------------------------------------

def test_owasp_for_known_and_fallback():
    assert owasp_for("CWE-89") == "A03"               # injection
    assert owasp_for("CWE-918") == "A10"              # ssrf
    assert owasp_for("cwe89") == "A03"                # tolerant of formatting
    assert owasp_for(None) == "A04"                   # fallthrough, not dropped
    assert owasp_for("something-weird") == "A04"


def test_owasp_operator_override():
    assert owasp_for("CWE-89", extra={"CWE-89": "A99"}) == "A99"


def test_map_report_rollup_and_order():
    findings = [_f("a", category="CWE-89"), _f("b", category="CWE-78"),
                _f("c", category="CWE-918")]
    rows = map_report(findings)
    # CWE-89 + CWE-78 both A03 (2), CWE-918 A10 (1); most-hit first
    assert rows[0].owasp_id == "A03" and rows[0].count == 2
    assert rows[0].name == owasp_name("A03") == "Injection"
    assert rows[1].owasp_id == "A10" and rows[1].count == 1


def test_map_report_accepts_store_rows(tmp_path):
    store = _store(tmp_path)
    store.record_scan("t", [_f("a", category="CWE-89")], now=1000.0)
    rows = map_report(store.open_findings("t"))
    assert rows[0].owasp_id == "A03"
