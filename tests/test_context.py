"""Context ingestion — step 11."""
from cosmo.config import Config
from cosmo.context import (
    ContextItem,
    apply_prioritization,
    build_priority_signals,
    extract_all,
    extract_signal,
    repo_of,
)
from cosmo.context.ingest import fetch_context
from cosmo.engine import run_review
from cosmo.findings import Finding
from cosmo.severity import Severity


# --- target parsing ---------------------------------------------------------

def test_repo_of():
    assert repo_of("owner/repo#12") == "owner/repo"
    assert repo_of("https://github.com/o/r/pull/5") == "o/r"
    assert repo_of("/local/path") is None


def test_fetch_skips_local_target():
    items, notes = fetch_context("/some/local/path")
    assert items == [] and any("not a GitHub target" in n for n in notes)


def test_fetch_uses_injected_fetcher():
    canned = [ContextItem("issue", "1", "t", "b", "open")]
    items, notes = fetch_context("o/r#1", fetcher=lambda repo, limit: canned)
    assert items == canned and notes == []


# --- signal extraction ------------------------------------------------------

def test_extracts_keywords_cve_stacktrace_paths():
    item = ContextItem(
        "issue", "42", "SQL injection in search",
        "See CVE-2021-1234. Traceback (most recent call last): boom in api/search.py",
        "open",
    )
    sig = extract_signal(item)
    assert "injection" in sig.keywords
    assert "CVE-2021-1234" in sig.cve_ids
    assert sig.has_stack_trace
    assert "api/search.py" in sig.mentioned_paths
    assert sig.security_weight > 0


def test_benign_issue_has_no_weight():
    sig = extract_signal(ContextItem("issue", "7", "Please add dark mode", "would be nice", "open"))
    assert sig.security_weight == 0


# --- prioritization (attention only, never suppress) ------------------------

def _f(file="api/search.py", conf=0.5, sev=Severity.HIGH):
    return Finding(id="x", title="t", severity=sev, source="static", file=file,
                   line=1, category="CWE-89", confidence=conf)


def test_referenced_file_gets_confidence_boost():
    items = [ContextItem("issue", "42", "SQL injection", "bug in api/search.py", "open")]
    priority = build_priority_signals(extract_all(items), ["api/search.py"])
    assert "api/search.py" in priority.path_boosts

    f = _f(conf=0.5)
    out = apply_prioritization([f], priority)
    assert out[0].confidence > 0.5
    assert "prioritized by context" in out[0].evidence


def test_prioritization_never_suppresses_or_creates():
    items = [ContextItem("issue", "1", "injection", "bug in a.py", "open")]
    priority = build_priority_signals(extract_all(items), ["b.py"])   # unrelated file
    findings = [_f(file="b.py", conf=0.5)]
    out = apply_prioritization(findings, priority)
    assert len(out) == 1                       # nothing created
    assert out[0].confidence == 0.5            # untouched (different file)


def test_boost_is_capped():
    # Many security issues naming the same file must not blow confidence past the cap.
    items = [ContextItem("issue", str(i), "rce injection overflow bypass",
                         "CVE-2020-1111 crash in x.py", "open") for i in range(20)]
    priority = build_priority_signals(extract_all(items), ["x.py"])
    assert priority.path_boosts["x.py"] <= 0.15 + 1e-9


def test_closed_issue_yields_partial_fix_hint():
    items = [ContextItem("issue", "9", "injection fixed", "patched api/x.py", "closed")]
    priority = build_priority_signals(extract_all(items), ["api/x.py"])
    assert any("partial-fix" in h for h in priority.partial_fix_hints)


# --- engine integration -----------------------------------------------------

def test_engine_applies_injected_context(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / "app.py").write_text("q = 1\n")

    class FakeProvider:
        name = "claude"

        def available(self):
            return True

        def review(self, diff, context, findings_so_far):
            return [Finding(id="m0", title="SQLi", severity=Severity.HIGH, source="model:claude",
                            file="app.py", line=1, category="CWE-89", confidence=0.5,
                            security_sensitive=True)]

    items = [ContextItem("issue", "3", "SQL injection", "vuln in app.py", "open")]
    report = run_review(str(tmp_path), Config(data={"threshold": "low"}),
                        provider=FakeProvider(), context_items=items)
    f = next(f for f in report.findings if f.file == "app.py")
    assert f.confidence > 0.5                  # prioritized by the injected issue
    assert any("context: prioritized" in n for n in report.notes)
