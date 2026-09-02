"""The scanner registry and how the pre-filter runs it.

The properties here are the ones that stop a wider tool set from making the
scan *less* trustworthy: a tool that is absent, disabled, broken or slow has to
be visible in `skipped`, one tool must not be able to sink the others, results
must not depend on which scanner finished first, and a repo must not be able to
switch off the scanner that would have caught it.
"""
import subprocess
import threading
import time

import pytest

from cosmo.config import Config, load_config
from cosmo.findings import Finding
from cosmo.severity import Severity
from cosmo.static import prefilter
from cosmo.static.prefilter import (DEFAULT_TOOLS, TOOLS, TOOLS_BY_NAME, Tool,
                                    run_static_prefilter, selected_tools,
                                    static_ruleset_id)


def _finding(name, file="a.py"):
    return Finding(id=f"{name}-1", title=f"from {name}", severity=Severity.HIGH,
                   source="static", file=file, line=1)


def _fake(name, *, runner=None, binaries=None):
    return Tool(name, binaries or (name,),
                runner or (lambda root, ev, sk: [_finding(name)]),
                f"{name} coverage", f"install {name}")


@pytest.fixture
def registry(monkeypatch):
    """Swap the registry for fakes so tests don't depend on installed tools."""
    def _install(tools, present=None):
        monkeypatch.setattr(prefilter, "TOOLS", tuple(tools))
        monkeypatch.setattr(prefilter, "DEFAULT_TOOLS",
                            tuple(t.name for t in tools))
        names = ({b for t in tools for b in t.binaries}
                 if present is None else set(present))
        monkeypatch.setattr(prefilter.shutil, "which",
                            lambda b: f"/usr/bin/{b}" if b in names else None)
    return _install


# --- the registry is coherent -----------------------------------------------

def test_every_registered_tool_is_fully_described():
    for tool in TOOLS:
        assert tool.name and tool.binaries and callable(tool.runner)
        assert tool.covers, f"{tool.name} must say what it covers"
        assert tool.install, f"{tool.name}'s skip line must be actionable"
        # Without an update source `cosmo tools --check-updates` silently has
        # nothing to say about this tool, which reads as "fine".
        assert tool.latest.startswith(("pypi:", "github:")), \
            f"{tool.name} has no update source"


def test_tool_names_are_unique_and_indexed():
    names = [t.name for t in TOOLS]
    assert len(names) == len(set(names))
    assert set(TOOLS_BY_NAME) == set(names) == set(DEFAULT_TOOLS)


# --- absence, disablement and failure are all visible -----------------------

def test_a_missing_tool_is_reported_with_what_it_would_have_covered(registry, tmp_path):
    registry([_fake("alpha"), _fake("beta")], present={"alpha"})
    findings, skipped = run_static_prefilter(str(tmp_path))
    assert [f.title for f in findings] == ["from alpha"]
    note = next(s for s in skipped if "beta" in s)
    assert "not installed" in note
    assert "beta coverage" in note      # what was lost, not just that it was
    assert "install beta" in note       # ...and how to get it


def test_a_disabled_tool_is_still_reported(registry, tmp_path):
    """Turning a scanner off narrows coverage. Silently is the one way it must
    not happen — that is the whole contract of this stage."""
    registry([_fake("alpha"), _fake("beta")])
    seen = []
    cfg = Config(data={"static": {"tools": ["alpha"]}})
    findings, skipped = run_static_prefilter(str(tmp_path), events=seen.append,
                                             config=cfg)
    assert [f.title for f in findings] == ["from alpha"]
    assert any("beta" in e.message and "not enabled" in e.message for e in seen)


def test_a_broken_tool_does_not_sink_the_others(registry, tmp_path):
    def explode(root, ev, sk):
        raise RuntimeError("boom")

    registry([_fake("alpha", runner=explode), _fake("beta")])
    findings, skipped = run_static_prefilter(str(tmp_path))
    assert [f.title for f in findings] == ["from beta"]
    assert any("alpha" in s and "boom" in s for s in skipped)


def test_a_timeout_names_the_tool_and_the_limit(registry, tmp_path):
    def slow(root, ev, sk):
        raise subprocess.TimeoutExpired(cmd="alpha", timeout=42)

    registry([_fake("alpha", runner=slow), _fake("beta")])
    findings, skipped = run_static_prefilter(str(tmp_path))
    assert [f.title for f in findings] == ["from beta"]
    note = next(s for s in skipped if "alpha" in s)
    assert "42s" in note and "NOT scanned" in note


def test_a_runner_can_report_a_partial_result(registry, tmp_path):
    """gitleaks scanning the tree but timing out on history is neither a clean
    pass nor a failed stage; the runner's own note has to survive."""
    def partial(root, ev, sk):
        sk.append("static:alpha history NOT scanned")
        return [_finding("alpha")]

    registry([_fake("alpha", runner=partial)])
    findings, skipped = run_static_prefilter(str(tmp_path))
    assert len(findings) == 1
    assert "static:alpha history NOT scanned" in skipped


# --- concurrency must not change the answer ---------------------------------

def test_findings_follow_registry_order_not_completion_order(registry, tmp_path):
    """Scanners run at once and finish in any order. If that leaked into the
    output, two identical runs would produce different reports."""
    def slow(root, ev, sk):
        time.sleep(0.15)
        return [_finding("alpha")]

    registry([_fake("alpha", runner=slow), _fake("beta"), _fake("gamma")])
    findings, _ = run_static_prefilter(str(tmp_path))
    assert [f.title for f in findings] == ["from alpha", "from beta", "from gamma"]


def test_scanners_actually_run_concurrently(registry, tmp_path):
    """Serially these would take 4 x 0.2s. The point of the pool is that a slow
    scanner does not hold up the rest."""
    barrier = threading.Barrier(4, timeout=5)

    def waits(root, ev, sk):
        barrier.wait()          # raises BrokenBarrierError if they are serialised
        return [_finding("x")]

    registry([_fake(n, runner=waits) for n in ("a", "b", "c", "d")])
    findings, skipped = run_static_prefilter(str(tmp_path))
    assert len(findings) == 4
    assert not [s for s in skipped if "error" in s]


def test_partial_notes_from_parallel_runners_are_all_kept(registry, tmp_path):
    """Each runner gets its own list; a shared one would race and drop notes."""
    def noisy(name):
        def run(root, ev, sk):
            sk.append(f"static:{name} partial")
            return []
        return run

    registry([_fake(n, runner=noisy(n)) for n in ("a", "b", "c", "d")])
    _, skipped = run_static_prefilter(str(tmp_path))
    for n in ("a", "b", "c", "d"):
        assert f"static:{n} partial" in skipped


# --- the cache must not replay a narrower scan ------------------------------

def test_the_tool_set_is_part_of_the_cache_identity():
    """Enabling a scanner and re-running must not hand back the old set's
    cached findings for unchanged files."""
    all_tools = static_ruleset_id(None)
    fewer = static_ruleset_id(Config(data={"static": {"tools": ["semgrep"]}}))
    assert all_tools != fewer
    assert "semgrep" in fewer


def test_ruleset_id_is_stable_regardless_of_how_the_list_was_written():
    a = static_ruleset_id(Config(data={"static": {"tools": ["gitleaks", "semgrep"]}}))
    b = static_ruleset_id(Config(data={"static": {"tools": ["semgrep", "gitleaks"]}}))
    assert a == b


# --- dependency auditing ----------------------------------------------------

def test_dep_audit_is_reported_when_no_dependency_scanner_ran(registry, tmp_path):
    registry([_fake("semgrep")])
    _, skipped = run_static_prefilter(str(tmp_path))
    assert any("dep-audit" in s for s in skipped)


def test_dep_audit_is_not_reported_when_trivy_ran(registry, tmp_path):
    registry([_fake("trivy")])
    _, skipped = run_static_prefilter(str(tmp_path))
    assert not any("dep-audit" in s for s in skipped)


# --- the trust boundary -----------------------------------------------------

def test_a_repo_cannot_switch_a_scanner_off(tmp_path):
    """A repo dropping gitleaks from the list is a repo hiding its own secrets.
    The operator's set is a floor; a repo may only add."""
    (tmp_path / "cosmo.yaml").write_text("static:\n  tools: [semgrep]\n")
    cfg = load_config(str(tmp_path))
    assert set(cfg.get("static.tools")) >= set(DEFAULT_TOOLS)
    assert any("static.tools" in w for w in cfg.warnings)


def test_a_repo_may_add_a_scanner_without_a_warning(tmp_path):
    listed = list(DEFAULT_TOOLS)
    (tmp_path / "cosmo.yaml").write_text(
        "static:\n  tools: [" + ", ".join(listed + ["extra-tool"]) + "]\n")
    cfg = load_config(str(tmp_path))
    assert "extra-tool" in cfg.get("static.tools")
    assert not any("static.tools" in w for w in cfg.warnings)


def test_an_unknown_tool_name_is_simply_not_run(registry, tmp_path):
    """A repo adding a name cosmo has no runner for must not crash the stage."""
    registry([_fake("alpha")])
    cfg = Config(data={"static": {"tools": ["alpha", "nonesuch"]}})
    findings, _ = run_static_prefilter(str(tmp_path), config=cfg)
    assert [f.title for f in findings] == ["from alpha"]


def test_selected_tools_defaults_to_everything_when_unconfigured():
    assert [t.name for t in selected_tools(None)] == list(DEFAULT_TOOLS)
    assert [t.name for t in selected_tools(Config(data={}))] == list(DEFAULT_TOOLS)


def test_a_tool_with_several_executable_names_resolves_either(monkeypatch):
    """find-sec-bugs ships a `.sh` wrapper some installs rename. Resolving at
    scan time, not import time, is what lets a tool installed after cosmo was
    imported still be found."""
    tool = TOOLS_BY_NAME["find-sec-bugs"]
    assert len(tool.binaries) > 1
    monkeypatch.setattr(prefilter.shutil, "which",
                        lambda b: "/usr/bin/x" if b == tool.binaries[-1] else None)
    assert tool.resolve() == tool.binaries[-1]
    monkeypatch.setattr(prefilter.shutil, "which", lambda b: None)
    assert tool.resolve() is None


# --- corroboration between tools --------------------------------------------

def test_agreement_between_independent_tools_is_recorded():
    """Duplicates collapse into one finding. Discarding the other tools'
    agreement would make running seven scanners look like running one."""
    from cosmo.engine import _dedupe

    def at(source, sev=Severity.HIGH):
        f = _finding("x")
        f.source, f.severity, f.category = source, sev, "CWE-78"
        return f

    out = _dedupe([at("static:semgrep"), at("static:bandit"),
                   at("static:find-sec-bugs")])
    assert len(out) == 1
    assert "also reported by: static:bandit, static:find-sec-bugs" in out[0].evidence


def test_independent_agreement_raises_confidence():
    from cosmo.engine import CORROBORATION_BONUS, _dedupe

    def at(source):
        f = _finding("x")
        f.source, f.category, f.confidence = source, "CWE-78", 0.7
        return f

    out = _dedupe([at("static:semgrep"), at("static:bandit")])
    assert out[0].confidence == pytest.approx(0.7 + CORROBORATION_BONUS)


def test_a_fork_agreeing_with_its_parent_is_not_independent():
    """opengrep inherits semgrep's rules. The two firing together is one
    opinion, and counting it twice would inflate every semgrep finding."""
    from cosmo.engine import _dedupe

    def at(source):
        f = _finding("x")
        f.source, f.category, f.confidence = source, "CWE-78", 0.7
        return f

    out = _dedupe([at("static:semgrep"), at("static:opengrep")])
    assert out[0].confidence == 0.7                    # unchanged
    assert "also reported by: static:opengrep" in out[0].evidence   # ...but shown


def test_corroboration_confidence_is_capped():
    from cosmo.engine import MAX_CORROBORATED_CONFIDENCE, _dedupe

    def at(source):
        f = _finding("x")
        f.source, f.category, f.confidence = source, "CWE-78", 0.9
        return f

    out = _dedupe([at(f"static:{n}") for n in
                   ("semgrep", "bandit", "trivy", "gitleaks", "trufflehog")])
    assert out[0].confidence <= MAX_CORROBORATED_CONFIDENCE


def test_a_lone_finding_is_left_untouched():
    from cosmo.engine import _dedupe
    f = _finding("x")
    f.evidence, f.confidence = "original", 0.7
    out = _dedupe([f])
    assert out[0].evidence == "original" and out[0].confidence == 0.7


def test_the_highest_severity_report_is_the_one_kept():
    from cosmo.engine import _dedupe

    low, high = _finding("a"), _finding("b")
    low.source, low.severity, low.category = "static:bandit", Severity.LOW, "CWE-78"
    high.source, high.severity, high.category = "static:semgrep", Severity.HIGH, "CWE-78"
    out = _dedupe([low, high])
    assert out[0].source == "static:semgrep" and out[0].severity is Severity.HIGH
    assert "static:bandit" in out[0].evidence


# --- provenance -------------------------------------------------------------

def test_every_runner_stamps_which_tool_found_it():
    """`source` follows the existing model:/ext: convention. Without the tool
    name there is no way to tell corroborating sources apart."""
    import inspect

    from cosmo.static import runners
    src = inspect.getsource(runners)
    assert 'source="static",' not in src, "a runner still reports a bare 'static'"
    for tool in ("gitleaks", "bandit", "trivy", "trufflehog", "find-sec-bugs"):
        assert f'source="static:{tool}"' in src


# --- attribution ------------------------------------------------------------

def test_every_tool_credits_its_authors():
    """cosmo finds almost nothing on its own — it runs other people's scanners.
    A tool added without attribution should fail here, not ship uncredited."""
    for tool in TOOLS:
        assert tool.project, f"{tool.name} has no project name"
        assert tool.author, f"{tool.name} names no maintainers"
        assert tool.license, f"{tool.name} has no license id"
        assert tool.homepage.startswith("http"), f"{tool.name} has no homepage"


def test_credits_file_lists_every_registered_tool():
    """CREDITS.md and the registry must not drift apart."""
    from pathlib import Path

    credits = (Path(__file__).resolve().parents[1] / "CREDITS.md").read_text()
    for tool in TOOLS:
        assert tool.project in credits, f"{tool.project} missing from CREDITS.md"
        assert tool.author in credits, f"{tool.author} missing from CREDITS.md"
        assert tool.license in credits, f"{tool.name}'s license missing"
        assert tool.homepage.rstrip("/") in credits, f"{tool.name}'s homepage missing"
