"""Authorized external-target mode — step 19 (architecture §9)."""
import pytest

from cosmo.broker import EgressDenied
from cosmo.config import Config
from cosmo.external import ExternalTargetMode, ScopeRequired, parse_scope
from cosmo.external.scope import ScopeError


def _cfg(**et):
    base = {"enabled": True}
    base.update(et)
    return Config(data={"external_targets": base})


def _decl(**over):
    d = {"program": "acme-bounty", "includes": ["*.acme.example"],
         "rate_limit_per_sec": 2.0}
    d.update(over)
    return d


# --- scope parsing + operator clamps ----------------------------------------

def test_scope_requires_operator_enable():
    with pytest.raises(ScopeError):
        parse_scope(_decl(), Config(data={}))            # external_targets.enabled defaults off


def test_scope_needs_program_includes_and_rate():
    cfg = _cfg()
    with pytest.raises(ScopeError):
        parse_scope(_decl(program=""), cfg)
    with pytest.raises(ScopeError):
        parse_scope(_decl(includes=[]), cfg)
    with pytest.raises(ScopeError):
        parse_scope({"program": "p", "includes": ["a"]}, cfg)   # no rate


def test_rate_clamped_to_operator_ceiling():
    cfg = _cfg(max_rate_limit_per_sec=1.0)
    s = parse_scope(_decl(rate_limit_per_sec=10.0), cfg)
    assert s.rate_limit_per_sec == 1.0                   # declaration can't go faster


def test_mandatory_excludes_cannot_be_dropped():
    cfg = _cfg(mandatory_excludes=["admin.acme.example"])
    s = parse_scope(_decl(excludes=["staging.acme.example"]), cfg)
    assert "admin.acme.example" in s.excludes            # operator exclude unioned in
    assert "staging.acme.example" in s.excludes


# --- recon is refused before /scope, and out-of-scope is hard-excluded ------

def test_recon_refused_without_scope():
    m = ExternalTargetMode(config=_cfg())
    with pytest.raises(ScopeRequired):
        m.run_tool("httpx", "https://api.acme.example", runner=lambda u: "ran")


def test_in_scope_runs_out_of_scope_denied():
    m = ExternalTargetMode(config=_cfg())
    m.declare(_decl(excludes=["secret.acme.example"]))
    assert m.run_tool("httpx", "https://api.acme.example", runner=lambda u: "ok") == "ok"
    # excluded host: hard-refused, runner never invoked
    ran = []
    with pytest.raises(EgressDenied):
        m.run_tool("httpx", "https://secret.acme.example", runner=lambda u: ran.append(u))
    assert ran == []
    # host outside the include list entirely
    with pytest.raises(EgressDenied):
        m.run_tool("httpx", "https://not-acme.example", runner=lambda u: ran.append(u))
    assert ran == []


def test_forbidden_internal_address_denied():
    m = ExternalTargetMode(config=_cfg())
    m.declare(_decl(includes=["*"]))                     # even a wildcard scope...
    with pytest.raises(EgressDenied):
        m.run_tool("httpx", "http://169.254.169.254/latest/meta-data",
                   runner=lambda u: "ssrf")             # ...can't reach the metadata IP


# --- global rate-limit budget sits in front of all tools --------------------

def test_rate_limit_is_one_global_budget():
    # 1 token, no refill within the test window (fixed clock)
    clock = lambda: 1000.0
    m = ExternalTargetMode(config=_cfg())
    m.declare(_decl(rate_limit_per_sec=1.0), clock=clock)
    assert m.run_tool("httpx", "https://a.acme.example", runner=lambda u: "1") == "1"
    # a *different* tool shares the same budget — second request is throttled
    with pytest.raises(EgressDenied):
        m.run_tool("nuclei", "https://b.acme.example", runner=lambda u: "2")


# --- every request is logged (the program-owner record) ---------------------

def test_all_requests_logged():
    m = ExternalTargetMode(config=_cfg())
    m.declare(_decl())
    m.run_tool("httpx", "https://api.acme.example", runner=lambda u: "ok")
    try:
        m.run_tool("httpx", "https://evil.example", runner=lambda u: "x")
    except EgressDenied:
        pass
    log = m.audit_log()
    assert len(log) == 2
    assert log[0].allowed is True and log[0].tool == "httpx"
    assert log[1].allowed is False                       # the denied one is recorded too


# --- findings flow into the shared shape ------------------------------------

def test_to_finding_shared_shape():
    f = ExternalTargetMode.to_finding("nuclei", "https://api.acme.example",
                                      "Exposed .git", severity="high", category="CWE-538")
    assert f.source == "external"
    assert f.file == "https://api.acme.example"
    assert str(f.severity) == "high"
    assert f.fingerprint == f.id


# --- interactive /scope -----------------------------------------------------

def test_interactive_scope_disabled_by_default(tmp_path):
    from cosmo.interactive import Session, dispatch
    s = Session(config=Config(data={}), target=str(tmp_path))
    assert "no scope declared" in dispatch(s, "/scope")
    out = dispatch(s, "/scope program=acme includes=a.example rate=1")
    assert "refused" in out                              # operator hasn't enabled it


def test_interactive_scope_declared(tmp_path):
    from cosmo.interactive import Session, dispatch
    s = Session(config=_cfg(), target=str(tmp_path))
    out = dispatch(s, "/scope program=acme includes=a.example,b.example rate=2")
    assert "scope declared: acme" in out
    assert "every request is logged" in out
    assert "a.example" in dispatch(s, "/scope")          # now shows the active scope
