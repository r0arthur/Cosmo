"""Claude-Code-CLI provider — subscription-backed reviewer (architecture §8 + §17).

Hermetic: the `claude` binary is never invoked; `_run_cli` is monkeypatched.
The load-bearing property is that using the subscription path does NOT bypass the
§8 data-governance gate — the diff still goes to Anthropic, so a sensitive repo
must gate it exactly like the API provider.
"""
from cosmo.config import Config
from cosmo.diff.resolver import Diff, DiffFile, Hunk
from cosmo.providers import ClaudeCLIProvider, resolve_primary, vendor_allowed
from cosmo.providers.registry import build_provider
from cosmo.severity import Severity


def _diff() -> Diff:
    h = Hunk(header="@@", added=[(1, "os.system(user_input)")])
    return Diff(source="local", target=".", files=[DiffFile(path="a.py", hunks=[h])])


# --- self-declaration / registry --------------------------------------------

def test_declares_hosted_anthropic_vendor():
    p = ClaudeCLIProvider()
    assert p.name == "claude-cli"
    assert p.vendor == "anthropic"
    assert p.exports_source is True   # the diff still reaches Anthropic via the CLI

def test_registered_in_factory():
    p = build_provider("claude-cli")
    assert isinstance(p, ClaudeCLIProvider)


# --- the §8 gate is NOT bypassed by the subscription path -------------------

def test_gate_blocks_at_sensitive_unless_anthropic_accepted():
    sensitive = Config(data={"providers_policy": {"data_sensitivity": "sensitive",
                                                  "sensitive_allowed_vendors": []}})
    ok, reason = vendor_allowed(ClaudeCLIProvider(), sensitive)
    assert not ok and "exports source" in reason

def test_gate_allows_when_anthropic_explicitly_accepted():
    cfg = Config(data={"providers_policy": {"data_sensitivity": "sensitive",
                                             "sensitive_allowed_vendors": ["anthropic"]}})
    assert vendor_allowed(ClaudeCLIProvider(), cfg)[0]

def test_resolve_selects_claude_cli_when_configured_and_available(monkeypatch):
    monkeypatch.setattr(ClaudeCLIProvider, "available", lambda self: True)
    cfg = Config(data={"providers": {"claude-cli": {"default": True}}})
    provider, warnings = resolve_primary(cfg)
    assert provider.name == "claude-cli"


# --- review parses the CLI's JSON output into the shared Finding contract ----

def test_review_parses_cli_json(monkeypatch):
    payload = ('[{"title":"OS command injection","severity":"high","file":"a.py",'
               '"line":1,"category":"CWE-78","confidence":0.9,'
               '"security_sensitive":true}]')
    monkeypatch.setattr(ClaudeCLIProvider, "_run_cli", lambda self, prompt: payload)
    findings = ClaudeCLIProvider().review(_diff(), context="", findings_so_far=[])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.HIGH
    assert f.source == "model:claude-cli"
    assert f.category == "CWE-78"

def test_complete_returns_cli_text(monkeypatch):
    monkeypatch.setattr(ClaudeCLIProvider, "_run_cli", lambda self, prompt: "  PONG\n")
    assert ClaudeCLIProvider().complete("ping") == "PONG"

def test_prompt_carries_review_instructions(monkeypatch):
    seen = {}
    monkeypatch.setattr(ClaudeCLIProvider, "_run_cli",
                        lambda self, prompt: seen.update(p=prompt) or "[]")
    ClaudeCLIProvider().review(_diff(), context="", findings_so_far=[])
    assert "security code reviewer" in seen["p"]      # system prompt is prepended
    assert "os.system(user_input)" in seen["p"]        # the added line is in the prompt


# --- availability reflects the binary, not an API key -----------------------

def test_available_follows_binary_presence(monkeypatch):
    import cosmo.providers.claude_cli as mod
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/claude")
    assert ClaudeCLIProvider().available() is True
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    assert ClaudeCLIProvider().available() is False

def test_nonzero_exit_raises(monkeypatch):
    import subprocess
    class P:
        returncode = 1
        stdout = ""
        stderr = "boom"
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    try:
        ClaudeCLIProvider()._run_cli("x")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "claude CLI exited 1" in str(e)
