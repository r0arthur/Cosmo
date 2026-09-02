"""Multi-model provider layer — step 9 (architecture §8)."""
from cosmo.config import Config, load_config
from cosmo.diff.resolver import Diff
from cosmo.findings import Finding
from cosmo.providers import (
    CROSS_CHECK,
    PRIMARY_REVIEW,
    ClaudeProvider,
    cross_check,
    resolve_primary,
    vendor_allowed,
)
from cosmo.providers.openai_compat import codex_provider, deepseek_provider, llama_provider
from cosmo.severity import Severity


# --- data-governance gate ---------------------------------------------------

def test_local_provider_always_allowed():
    ok, _ = vendor_allowed(llama_provider(), Config(data={}))
    assert ok


def test_hosted_allowed_at_normal_sensitivity():
    cfg = Config(data={"providers_policy": {"data_sensitivity": "normal"}})
    assert vendor_allowed(deepseek_provider(), cfg)[0]


def test_hosted_blocked_at_sensitive():
    cfg = Config(data={"providers_policy": {"data_sensitivity": "sensitive",
                                            "sensitive_allowed_vendors": []}})
    ok, reason = vendor_allowed(deepseek_provider(), cfg)
    assert not ok and "exports source" in reason


def test_hosted_allowed_when_vendor_explicitly_accepted():
    cfg = Config(data={"providers_policy": {"data_sensitivity": "sensitive",
                                            "sensitive_allowed_vendors": ["openai"]}})
    assert vendor_allowed(codex_provider(), cfg)[0]      # openai accepted
    assert not vendor_allowed(deepseek_provider(), cfg)[0]  # deepseek not


# --- config trust tier: repo can only tighten sensitivity -------------------

def test_repo_can_raise_but_not_lower_sensitivity(tmp_path):
    (tmp_path / "cosmo.yaml").write_text("providers_policy:\n  data_sensitivity: sensitive\n")
    cfg = load_config(tmp_path)
    assert cfg.get("providers_policy.data_sensitivity") == "sensitive"   # tighten allowed

    # Operator sensitive, repo tries to lower to normal → clamped.
    import os
    op = tmp_path / "op.yaml"
    op.write_text("providers_policy:\n  data_sensitivity: sensitive\n")
    (tmp_path / "cosmo.yaml").write_text("providers_policy:\n  data_sensitivity: normal\n")
    cfg2 = load_config(tmp_path, operator_config=str(op))
    assert cfg2.get("providers_policy.data_sensitivity") == "sensitive"  # loosening clamped


# --- resolution order + fallback --------------------------------------------

def test_resolves_to_claude_by_default():
    provider, warnings = resolve_primary(Config(data={}))
    assert isinstance(provider, ClaudeProvider)


def test_unavailable_configured_provider_falls_back_to_claude(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    cfg = Config(data={"providers": {"deepseek": {"default": True}}})
    provider, warnings = resolve_primary(cfg)
    assert isinstance(provider, ClaudeProvider)          # deepseek unavailable → fallback
    assert any("deepseek" in w and "fall" in w.lower() for w in warnings)


def test_sensitive_repo_skips_hosted_configured_provider(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "x")            # codex would be available...
    cfg = Config(data={
        "providers": {"codex": {"default": True}},
        "providers_policy": {"data_sensitivity": "sensitive", "sensitive_allowed_vendors": []},
    })
    provider, warnings = resolve_primary(cfg)
    assert isinstance(provider, ClaudeProvider)          # ...but gated by sensitivity
    assert any("exports source" in w for w in warnings)


# --- ensemble cross-check ---------------------------------------------------

def _diff():
    return Diff(source="local", target=".", files=[], raw="+ x")


def _f(line=10, category="CWE-89", conf=0.5):
    return Finding(id="p0", title="SQLi", severity=Severity.HIGH, source="model:claude",
                   file="a.py", line=line, category=category, confidence=conf)


class FakeCross:
    name = "llama"
    vendor = "local"
    exports_source = False
    roles = {CROSS_CHECK}

    def __init__(self, returns):
        self._returns = returns

    def available(self):
        return True

    def review(self, diff, context, findings_so_far):
        return self._returns


def test_agreement_raises_confidence():
    f = _f(conf=0.5)
    agreeing = [Finding(id="c0", title="SQLi", severity=Severity.HIGH, source="model:llama",
                        file="a.py", line=11, category="CWE-89")]
    out, _ = cross_check([f], FakeCross(agreeing), _diff())
    assert out[0].confidence > 0.5


def test_disagreement_lowers_confidence_and_flags():
    f = _f(conf=0.6)
    out, _ = cross_check([f], FakeCross([]), _diff())
    assert out[0].confidence < 0.6
    assert "no cross-model agreement" in out[0].evidence


def test_low_severity_not_cross_checked():
    f = Finding(id="p0", title="minor", severity=Severity.LOW, source="model:claude",
                file="a.py", line=1, category="CWE-89", confidence=0.5)
    out, _ = cross_check([f], FakeCross([]), _diff())
    assert out[0].confidence == 0.5                      # untouched


def test_provider_without_cross_check_role_skipped():
    class NoRole(FakeCross):
        roles = {PRIMARY_REVIEW}
    out, warnings = cross_check([_f()], NoRole([]), _diff())
    assert any("not eligible for cross_check" in w for w in warnings)


# --- an unavailable provider must name the whole menu, not just Anthropic ----

def test_unavailable_message_names_the_provider_actually_tried(monkeypatch):
    """The skip line was hard-coded to ANTHROPIC_API_KEY whichever model was
    asked for, so a live run read as if Claude were the only model cosmo drives.
    """
    from cosmo.providers import build_provider, describe_unavailable

    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    msg = describe_unavailable(build_provider("codex"))
    assert "model:codex" in msg
    assert "OPENAI_API_KEY" in msg
    assert "ANTHROPIC_API_KEY" not in msg        # not this provider's requirement


def test_unavailable_default_is_marked_as_the_default(monkeypatch):
    from cosmo.providers import build_provider, describe_unavailable
    from cosmo.providers.registry import DEFAULT_PROVIDER

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    msg = describe_unavailable(build_provider(DEFAULT_PROVIDER))
    assert "default" in msg
    assert "ANTHROPIC_API_KEY" in msg


def test_unavailable_message_offers_the_alternatives(monkeypatch):
    """With nothing configured, the operator gets the full menu and what each
    one needs — otherwise the only visible option is the one that just failed."""
    import shutil as _shutil

    from cosmo.providers import build_provider, describe_unavailable

    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(_shutil, "which", lambda *_a, **_k: None)   # no claude CLI

    msg = describe_unavailable(build_provider("claude"))
    for other in ("claude-cli", "codex", "deepseek"):
        assert other in msg
    # `llama` declares cross_check only — it is not a stand-in for the reviewer.
    assert "llama" not in msg


def test_a_reachable_alternative_is_named_as_a_flag(monkeypatch):
    import shutil as _shutil

    from cosmo.providers import build_provider, describe_unavailable

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(_shutil, "which", lambda *_a, **_k: None)

    msg = describe_unavailable(build_provider("claude"))
    assert "--model codex" in msg
    assert "DEEPSEEK_API_KEY" not in msg          # only what is usable right now


def test_every_built_in_provider_has_a_stated_requirement():
    """A provider added without a requirement line would report an unavailable
    reason of 'setup', which tells an operator nothing."""
    from cosmo.providers.registry import _FACTORIES, REQUIREMENTS

    assert set(_FACTORIES) == set(REQUIREMENTS)
