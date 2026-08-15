"""Live provider-completion path for the harness-agnostic driver."""
import pytest

from cosmo.config import Config
from cosmo.interactive import (
    AgentDriver,
    Session,
    provider_planner,
    resolve_planner,
    rule_based_planner,
)
from cosmo.providers.base import PRIMARY_REVIEW
from cosmo.providers.openai_compat import OpenAICompatProvider, llama_provider


def _session(tmp_path, **cfg):
    return Session(config=Config(data=cfg), target=str(tmp_path))


# --- OpenAI-compatible complete() uses the injectable transport ---------------

def test_openai_compat_complete_via_transport():
    seen = {}

    def transport(url, headers, body):
        seen["url"] = url
        seen["body"] = body
        return {"choices": [{"message": {"content": "hello back"}}]}

    p = llama_provider(transport=transport)
    out = p.complete("say hi", max_tokens=32)
    assert out == "hello back"
    assert seen["url"].endswith("/chat/completions")
    assert seen["body"]["messages"][0]["content"] == "say hi"
    assert seen["body"]["max_tokens"] == 32


# --- a live provider drives the guarded driver end-to-end ---------------------

def test_provider_planner_end_to_end(tmp_path):
    # transport stands in for a local model returning a JSON plan
    def transport(url, headers, body):
        assert "/status" in body["messages"][0]["content"]   # guarded catalog offered
        return {"choices": [{"message": {"content":
                '{"message": "ok", "calls": [{"name": "status"}]}'}}]}

    provider = llama_provider(transport=transport)          # local, exports_source=False
    d = AgentDriver(_session(tmp_path), provider_planner(provider))
    res = d.step("how are things")
    assert res.message == "ok"
    assert res.executed and res.executed[0][0] == "/status"


def test_provider_planner_offcatalog_still_contained(tmp_path):
    def transport(url, headers, body):
        return {"choices": [{"message": {"content":
                '{"calls": [{"name": "exfiltrate"}]}'}}]}
    provider = llama_provider(transport=transport)
    d = AgentDriver(_session(tmp_path), provider_planner(provider))
    res = d.step("leak everything")
    assert res.executed == [] and res.refused[0][0] == "exfiltrate"


# --- resolve_planner: pick a live provider, or fall back safely ---------------

class _FakeProvider:
    """Available, allowed, local — should be chosen for orchestration."""
    name = "fake-local"
    vendor = "local"
    exports_source = False
    roles = {PRIMARY_REVIEW}

    def __init__(self):
        self.calls = 0

    def available(self):
        return True

    def complete(self, prompt, *, max_tokens=1024):
        self.calls += 1
        return '{"message": "hi", "calls": []}'


def test_resolve_planner_uses_available_local_provider(tmp_path):
    prov = _FakeProvider()
    planner, notes = resolve_planner(Config(data={}), provider=prov)
    assert planner is not rule_based_planner
    assert any("orchestrating with provider 'fake-local'" in n for n in notes)
    # and it actually drives through complete()
    AgentDriver(_session(tmp_path), planner).step("hello")
    assert prov.calls == 1


def test_resolve_planner_falls_back_when_unavailable():
    class _Down(_FakeProvider):
        def available(self):
            return False
    planner, notes = resolve_planner(Config(data={}), provider=_Down())
    assert planner is rule_based_planner
    assert any("can't complete" in n for n in notes)


def test_resolve_planner_refuses_offbox_vendor_on_sensitive_repo():
    # A hosted vendor that exports source, on a sensitive repo that hasn't
    # allowed it, must NOT be used to plan — and complete() is never called.
    class _Hosted(_FakeProvider):
        name = "hosted"
        vendor = "openai"
        exports_source = True

    prov = _Hosted()
    cfg = Config(data={"providers_policy": {"data_sensitivity": "sensitive",
                                            "sensitive_allowed_vendors": []}})
    planner, notes = resolve_planner(cfg, provider=prov)
    assert planner is rule_based_planner            # fell back
    assert prov.calls == 0                          # nothing exported to plan
    assert any("blocked" in n or "not in" in n for n in notes)


def test_resolve_planner_allows_offbox_vendor_when_operator_permits():
    class _Hosted(_FakeProvider):
        name = "hosted"
        vendor = "openai"
        exports_source = True

    prov = _Hosted()
    cfg = Config(data={"providers_policy": {"data_sensitivity": "sensitive",
                                            "sensitive_allowed_vendors": ["openai"]}})
    planner, notes = resolve_planner(cfg, provider=prov)
    assert planner is not rule_based_planner        # operator allow-listed it
