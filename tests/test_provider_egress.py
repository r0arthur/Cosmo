"""Model-provider API egress routed through the broker."""
import pytest

from cosmo.broker import EgressBroker, EgressDenied, Mode
from cosmo.config import Config
from cosmo.providers.claude import ClaudeProvider
from cosmo.providers.egress import (
    guard_provider_egress,
    provider_broker,
    provider_broker_from_config,
)
from cosmo.providers.openai_compat import (
    OpenAICompatProvider,
    deepseek_provider,
    llama_provider,
)


def _ok_transport(*a):
    return {"choices": [{"message": {"content": '{"message":"hi","calls":[]}'}}]}


# --- the built-in provider hosts are allowed; everything else is not ----------

def test_builtin_hosts_allowed():
    b = provider_broker()
    for host in ("api.anthropic.com", "api.openai.com", "api.deepseek.com", "localhost"):
        assert b.authorize(Mode.PROVIDER, f"https://{host}/v1/x", "t").allowed


def test_unknown_host_refused():
    b = EgressBroker()
    b.allow_provider("api.openai.com")
    assert not b.authorize(Mode.PROVIDER, "https://evil.example/v1", "t").allowed


def test_forbidden_address_refused_even_if_listed():
    # A provider endpoint pointed at the metadata IP is refused regardless.
    b = EgressBroker()
    b.allow_provider("169.254.169.254")           # even if somehow allow-listed...
    d = b.authorize(Mode.PROVIDER, "http://169.254.169.254/latest/meta-data", "t")
    assert not d.allowed and "forbidden" in d.reason


# --- guard_provider_egress raises + logs --------------------------------------

def test_guard_allows_and_logs():
    b = EgressBroker()
    b.allow_provider("api.deepseek.com")
    used = guard_provider_egress(b, "https://api.deepseek.com/v1/chat/completions", "model:deepseek")
    assert used is b
    assert len(b.log.records) == 1                # the call is on the single audit log


def test_guard_denies_unknown_host():
    b = EgressBroker()
    with pytest.raises(EgressDenied):
        guard_provider_egress(b, "https://not-a-model.example/v1", "model:x")
    assert len(b.log.records) == 1                # the denial is logged too


# --- a provider's own review()/complete() goes through the broker -------------

def test_openai_compat_complete_guarded_and_runs():
    # llama on localhost is allow-listed by the shared default broker → succeeds
    p = llama_provider(transport=_ok_transport)
    assert p.complete("hi") == '{"message":"hi","calls":[]}'


def test_provider_with_offlist_endpoint_is_refused():
    # A provider pointed at an unlisted host: the guard refuses before any send.
    sent = []

    def transport(url, headers, body):
        sent.append(url)                          # must never be reached
        return _ok_transport()

    p = OpenAICompatProvider(
        "rogue", "local", "http://evil.example/v1", "m",
        key_env=None, exports_source=False, roles=set(),
        transport=transport, broker=EgressBroker())   # empty allow-list
    with pytest.raises(EgressDenied):
        p.complete("hi")
    assert sent == []                             # bytes never left


def test_provider_endpoint_to_metadata_ip_refused():
    sent = []

    def transport(url, headers, body):
        sent.append(url)
        return _ok_transport()

    # A repo could override a local model's endpoint via preference-tier config;
    # the broker's forbidden-address block stops it reaching the metadata service.
    p = llama_provider(endpoint="http://169.254.169.254/v1",
                       transport=transport, broker=provider_broker())
    with pytest.raises(EgressDenied):
        p.complete("hi")
    assert sent == []


# --- operator can allow a self-hosted endpoint via safety-tier config ---------

def test_config_allows_self_hosted_endpoint():
    cfg = Config(data={"providers_policy": {"allowed_provider_hosts": ["llm.internal.example"]}})
    b = provider_broker_from_config(cfg)
    assert b.authorize(Mode.PROVIDER, "https://llm.internal.example/v1", "t").allowed
    # still refuses a host the operator didn't list
    assert not b.authorize(Mode.PROVIDER, "https://other.example/v1", "t").allowed


def test_config_broker_still_blocks_metadata():
    cfg = Config(data={"providers_policy": {"allowed_provider_hosts": ["10.0.0.5"]}})
    b = provider_broker_from_config(cfg)
    d = b.authorize(Mode.PROVIDER, "http://169.254.169.254/latest", "t")
    assert not d.allowed


# --- end-to-end: run_review attaches a broker to the resolved provider --------

def test_run_review_attaches_broker(tmp_path, monkeypatch):
    # A stub provider records the broker the engine attaches, and asserts a
    # PROVIDER-mode authorization happens during review.
    from cosmo import engine

    class _Stub:
        name = "stub"
        vendor = "local"
        exports_source = False
        roles = set()
        broker = None

        def available(self):
            return True

        def review(self, diff, context, findings):
            # the engine attached a config-derived broker before calling us
            assert isinstance(self.broker, EgressBroker)
            guard_provider_egress(self.broker, "https://api.openai.com/v1/x", "model:stub")
            return []

    (tmp_path / "a.py").write_text("x = 1\n")
    stub = _Stub()
    report = engine.run_review(str(tmp_path), Config(data={}), provider=stub)
    assert isinstance(stub.broker, EgressBroker)
    assert any(r.mode == str(Mode.PROVIDER) for r in stub.broker.log.records)
