"""Provider egress through the broker (architecture §8 + §9a).

Model-provider API calls now cross the same single chokepoint as every other
network touch. They are operator-credentialed, not untrusted, so PROVIDER mode's
job is not to gate *whether* to talk to the model — that is the §8
data-governance decision (`vendor_allowed`) — but to give model egress the same
two structural guarantees the broker gives everything else:

  * **One audit log.** Every model call is recorded in the broker's request log
    alongside sandbox, external, and disclosure egress.
  * **One forbidden-address block.** A provider endpoint pointed at an internal
    or cloud-metadata address (e.g. a repo overriding a local model's endpoint
    via the preference-tier `providers` config) is refused, exactly like an SSRF
    attempt in any other mode.

The allow-list is built from the known built-in vendor hosts plus loopback, and
extended by the operator via the safety-tier `providers_policy.allowed_provider_hosts`
(for a self-hosted / on-prem model endpoint). A host that is neither is refused.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..broker import EgressBroker, EgressDenied, Mode

# The endpoints the built-in providers ship with (see openai_compat / claude).
_BUILTIN_PROVIDER_HOSTS = (
    "api.anthropic.com",     # Claude (SDK)
    "api.openai.com",        # codex
    "api.deepseek.com",      # deepseek
    "localhost", "127.0.0.1", "::1",   # local Llama (Ollama/vLLM) defaults
)

_shared: EgressBroker | None = None


def provider_broker() -> EgressBroker:
    """A process-wide broker allowing the built-in provider hosts. Used when a
    provider isn't given a config-derived broker of its own."""
    global _shared
    if _shared is None:
        b = EgressBroker()
        b.allow_provider(*_BUILTIN_PROVIDER_HOSTS)
        _shared = b
    return _shared


def provider_broker_from_config(config) -> EgressBroker:
    """A fresh broker allowing the built-ins plus any operator-approved provider
    hosts (`providers_policy.allowed_provider_hosts`, safety tier)."""
    b = EgressBroker()
    b.allow_provider(*_BUILTIN_PROVIDER_HOSTS)
    extra = config.get("providers_policy.allowed_provider_hosts", []) or []
    b.allow_provider(*[str(h) for h in extra])
    return b


def host_of(url: str) -> str:
    return urlsplit(url).hostname or ""


def guard_provider_egress(broker: EgressBroker | None, url: str, tool: str) -> EgressBroker:
    """Authorize a model-API call through the broker (mode gate + forbidden-address
    block + log). Raises EgressDenied if refused. Returns the broker used, so the
    caller can inspect its log. The actual bytes are sent by the provider's own
    SDK/HTTP transport — unavoidable for the SDK — but the decision and the audit
    record are the broker's, in one place."""
    b = broker or provider_broker()
    decision = b.authorize(Mode.PROVIDER, url, tool)
    if not decision.allowed:
        raise EgressDenied(decision)
    return b
