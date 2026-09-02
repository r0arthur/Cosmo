"""Provider resolution + the data-governance gate (architecture §8).

Resolution order (provider selection): session `/model` → `--model` flag → repo
`cosmo.yaml` → org config → built-in Claude default.

Data-governance gate: enabling a hosted provider exports the target's source to
that vendor. At `data_sensitivity: sensitive` (a safety-tier setting a repo can
only tighten, never loosen — §15), only local providers and vendors the operator
has explicitly accepted (`sensitive_allowed_vendors`) are eligible. Everything
else falls through to the local Llama path or the Claude default per policy.

On a configured non-default provider being unavailable: fall back to Claude with
a warning, or hard-fail — never silently skip review (§8).
"""
from __future__ import annotations

from ..config import Config
from .base import PRIMARY_REVIEW, ModelProvider
from .claude import ClaudeProvider
from .claude_cli import ClaudeCLIProvider
from .openai_compat import codex_provider, deepseek_provider, llama_provider

_FACTORIES = {
    "claude": lambda: ClaudeProvider(),
    "claude-cli": lambda: ClaudeCLIProvider(),
    "codex": lambda: codex_provider(),
    "deepseek": lambda: deepseek_provider(),
    "llama": lambda: llama_provider(),
}

# cosmo's built-in default when nothing else is configured or reachable.
DEFAULT_PROVIDER = "claude"

# What each built-in provider needs before `available()` returns True. This is
# the *only* place the requirement is written down, so a skip message can say
# what is actually missing for the provider in play instead of naming
# Anthropic's key regardless of which model was asked for.
REQUIREMENTS: dict[str, str] = {
    "claude": "ANTHROPIC_API_KEY and the `anthropic` SDK",
    "claude-cli": "the `claude` CLI on PATH",
    "codex": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "llama": "a local OpenAI-compatible server (Ollama/vLLM) at "
             "http://localhost:11434/v1",
}


def primary_candidates() -> list[str]:
    """Built-in providers that declare themselves fit to be the primary reviewer.

    `llama` is excluded by its own `roles`: a small local model is offered for
    cross-checking, not as a stand-in for the reviewer.
    """
    names = []
    for name in _FACTORIES:
        provider = build_provider(name)
        if provider is not None and PRIMARY_REVIEW in provider.roles:
            names.append(name)
    return names


def describe_unavailable(provider: ModelProvider) -> str:
    """Why this provider cannot run, and what else could run instead.

    The review stage skipping is the one moment an operator needs the whole
    menu, so the message names the provider actually tried, what it is missing,
    and either the alternatives already usable on this machine or what each
    would need. Anything less reads as "cosmo only supports Claude".
    """
    name = provider.name
    role = " (cosmo's default)" if name == DEFAULT_PROVIDER else ""
    need = REQUIREMENTS.get(name, "credentials or a reachable endpoint")

    ready, dormant = [], []
    for other in primary_candidates():
        if other == name:
            continue
        candidate = build_provider(other)
        if candidate is not None and candidate.available():
            ready.append(other)
        else:
            dormant.append(f"{other} needs {REQUIREMENTS.get(other, 'setup')}")

    if ready:
        alt = "available now: " + ", ".join(f"--model {n}" for n in ready)
    else:
        alt = "other providers: " + "; ".join(dormant)
    return f"model:{name}{role} unavailable — needs {need}. {alt}"


def build_provider(name: str) -> ModelProvider | None:
    factory = _FACTORIES.get(name)
    return factory() if factory else None


def vendor_allowed(provider: ModelProvider, config: Config) -> tuple[bool, str]:
    """The data-sensitivity gate. Local providers always pass."""
    if not provider.exports_source:
        return True, "local — source never leaves the box"
    sensitivity = config.get("providers_policy.data_sensitivity", "normal")
    if sensitivity != "sensitive":
        return True, "normal sensitivity"
    allowed = config.get("providers_policy.sensitive_allowed_vendors", []) or []
    if provider.vendor in allowed:
        return True, f"vendor {provider.vendor!r} explicitly accepted for sensitive repos"
    return False, (
        f"blocked: sensitivity=sensitive and vendor {provider.vendor!r} exports source "
        f"off-box (not in sensitive_allowed_vendors)"
    )


def resolve_primary(
    config: Config,
    cli_model: str | None = None,
    session_model: str | None = None,
) -> tuple[ModelProvider, list[str]]:
    """Return (primary provider, warnings), always ending at a usable provider."""
    warnings: list[str] = []
    hard_fail = config.get("providers.on_failure", "fallback") == "hard_fail"

    configured = None
    providers_cfg = config.get("providers", {}) or {}
    for name, spec in providers_cfg.items():
        if isinstance(spec, dict) and spec.get("default"):
            configured = name
            break

    for candidate in (session_model, cli_model, configured):
        if not candidate:
            continue
        provider = build_provider(candidate)
        if provider is None:
            warnings.append(f"unknown provider {candidate!r} — skipped")
            continue
        ok, reason = vendor_allowed(provider, config)
        if not ok:
            warnings.append(f"provider {candidate!r} {reason}")
            continue
        if not provider.available():
            msg = f"provider {candidate!r} unavailable (no SDK/key)"
            if hard_fail:
                raise RuntimeError(msg + " and on_failure=hard_fail")
            warnings.append(msg + " — falling back")
            continue
        return provider, warnings

    # Built-in Claude default (§8).
    return ClaudeProvider(), warnings
