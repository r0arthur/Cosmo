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
from .base import ModelProvider
from .claude import ClaudeProvider
from .openai_compat import codex_provider, deepseek_provider, llama_provider

_FACTORIES = {
    "claude": lambda: ClaudeProvider(),
    "codex": lambda: codex_provider(),
    "deepseek": lambda: deepseek_provider(),
    "llama": lambda: llama_provider(),
}


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
