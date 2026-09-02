"""Custom extensions — third-party plugins & skills for cosmo.

Researchers extend cosmo without forking it by shipping an `Extension` that
contributes skills, detectors, and/or `/x-*` slash-commands. Extensions are
*discovered* from operator-configured local paths and installed entry points,
but only *activated* (imported and run) when the operator lists them in the
safety-tier `extensions.enabled` — a scanned repo can never enable one. Every
contribution flows through the same guardrails as first-party code: custom
findings go through the public-comment gate, custom commands are namespaced so
they can't impersonate a guarded builtin, and custom-skill trust follows the
operator's activation decision (RISK-03).

See `docs/extensions.md` for the authoring guide and `examples/extensions/` for
a worked example.
"""
from .loader import Discovered, LoadedExtensions, discover, load_enabled
from .registry import (
    CommandHandler,
    Detector,
    Extension,
    normalize_extension_findings,
)

__all__ = [
    "Extension", "Detector", "CommandHandler", "normalize_extension_findings",
    "Discovered", "LoadedExtensions", "discover", "load_enabled",
]
