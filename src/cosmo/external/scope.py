"""`/scope` declaration parsing + operator clamping.

A `/scope` declaration is the *only* way an external host becomes reachable, and
it is mandatory before any recon runs. This module turns a declaration (from
`/scope`, a YAML file, or CLI args) into a broker `Scope`, enforcing that:

- external-target mode is enabled by the operator at all (`external_targets.enabled`
  is a safety-tier setting a repo cannot flip on);
- the declaration is complete — a program name, a non-empty include list, and an
  explicit rate limit read from the program's terms (never inferred);
- operator `mandatory_excludes` are merged into the exclusion set and cannot be
  dropped by the declaration;
- the declared rate is clamped down to the operator ceiling if one is set — a
  declaration can go slower than the operator maximum, never faster.
"""
from __future__ import annotations

from ..broker import Scope
from ..config import Config


class ScopeError(Exception):
    """The declaration is incomplete or external-target mode is not permitted."""


def parse_scope(declaration: dict, config: Config) -> Scope:
    et = config.get("external_targets", {}) or {}
    if not et.get("enabled", False):
        raise ScopeError("external-target mode is disabled by the operator "
                         "(external_targets.enabled, safety tier)")

    program = (declaration.get("program") or "").strip()
    if not program:
        raise ScopeError("scope declaration needs a program name/URL")

    includes = [h.strip() for h in (declaration.get("includes") or []) if h.strip()]
    if not includes:
        raise ScopeError("scope declaration needs a non-empty in-scope asset list")

    if "rate_limit_per_sec" not in declaration:
        raise ScopeError("scope declaration needs an explicit rate limit from the "
                         "program's terms (never inferred)")
    rate = float(declaration["rate_limit_per_sec"])
    if rate <= 0:
        raise ScopeError("rate_limit_per_sec must be positive")

    # Operator ceiling: the declaration can only go slower.
    ceiling = et.get("max_rate_limit_per_sec")
    if ceiling is not None:
        rate = min(rate, float(ceiling))

    # Operator mandatory excludes are unioned in and cannot be removed.
    declared_excludes = [h.strip() for h in (declaration.get("excludes") or []) if h.strip()]
    mandatory = [h.strip() for h in (et.get("mandatory_excludes") or []) if h.strip()]
    excludes = list(dict.fromkeys(declared_excludes + mandatory))

    return Scope(program=program, includes=includes, excludes=excludes,
                 rate_limit_per_sec=rate)
