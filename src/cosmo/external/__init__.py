"""Authorized external-target mode (architecture §9, build step 19).

Testing a live target the user is separately authorized to test. The enforcement
already lives in the egress broker (§9a, step 7) — mode gate, resolved-host
scope/exclusion check, one global rate-limit budget, forbidden-address refusal,
and logging. This layer adds the `/scope` declaration parsing (with operator
clamps) and a thin driver that runs recon tools through the broker in EXTERNAL
mode. There is no code path from §6/§7 sandbox/fuzz testing into this mode:
an external host is reachable only through an explicit, logged `/scope`.
"""
from .mode import ExternalTargetMode, ScopeRequired
from .scope import ScopeError, parse_scope

__all__ = ["ExternalTargetMode", "ScopeRequired", "parse_scope", "ScopeError"]
