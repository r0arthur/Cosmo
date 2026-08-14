"""Authorized external-target mode (architecture §9).

Testing a live target the user is *separately authorized* to test (a bug-bounty
program, an approved pentest). Distinct from §6/§7, which only ever touch a build
cosmo provisioned itself — and there is deliberately **no code path between the
two**. An external host is reachable only through an explicit, logged `/scope`
declaration, and every reach is mediated by the egress broker (§9a) in EXTERNAL
mode: scope/exclusion check on the resolved host, one global rate-limit budget,
forbidden-address (SSRF) refusal, and logging. This module is a thin driver over
that broker — it does not re-implement any of the enforcement.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..broker import EgressBroker, EgressDenied, Mode, Scope
from ..config import Config
from ..findings import Finding
from ..severity import Severity
from .scope import parse_scope


class ScopeRequired(Exception):
    """A recon/scan was attempted before any `/scope` was declared."""


@dataclass
class ExternalTargetMode:
    config: Config
    broker: EgressBroker = field(default_factory=EgressBroker)
    scope: Scope | None = None

    # --- scope lifecycle ----------------------------------------------------

    def declare(self, declaration: dict, clock=None) -> Scope:
        """Parse + clamp a declaration and activate it on the broker. This builds
        the single global rate-limit bucket from the declared terms."""
        scope = parse_scope(declaration, self.config)
        self.scope = scope
        self.broker.declare_scope(scope, clock=clock)
        return scope

    def clear(self) -> None:
        self.scope = None
        self.broker.clear_scope()

    # --- recon --------------------------------------------------------------

    def run_tool(self, tool: str, url: str, runner, *, transport=None):
        """Run one external tool against `url`, gated by the broker in EXTERNAL
        mode. `runner(url) -> result` is invoked only if the broker authorizes;
        an out-of-scope host, an exclusion, a forbidden address, or a spent rate
        budget raises EgressDenied and the runner never runs.

        `transport` (optional) lets the broker follow + re-check redirects; when
        given, the broker performs the request and the runner interprets it."""
        if self.scope is None:
            raise ScopeRequired("declare a /scope before any external recon (§9)")
        if transport is not None:
            status, headers, body = self.broker.request(Mode.EXTERNAL, url, tool=tool,
                                                        transport=transport)
            return runner(url, status=status, headers=headers, body=body)
        decision = self.broker.authorize(Mode.EXTERNAL, url, tool=tool)
        if not decision.allowed:
            raise EgressDenied(decision)
        return runner(url)

    # --- audit + findings ---------------------------------------------------

    def audit_log(self) -> list:
        """The broker's request log — the record a program owner may ask for."""
        return list(self.broker.log.records)

    @staticmethod
    def to_finding(tool: str, url: str, title: str, severity="medium",
                   category: str | None = None, evidence: str = "") -> Finding:
        """Normalize an external-mode result into the shared Finding shape, so it
        flows into the same aggregator/waiver/disclosure paths as every source."""
        sev = severity if isinstance(severity, Severity) else Severity.parse(severity)
        fid = f"ext-{abs(hash((tool, url, title))) & 0xffffffff:x}"
        return Finding(id=fid, title=title, severity=sev, source="external",
                       file=url, line=0, category=category, evidence=evidence,
                       fingerprint=fid)
