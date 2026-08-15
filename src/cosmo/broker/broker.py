"""Egress broker — the single guarded network chokepoint (architecture §9a).

Every mode that touches the network goes through here. There is structurally one
path out, and it is guarded, so "no code path to an arbitrary external target"
becomes a property that can be tested rather than a claim in prose.

Per outbound request, in order (§9a):
  1. Mode gate            — the caller's mode bounds what it can reach at all.
  2. Scope resolution     — include/exclude on the RESOLVED host, so a redirect
                            or newly-discovered host outside scope is refused.
  3. Global rate limit    — one token bucket in front of all external tools.
  4. Logging              — emitted here so no tool can sidestep it.

The broker governs sandbox provisioning, external-target recon, disclosure
delivery, and — via PROVIDER mode — model-provider API egress (§8). Provider
calls are operator-credentialed rather than untrusted, but routing them here too
means every network touch has exactly one audit log and one forbidden-address
(SSRF/metadata) block, so a provider endpoint a repo pointed at an internal
address is refused like anything else. GitHub reads (§3) remain plain trusted
egress outside the broker.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from .log import RequestLog
from .modes import Decision, EgressDenied, Mode
from .ratelimit import TokenBucket
from .scope import (
    DisclosurePolicy,
    ProviderPolicy,
    SandboxPolicy,
    Scope,
    is_forbidden_address,
    is_metadata_address,
    normalize_host,
)

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _host_of(url: str) -> str:
    return normalize_host(urlsplit(url).hostname or "")


class EgressBroker:
    def __init__(self, log: RequestLog | None = None):
        self.log = log or RequestLog()
        self.active_scope: Scope | None = None
        self.sandbox_policy = SandboxPolicy()
        self.disclosure_policy = DisclosurePolicy()
        self.provider_policy = ProviderPolicy()
        self._bucket: TokenBucket | None = None

    def allow_provider(self, *hosts: str) -> None:
        """Add allow-listed model-provider hosts for PROVIDER-mode egress (§8)."""
        self.provider_policy.allow(*hosts)

    # --- policy declaration -------------------------------------------------

    def declare_scope(self, scope: Scope, clock=None) -> None:
        """Activate an authorized external target (§9). Builds the one global bucket."""
        self.active_scope = scope
        kw = {"clock": clock} if clock else {}
        self._bucket = TokenBucket(scope.rate_limit_per_sec, **kw)

    def clear_scope(self) -> None:
        self.active_scope = None
        self._bucket = None

    def open_provisioning_window(self) -> None:
        self.sandbox_policy.provisioning_open = True

    def close_provisioning_window(self) -> None:
        self.sandbox_policy.provisioning_open = False

    # --- authorization ------------------------------------------------------

    def authorize(self, mode: Mode, url: str, tool: str = "unknown") -> Decision:
        """Full gate for one outbound request. Consumes a rate-limit token for
        EXTERNAL mode (authorization = intent to send now)."""
        host = _host_of(url)
        d = self._decide(mode, url, host)
        self.log.record(d, tool)
        return d

    def _decide(self, mode: Mode, url: str, host: str) -> Decision:
        def deny(reason: str) -> Decision:
            return Decision(False, reason, mode, url, host)

        def allow(reason: str) -> Decision:
            return Decision(True, reason, mode, url, host)

        if not host:
            return deny("no resolvable host in target")

        if mode is Mode.SANDBOX:
            ok, reason = self.sandbox_policy.allows(host)
            return allow(reason) if ok else deny(reason)

        if mode is Mode.EXTERNAL:
            if self.active_scope is None:
                return deny("external-target mode requires an active /scope declaration")
            if is_forbidden_address(host):
                return deny("target resolves to a forbidden internal/metadata address")
            if not self.active_scope.is_in_scope(host):
                return deny("host is out of declared scope")
            if self._bucket is None or not self._bucket.try_consume():
                return deny("rate limit exceeded (global scope budget)")
            return allow("in scope")

        if mode is Mode.DISCLOSURE:
            if is_forbidden_address(host):
                return deny("disclosure target resolves to a forbidden internal address")
            if self.disclosure_policy.allows(host):
                return allow("configured disclosure endpoint")
            return deny("host is not a configured disclosure endpoint")

        if mode is Mode.PROVIDER:
            # Metadata is a hard stop even if allow-listed; loopback/private is
            # fine for a local/on-prem model *when the operator listed it*.
            if is_metadata_address(host):
                return deny("provider endpoint resolves to a forbidden metadata address")
            if self.provider_policy.allows(host):
                return allow("allow-listed provider host")
            return deny("provider host is not allow-listed")

        return deny(f"unknown mode: {mode}")  # pragma: no cover

    # --- guarded request ----------------------------------------------------

    def request(self, mode: Mode, url: str, tool: str = "unknown", *, transport=None,
                max_redirects: int = 5):
        """Perform a guarded request, re-authorizing EVERY redirect hop against
        the same policy. A redirect to an out-of-scope host is refused mid-chain.

        `transport(url) -> (status:int, headers:dict, body)` is pluggable so this
        is testable without real network; a urllib default is used otherwise.
        """
        transport = transport or _urllib_transport
        current = url
        for _ in range(max_redirects + 1):
            decision = self.authorize(mode, current, tool)
            if not decision.allowed:
                raise EgressDenied(decision)
            status, headers, body = transport(current)
            headers = {k.lower(): v for k, v in (headers or {}).items()}
            if status in _REDIRECT_STATUSES and "location" in headers:
                current = urljoin(current, headers["location"])
                continue
            return status, headers, body
        raise EgressDenied(Decision(False, "too many redirects", mode, current, _host_of(current)))


def _urllib_transport(url: str):  # pragma: no cover - real network, not exercised in tests
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None  # the broker follows redirects itself, re-checking each hop

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(url, timeout=15)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
