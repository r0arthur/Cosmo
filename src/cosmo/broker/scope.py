"""Scope, sandbox, and disclosure policies (architecture §9/§9a).

Host matching is deliberately simple and explicit: exclusions are checked first
and always win, so a declared out-of-scope asset is refused outright, never
warned-and-continued (§9).

A safety net independent of scope: any target that resolves to a loopback,
private, link-local, or cloud-metadata address is refused in external-facing
modes — this is the SSRF/redirect pivot that a hostname allowlist alone misses.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

# Always refused in EXTERNAL/DISCLOSURE modes regardless of scope.
_FORBIDDEN_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata"}
_METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}


def normalize_host(host: str) -> str:
    return (host or "").lower().rstrip(".")


def host_matches(host: str, pattern: str) -> bool:
    """`*` matches any host; `*.example.com` matches the apex and any subdomain;
    others match exactly."""
    host = normalize_host(host)
    pattern = normalize_host(pattern)
    if pattern == "*":
        return bool(host)
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def is_forbidden_address(host: str) -> bool:
    """True for loopback/private/link-local/metadata targets (SSRF safety net)."""
    host = normalize_host(host)
    if host in _FORBIDDEN_HOSTNAMES or host in _METADATA_IPS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a hostname; DNS-resolution-based checks are a v2 hook
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved


@dataclass
class Scope:
    """An authorized external-target declaration (`/scope`, §9)."""

    program: str
    includes: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    rate_limit_per_sec: float = 1.0     # from the program's declared terms, never inferred

    def is_in_scope(self, host: str) -> bool:
        if any(host_matches(host, p) for p in self.excludes):
            return False
        return any(host_matches(host, p) for p in self.includes)


@dataclass
class SandboxPolicy:
    """What SANDBOX-mode egress may reach (architecture §6)."""

    internal_hosts: list[str] = field(default_factory=list)   # sandbox-internal network
    provisioning_allowlist: list[str] = field(default_factory=list)  # package registries / proxy
    provisioning_open: bool = False   # the narrow provisioning egress window (RISK-02)

    def allows(self, host: str) -> tuple[bool, str]:
        if any(host_matches(host, p) for p in self.internal_hosts):
            return True, "sandbox-internal network"
        if self.provisioning_open and any(host_matches(host, p) for p in self.provisioning_allowlist):
            return True, "provisioning egress window"
        if any(host_matches(host, p) for p in self.provisioning_allowlist):
            return False, "provisioning allowlist host, but the egress window is closed"
        return False, "sandbox mode cannot reach an external host"


@dataclass
class DisclosurePolicy:
    """Endpoints DISCLOSURE-mode egress may reach (architecture §13)."""

    allowed_endpoints: list[str] = field(default_factory=list)

    def allows(self, host: str) -> bool:
        return any(host_matches(host, p) for p in self.allowed_endpoints)
