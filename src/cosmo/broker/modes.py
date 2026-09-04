"""Egress modes and the authorization decision type.

The mode is stamped on every outbound request and is what makes "no code path
to an arbitrary external target" a structural property rather than a convention:
a SANDBOX-mode request cannot resolve to anything but the sandbox-internal
network and the provisioning allowlist, and an EXTERNAL-mode request cannot run
without an active `/scope` declaration.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Mode(str, Enum):
    SANDBOX = "sandbox" # — own build only; internal net + provisioning allowlist
    EXTERNAL = "external" # — authorized live target; requires an active /scope
    DISCLOSURE = "disclosure" # — configured disclosure endpoints only
    PROVIDER = "provider" # — model API egress; only allow-listed provider hosts

    def __str__(self) -> str:  # noqa: D105
        return self.value


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    mode: Mode
    target: str
    resolved_host: str | None = None

    def __bool__(self) -> bool:  # `if broker.authorize(...):`
        return self.allowed


class EgressDenied(Exception):
    """Raised when a guarded request is refused by the broker."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"egress denied [{decision.mode}] {decision.target}: {decision.reason}")
