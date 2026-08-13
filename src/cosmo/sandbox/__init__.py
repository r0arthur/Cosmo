"""Dynamic analysis sandbox (architecture §6, build step 8).

Runs a build cosmo itself provisioned, in a hardened rootless container, to
confirm suspected findings with evidence. All egress goes through the egress
broker (§9a, step 7) in SANDBOX mode. Not on the MVP default path — invoked
explicitly via `confirm_findings`.
"""
from .probes import ConfirmationOutcome, Probe, default_probe_for, evaluate
from .provision import UnsafeCommand, plan_provisioning, validate_provisioning_command
from .runtime import ContainerSpec, PodmanRuntime, build_run_args, detect_runtime
from .sandbox import SandboxResult, confirm_findings

__all__ = [
    "confirm_findings", "SandboxResult",
    "ContainerSpec", "build_run_args", "PodmanRuntime", "detect_runtime",
    "plan_provisioning", "validate_provisioning_command", "UnsafeCommand",
    "Probe", "ConfirmationOutcome", "evaluate", "default_probe_for",
]
