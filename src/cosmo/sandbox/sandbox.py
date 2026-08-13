"""Dynamic analysis sandbox orchestrator (architecture §6, build step 8).

Only ever targets a build cosmo itself provisioned — never a live external
target (that is §9, gated separately). All egress is mediated by the egress
broker (§9a) in SANDBOX mode, so this stage is structurally incapable of
reaching an arbitrary external host.

Stages: provision → health check → targeted confirmation → (exploratory: v2) →
evidence capture → teardown. **Teardown runs even on failure/crash.** A
provisioning failure degrades findings to `unconfirmed`; it never blocks the
static/LLM findings that don't need the sandbox.

Not on the MVP default path: `run_review` (steps 1–6) never calls this. A CI/
interactive trigger invokes `confirm_findings` explicitly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..broker import EgressBroker, Mode
from ..findings import ConfirmationStatus, Finding
from .probes import default_probe_for, evaluate
from .provision import plan_provisioning
from .runtime import ContainerRuntime, ContainerSpec, detect_runtime

# A prober runs one finding's probe against the live app and reports whether the
# vulnerable behavior was observed. Injectable so the orchestrator is testable
# without a running service. Returns (reproduced|None, evidence).
Prober = Callable[[Finding], "tuple[bool | None, str]"]


def _null_prober(finding: Finding) -> tuple[bool | None, str]:
    return None, "no probe executed (sandbox scaffold)"


@dataclass
class SandboxResult:
    findings: list[Finding]
    waiver_signals: list[str] = field(default_factory=list)  # fingerprints with a genuine FP signal
    skipped: list[str] = field(default_factory=list)
    rejected_commands: list[str] = field(default_factory=list)
    torn_down: bool = False


def confirm_findings(
    findings: list[Finding],
    spec: ContainerSpec,
    *,
    provisioning_commands: list[str] | None = None,
    runtime: ContainerRuntime | None = None,
    broker: EgressBroker | None = None,
    prober: Prober = _null_prober,
) -> SandboxResult:
    result = SandboxResult(findings=findings)
    runtime = runtime or detect_runtime()
    broker = broker or EgressBroker()

    if runtime is None or not runtime.available():
        result.skipped.append("sandbox (no container runtime — findings left unconfirmed)")
        return result

    # Wire the sandbox's internal net + provisioning allowlist into the broker.
    broker.sandbox_policy.internal_hosts = broker.sandbox_policy.internal_hosts or ["app.internal"]

    handle = None
    try:
        handle = runtime.start(spec)

        # Stage 1 — provisioning inside the broker's egress window (RISK-02/03).
        if provisioning_commands:
            safe, rejected = plan_provisioning(provisioning_commands)
            result.rejected_commands = rejected
            broker.open_provisioning_window()
            try:
                for argv in safe:
                    runtime.exec(handle, argv, timeout=spec.wall_clock_seconds)
            finally:
                broker.close_provisioning_window()  # egress drops to zero before the app runs

        # Stage 3 — targeted, non-destructive confirmation.
        for f in findings:
            if f.confirmation_status is ConfirmationStatus.CONFIRMED:
                continue
            probe = default_probe_for(f)
            reproduced, evidence = prober(f)
            outcome = evaluate(f, probe, reproduced, evidence)
            f.confirmation_status = outcome.status
            f.confidence = max(0.0, min(1.0, f.confidence + outcome.confidence_delta))
            f.evidence = outcome.evidence or f.evidence
            if outcome.feeds_waiver and f.fingerprint:
                result.waiver_signals.append(f.fingerprint)

    except Exception as exc:  # degrade, don't crash the whole review (§6)
        result.skipped.append(f"sandbox (error: {exc}; findings left unconfirmed)")
    finally:
        if handle is not None:
            runtime.teardown(handle)          # runs even on failure/crash
            result.torn_down = handle.torn_down

    return result
