"""Container runtime + isolation spec.

This stage runs untrusted, potentially adversarial code, so the isolation
requirements are non-negotiable. They live in ContainerSpec and are translated
to runtime flags by `build_run_args` — a pure function, unit-tested directly so
the guarantees can't silently regress:

  * rootless, non-root user            --user, no-new-privileges, --cap-drop=ALL
  * no network egress by default        --network none (broker mediates any egress)
  * docker socket NEVER mounted         (asserted absent)
  * read-only source, writable scratch  -v src:/src:ro + --read-only + tmpfs /work
  * CPU/memory/pids/disk caps           --cpus/--memory/--pids-limit/--storage-opt
  * clean env — no host secrets         only spec.env is passed; never --env-host

The concrete runtime (podman preferred, rootless) is detected at run time; if
none is available the sandbox stage degrades gracefully rather than failing.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ContainerSpec:
    image: str
    source_dir: str
    network: str = "none"           # "none" | an internal network name (never host/bridge by default)
    cpus: float = 1.0
    memory_mb: int = 1024
    pids_limit: int = 256
    disk_mb: int = 2048
    wall_clock_seconds: int = 300
    user: str = "1000:1000"         # rootless, non-root
    workdir: str = "/work"
    env: dict[str, str] = field(default_factory=dict)   # clean env; host secrets never added


def build_run_args(spec: ContainerSpec) -> list[str]:
    """Translate the spec to `podman run` args (docker-compatible subset).

    Security-critical and therefore pure + tested. Never emits a docker-socket
    mount and never emits --env-host.
    """
    args = [
        "run", "--rm",
        "--user", spec.user,
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--network", spec.network,
        "--read-only",                          # read-only rootfs
        "--tmpfs", f"{spec.workdir}:rw,nosuid,nodev",
        "--workdir", spec.workdir,
        "-v", f"{spec.source_dir}:/src:ro",     # source mounted read-only
        "--cpus", str(spec.cpus),
        "--memory", f"{spec.memory_mb}m",
        "--pids-limit", str(spec.pids_limit),
        "--storage-opt", f"size={spec.disk_mb}M",
    ]
    for k, v in spec.env.items():               # only explicit keys — never the host env
        args += ["--env", f"{k}={v}"]
    args.append(spec.image)
    return args


class ContainerHandle:
    def __init__(self, container_id: str):
        self.container_id = container_id
        self.torn_down = False


class ContainerRuntime(Protocol):
    name: str

    def available(self) -> bool: ...
    def start(self, spec: ContainerSpec) -> ContainerHandle: ...
    def exec(self, handle: ContainerHandle, cmd: list[str], timeout: int) -> tuple[int, str, str]: ...
    def teardown(self, handle: ContainerHandle) -> None: ...


class PodmanRuntime:
    """Rootless podman by default; docker is arg-compatible for this subset."""

    def __init__(self, binary: str = "podman"):
        self.binary = binary
        self.name = binary

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def start(self, spec: ContainerSpec) -> ContainerHandle:  # pragma: no cover - needs a runtime
        args = build_run_args(spec) + ["sleep", str(spec.wall_clock_seconds)]
        out = subprocess.run([self.binary, "-d", *args], capture_output=True, text=True, check=True)
        return ContainerHandle(out.stdout.strip())

    def exec(self, handle, cmd, timeout):  # pragma: no cover - needs a runtime
        p = subprocess.run(
            [self.binary, "exec", handle.container_id, *cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr

    def teardown(self, handle) -> None:  # pragma: no cover - needs a runtime
        subprocess.run([self.binary, "rm", "-f", handle.container_id], capture_output=True)
        handle.torn_down = True


def detect_runtime() -> ContainerRuntime | None:
    for binary in ("podman", "docker"):
        rt = PodmanRuntime(binary)
        if rt.available():
            return rt
    return None
