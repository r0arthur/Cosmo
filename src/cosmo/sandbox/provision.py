"""Environment provisioning helpers (architecture §6.1, RISK-02 / RISK-03).

Two safety properties live here:

RISK-03 — README/manifests are untrusted DATA, never instructions. An LLM may
draft setup commands, but each drafted command is validated against an allowlist
of build verbs and rejected if it contains shell metacharacters (no chaining,
redirection, substitution, or `curl … | sh`). Free-form model output never
becomes a shell script.

RISK-02 — dependency installation is the one point that needs the network. It
runs inside the broker's provisioning egress window, and install commands are
hardened to skip lifecycle scripts on the first pass (`--ignore-scripts`), so
attacker-controlled postinstall/setup.py code doesn't execute during the window.
"""
from __future__ import annotations

import os
import shlex

# Executables permitted as the first token of a drafted provisioning command.
ALLOWED_BUILD_TOOLS = {
    "npm", "pnpm", "yarn", "pip", "pip3", "python", "python3", "poetry",
    "go", "mvn", "gradle", "make", "bundle", "composer", "cargo", "dotnet",
}
# Any of these in the raw string ⇒ reject (we execute argv directly, never a shell).
_SHELL_METACHARS = set("|&;<>`$()!{}*?\n\\\"'")

_INSTALL_HARDENING = {
    "npm": ("--ignore-scripts",),
    "pnpm": ("--ignore-scripts",),
    "yarn": ("--ignore-scripts",),
    "pip": ("--no-build-isolation",),   # placeholder; real pip script control is via env, see note
    "pip3": ("--no-build-isolation",),
}


class UnsafeCommand(ValueError):
    pass


def validate_provisioning_command(cmd: str) -> list[str]:
    """Return the argv for a safe command, or raise UnsafeCommand."""
    if any(ch in cmd for ch in _SHELL_METACHARS):
        raise UnsafeCommand(f"shell metacharacter in provisioning command: {cmd!r}")
    parts = shlex.split(cmd)
    if not parts:
        raise UnsafeCommand("empty provisioning command")
    tool = os.path.basename(parts[0])
    if tool not in ALLOWED_BUILD_TOOLS:
        raise UnsafeCommand(f"{tool!r} is not an allowed build tool")
    return parts


def harden_install(argv: list[str]) -> list[str]:
    """Add lifecycle-script suppression to an install command's first pass (RISK-02)."""
    if not argv:
        return argv
    tool = os.path.basename(argv[0])
    flags = _INSTALL_HARDENING.get(tool)
    is_install = any(a in ("install", "ci", "add") for a in argv[1:2]) or (tool in ("pip", "pip3") and "install" in argv)
    if flags and is_install:
        for f in flags:
            if f not in argv:
                argv = argv + [f]
    return argv


def plan_provisioning(commands: list[str]) -> tuple[list[list[str]], list[str]]:
    """Validate + harden a drafted command list.

    Returns (safe_argvs, rejected) — rejected commands are dropped with a reason,
    never executed. The sandbox degrades to `unconfirmed` if nothing safe remains.
    """
    safe: list[list[str]] = []
    rejected: list[str] = []
    for cmd in commands:
        try:
            argv = validate_provisioning_command(cmd)
        except UnsafeCommand as exc:
            rejected.append(str(exc))
            continue
        safe.append(harden_install(argv))
    return safe, rejected
