"""Git hook trigger adapter (architecture §2).

A thin caller of run_review over the STAGED diff — no scan logic lives here.
Per §2 the git-hook trigger defaults to a `critical` threshold, short CLI
output, opt-in blocking, and static + LLM only (no sandbox/fuzzing — too slow
for a commit hook). It leans on the incremental cache (§15, step 12) to stay
fast enough to run inline.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from ..config import Config
from ..engine import run_review
from ..findings import Report

_HOOK_DEFAULTS = {"threshold": "critical", "blocking": False}


def run_git_hook(
    config: Config,
    *,
    hook_key: str = "pre_commit",
    staged_path: str = ".",
    blocking_override: bool | None = None,
) -> tuple[Report, int]:
    """Run the review over the staged diff. Returns (report, exit_code).

    exit_code is non-zero only when blocking is enabled AND an actionable finding
    survives the hook's threshold — so a non-blocking hook never aborts a commit.
    """
    trig = (config.get("triggers", {}) or {}).get(hook_key, {}) or {}
    config.data["threshold"] = trig.get("threshold", _HOOK_DEFAULTS["threshold"])
    blocking = blocking_override if blocking_override is not None else trig.get(
        "blocking", _HOOK_DEFAULTS["blocking"])

    report = run_review(f"staged:{staged_path}", config)
    actionable = [f for f in report.findings if not f.waived]
    exit_code = 1 if (blocking and actionable) else 0
    return report, exit_code


def render_hook_output(report: Report, exit_code: int) -> str:
    """Short, commit-friendly output."""
    actionable = sorted((f for f in report.findings if not f.waived),
                        key=lambda x: x.severity, reverse=True)
    if not actionable:
        skips = [s for s in report.skipped_stages if "unavailable" in s or "not installed" in s]
        tail = "  (some stages skipped)" if skips else ""
        return f"cosmo: no findings at or above threshold.{tail}"

    lines = [f"cosmo: {len(actionable)} finding(s) at or above threshold:"]
    for f in actionable:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"  [{str(f.severity).upper()}] {loc} — {f.title}")
    if exit_code:
        lines.append("commit blocked. Fix, or waive with `cosmo waive . <fingerprint>`, "
                     "or commit with --no-verify.")
    return "\n".join(lines)


# --- hook installation ------------------------------------------------------

_HOOK_TEMPLATE = """#!/usr/bin/env bash
# Installed by cosmo (architecture §2). Runs a staged-diff security review.
exec cosmo hook{blocking}
"""


def install_hook(repo_path: str = ".", hook_type: str = "pre-commit", blocking: bool = False) -> str:
    """Write a git hook that invokes `cosmo hook`. Returns the hook path."""
    hooks_dir = Path(repo_path) / ".git" / "hooks"
    if not hooks_dir.parent.is_dir():
        raise RuntimeError(f"{repo_path!r} is not a git repository (no .git)")
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / hook_type
    hook_path.write_text(_HOOK_TEMPLATE.format(blocking=" --blocking" if blocking else ""))
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(hook_path)
