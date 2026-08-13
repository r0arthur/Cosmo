"""GitHub Action trigger adapter (architecture §2).

A thin caller of run_review for the PR-diff trigger. Per §2: `medium+` threshold,
PR-comment / Checks + SARIF output, configurable blocking, static + LLM (the
dynamic sandbox is opt-in and out of the default path here). This is where the
public-comment gate (§12, RISK-05) governs a real outbound post: the PR comment
is rendered through `render_pr_comment`, which withholds confirmed/sensitive
findings and posts, at most, a generic acknowledgment — never a PoC.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Callable

from ..config import Config
from ..engine import run_review
from ..findings import Report
from ..output import render_pr_comment, render_sarif

_CI_DEFAULTS = {"threshold": "medium", "blocking": True}
_PR_REF = re.compile(r"(?P<repo>[^/\s#]+/[^/\s#]+)#(?P<num>\d+)")

# poster(pr_ref, body) -> None
Poster = Callable[[str, str], None]


def parse_pr_ref(pr_ref: str) -> tuple[str, str]:
    m = _PR_REF.search(pr_ref)
    if not m:
        raise ValueError(f"not a PR ref (expected 'owner/repo#123'): {pr_ref!r}")
    return m.group("repo"), m.group("num")


def run_github_action(
    config: Config,
    scan_target: str,
    *,
    pr_ref: str | None = None,
    post: bool = False,
    sarif_path: str | None = None,
    blocking_override: bool | None = None,
    poster: Poster | None = None,
) -> tuple[Report, int]:
    """Run the PR review; optionally write SARIF and post the gated PR comment.

    `scan_target` is what gets reviewed; `pr_ref` is where a comment is posted
    (defaults to scan_target). Returns (report, exit_code)."""
    trig = (config.get("triggers", {}) or {}).get("ci", {}) or {}
    config.data["threshold"] = trig.get("threshold", _CI_DEFAULTS["threshold"])
    blocking = blocking_override if blocking_override is not None else trig.get(
        "blocking", _CI_DEFAULTS["blocking"])

    report = run_review(scan_target, config)

    if sarif_path:
        Path(sarif_path).write_text(render_sarif(report))

    if post:
        body = render_pr_comment(report)   # gated — withholds confirmed/sensitive detail (§12)
        (poster or _gh_post)(pr_ref or scan_target, body)

    actionable = [f for f in report.findings if not f.waived]
    exit_code = 1 if (blocking and actionable) else 0
    return report, exit_code


def _gh_post(pr_ref: str, body: str) -> None:  # pragma: no cover - network
    repo, num = parse_pr_ref(pr_ref)
    subprocess.run(["gh", "pr", "comment", num, "-R", repo, "--body-file", "-"],
                   input=body, text=True, check=True)
