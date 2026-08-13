"""Trigger adapters (architecture §2) — thin callers of run_review.

Build step 13: the git-hook adapter (pre-commit over the staged diff).
Build step 14: the GitHub Action adapter (PR diff → SARIF + gated PR comment).
"""
from .git_hook import install_hook, render_hook_output, run_git_hook
from .github_action import parse_pr_ref, run_github_action

__all__ = [
    "run_git_hook", "render_hook_output", "install_hook",
    "run_github_action", "parse_pr_ref",
]
