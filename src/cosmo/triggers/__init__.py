"""Trigger adapters (architecture §2) — thin callers of run_review.

Build step 13: the git-hook adapter (pre-commit over the staged diff). The
GitHub Action adapter is step 14.
"""
from .git_hook import install_hook, render_hook_output, run_git_hook

__all__ = ["run_git_hook", "render_hook_output", "install_hook"]
