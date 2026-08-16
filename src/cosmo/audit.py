"""Whole-project LLM audit — chunked per-file review (extends architecture §1).

The batch LLM review (`provider.review`) sends the whole diff to the model as a
single prompt. That fits a PR or a small target, but a whole large codebase
overflows the context window. This module audits a *whole project* by splitting
it into per-file review units and running the LLM review on each, aggregating the
findings through the same downstream path (dedupe → waiver → gate).

Load-bearing safety property — a HARD CALL BUDGET (tested):
`llm_audit.max_files` caps how many files one audit sends to the model. It is an
operator ceiling (a safety-tier setting a repo may only *lower*, never raise), so
a whole-project audit can never fire an unbounded number of paid/subscription LLM
calls by accident. Files beyond the budget are **reported as un-audited**, never
silently dropped — the operator sees exactly what was and wasn't covered.
"""
from __future__ import annotations

from typing import Callable

from .config import Config
from .diff.resolver import Diff
from .findings import Finding

# Called with a human-readable progress line as each file is reviewed, so a slow
# multi-call audit shows it is working instead of looking hung.
Progress = Callable[[str], None]

# Conservative default so `--audit` with no operator config can't surprise the
# user with a huge run; the operator raises it deliberately.
DEFAULT_MAX_FILES = 50


def audit_call_budget(config: Config) -> int:
    """The per-run file/call ceiling for a whole-project audit (safety tier)."""
    return int(config.get("llm_audit.max_files", DEFAULT_MAX_FILES))


def chunk_by_file(diff: Diff) -> list[Diff]:
    """One sub-Diff per file — the review unit for a whole-project audit.

    `raw` is cleared so `build_review_prompt` reconstructs the prompt from just
    this file's added lines (the model sees one file at a time)."""
    return [
        Diff(source=diff.source, target=diff.target, files=[f], raw="")
        for f in diff.files
    ]


def run_llm_audit(
    diff: Diff,
    provider,
    context: str,
    findings_so_far: list[Finding],
    config: Config,
    notes: list[str],
    skipped: list[str],
    progress: Progress | None = None,
) -> list[Finding]:
    """Review a whole project file-by-file, bounded by the call budget.

    A per-file review error is isolated (recorded in `skipped`) and never aborts
    the rest of the audit. The number reviewed vs. total, and any un-audited
    remainder, are always surfaced in `notes`. `progress`, if given, is called
    with a status line as each file is reviewed (for slow multi-call runs).
    """
    budget = audit_call_budget(config)
    chunks = chunk_by_file(diff)
    reviewed = chunks[:budget]      # the hard cap — never exceeded

    def _say(msg: str) -> None:
        if progress is not None:
            progress(msg)

    total = len(reviewed)
    _say(f"llm-audit: reviewing {total} file(s) with model:{provider.name} "
         f"(budget {budget}, {len(chunks)} total)…")

    out: list[Finding] = []
    for i, sub in enumerate(reviewed, start=1):
        path = sub.files[0].path if sub.files else "?"
        _say(f"  [{i}/{total}] {path}")
        try:
            found = provider.review(sub, context, findings_so_far + out)
            out += found
            if found:
                _say(f"        → {len(found)} finding(s)")
        except Exception as exc:    # one bad file doesn't sink the audit
            skipped.append(f"model:{provider.name} audit {path} (error: {exc})")
            _say(f"        → skipped (error: {str(exc)[:80]})")

    notes.append(
        f"llm-audit: reviewed {len(reviewed)}/{len(chunks)} file(s) "
        f"with model:{provider.name} (budget {budget})"
    )
    if len(chunks) > budget:
        remaining = len(chunks) - budget
        notes.append(
            f"llm-audit: {remaining} file(s) NOT audited — over the "
            f"llm_audit.max_files budget ({budget}); raise it in operator config to cover more"
        )
    return out
