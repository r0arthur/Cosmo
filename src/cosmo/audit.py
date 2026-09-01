"""Whole-project LLM audit — chunked per-file review (extends architecture §1).

The batch LLM review (`provider.review`) sends the whole diff to the model as a
single prompt. That fits a PR or a small target, but a whole large codebase
overflows the context window. This module audits a *whole project* by splitting
it into per-file review units and running the LLM review on each — several at a
time, since the units are independent — aggregating the findings through the same
downstream path (dedupe → waiver → gate).

Load-bearing safety property — a HARD CALL BUDGET (tested):
`llm_audit.max_files` caps how many files one audit sends to the model. It is an
operator ceiling (a safety-tier setting a repo may only *lower*, never raise), so
a whole-project audit can never fire an unbounded number of paid/subscription LLM
calls by accident. Files beyond the budget are **reported as un-audited**, never
silently dropped — the operator sees exactly what was and wasn't covered.

Concurrency does not widen that budget: the file list is truncated to the ceiling
*before* any review is dispatched, so `llm_audit.concurrency` only changes how
fast the capped set is worked through, never how many calls are made.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .config import Config
from .diff.resolver import Diff
from .findings import Finding

# Called with a human-readable progress line as each file is reviewed, so a slow
# multi-call audit shows it is working instead of looking hung.
Progress = Callable[[str], None]
# Called after each file with (path, that file's findings), so a caller running
# the audit in the background can merge findings into live state incrementally.
OnResult = Callable[[str, "list[Finding]"], None]

# Conservative default so `--audit` with no operator config can't surprise the
# user with a huge run; the operator raises it deliberately.
DEFAULT_MAX_FILES = 50

# Per-file reviews are independent, so they run concurrently. Modest by default:
# the ceiling that bites first is the provider's rate limit, not local CPU.
DEFAULT_CONCURRENCY = 4


def audit_call_budget(config: Config) -> int:
    """The per-run file/call ceiling for a whole-project audit (safety tier)."""
    return int(config.get("llm_audit.max_files", DEFAULT_MAX_FILES))


def audit_concurrency(config: Config) -> int:
    """How many per-file reviews run at once (safety tier; repo may only lower).

    Never returns < 1: a 0 or negative operator value would otherwise reach
    ThreadPoolExecutor, which rejects it.
    """
    return max(1, int(config.get("llm_audit.concurrency", DEFAULT_CONCURRENCY)))


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
    on_result: OnResult | None = None,
    events=None,
) -> list[Finding]:
    """Review a whole project file-by-file, bounded by the call budget.

    Files are reviewed concurrently (`llm_audit.concurrency`). Each file is an
    independent unit: it sees `findings_so_far`, but not the other files' results.
    That is what makes the run parallelizable *and* reproducible — the returned
    findings stay in input file order however the reviews interleave.

    A per-file review error is isolated (recorded in `skipped`) and never aborts
    the rest of the audit. The number reviewed vs. total, and any un-audited
    remainder, are always surfaced in `notes`.

    `progress` and `on_result` are called from worker threads, serialized under
    one lock so neither ever sees two files at once.
    """
    from .events import Emitter
    ev = events if isinstance(events, Emitter) else Emitter(events)

    budget = audit_call_budget(config)
    workers = audit_concurrency(config)
    chunks = chunk_by_file(diff)
    reviewed = chunks[:budget]      # the hard cap — never exceeded

    total = len(reviewed)
    lock = threading.Lock()
    done = 0

    def _say(msg: str) -> None:
        if progress is not None:
            progress(msg)

    def _tick(line: str) -> None:
        # Files finish out of order, so a completion count — not the input index —
        # is what makes the progress stream readable. Caller holds `lock`.
        nonlocal done
        done += 1
        _say(f"  [{done}/{total}] {line}")

    def _review_one(sub: Diff) -> list[Finding]:
        path = sub.files[0].path if sub.files else "?"
        # Emitted outside the lock so the UI shows every review that is genuinely
        # in flight, not a serialized view of them.
        ev.api_request(f"model:{provider.name} reviewing {path}", stage="llm", file=path)
        try:
            found = provider.review(sub, context, findings_so_far)
        except Exception as exc:    # one bad file doesn't sink the audit
            with lock:
                skipped.append(f"model:{provider.name} audit {path} (error: {exc})")
                _tick(f"{path} → skipped (error: {str(exc)[:80]})")
                ev.error(f"{path}: {str(exc)[:80]}", stage="llm", file=path)
            return []
        with lock:
            _tick(path + (f" → {len(found)} finding(s)" if found else ""))
            ev.output(f"{path} → {len(found)} finding(s)  [{done}/{total}]",
                      stage="llm", file=path, findings=len(found),
                      done=done, total=total)
            try:
                if on_result is not None:
                    on_result(path, found)
            except Exception as exc:    # nor does a caller's sink
                skipped.append(f"on_result {path} (error: {exc})")
        return found

    _say(f"llm-audit: reviewing {total} file(s) with model:{provider.name} "
         f"(budget {budget}, {len(chunks)} total, {workers} at a time)…")
    ev.operation(f"whole-project audit: {total} file(s) via model:{provider.name}, "
                 f"{workers} at a time (budget {budget} of {len(chunks)} files)",
                 stage="llm", total=total, workers=workers, budget=budget)

    if workers == 1 or total <= 1:
        per_file = [_review_one(sub) for sub in reviewed]
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cosmo-audit") as pool:
            # .map yields in input order, so `out` never depends on which
            # review happened to finish first.
            per_file = list(pool.map(_review_one, reviewed))

    out = [f for found in per_file for f in found]

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
