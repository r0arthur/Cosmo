"""Commit-history review — sweep a repository's past commits for vulnerabilities.

`run_review` looks at one diff: a PR, a working tree, a project. This module
looks at *many* — every commit in a range becomes its own review unit, which is
how you find a flaw that was introduced years ago and never fixed, or one that
was quietly patched without ever getting an advisory.

Two properties carry the design.

**A hard commit budget (cost guard).** `history.max_commits` caps how many
commits one sweep sends to the model. It is an operator ceiling a repo may only
lower, and the commit list is truncated *before* any review is dispatched — so
concurrency changes how fast the capped set is worked through, never how many
calls are made. Commits past the budget are reported as un-reviewed, never
silently dropped.

**Reachability is annotated, never asserted.** A finding in an old commit only
matters if the code is still there, so each one is checked against HEAD. The
answer is three-valued: PRESENT, ABSENT, or UNKNOWN. ABSENT means the line is
gone — which may be a fix, or may be a rename or a refactor — so it is recorded
as *context for the operator*, and never auto-waives a finding. That is the same
discipline as RISK-04: a probe that didn't reproduce is not proof of safety.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .audit import audit_concurrency
from .config import Config
from .diff.resolver import Diff, parse_unified_diff
from .findings import Finding

# A sweep is the most expensive thing cosmo can do — one model call per commit.
# Deliberately small by default; the operator raises it knowingly.
DEFAULT_MAX_COMMITS = 200

_SEP = "\x1f"      # unit separator: safe inside commit subjects
_FMT = _SEP.join(["%H", "%h", "%an", "%ae", "%aI", "%s"])


class HeadStatus(str, Enum):
    """Whether the reviewed code is still in the current HEAD."""

    PRESENT = "present"    # the vulnerable line is still there
    ABSENT = "absent"      # gone — could be a fix, could be a refactor
    UNKNOWN = "unknown"    # could not be determined; never read as safe

    def __str__(self) -> str:  # noqa: D105
        return self.value


@dataclass(frozen=True)
class Commit:
    sha: str
    short: str
    author: str
    email: str
    date: str          # ISO-8601
    subject: str

    def label(self) -> str:
        return f"{self.short} {self.subject}"


@dataclass
class Selection:
    """Which commits a sweep should look at."""

    since: str | None = None
    until: str | None = None
    author: str | None = None
    rev_range: str | None = None
    paths: list[str] | None = None
    include_merges: bool = False


def history_budget(config: Config) -> int:
    """Commits one sweep may review (safety tier; a repo may only lower it)."""
    return max(0, int(config.get("history.max_commits", DEFAULT_MAX_COMMITS)))


def clamp_requested(config: Config, requested: int | None) -> int:
    """Resolve a `--max-commits` request against the operator ceiling.

    A CLI flag is held to the same tier rule as a repo's cosmo.yaml: it may
    lower the budget, never raise it, so a flag cannot buy a bigger model bill.
    """
    ceiling = history_budget(config)
    if requested is None:
        return ceiling
    return max(0, min(int(requested), ceiling))


# --- sources ----------------------------------------------------------------
#
# A sweep needs three things from wherever the history lives: the commit list,
# one commit's diff, and a file's current content. Keeping that behind a source
# lets the same review logic run over a local clone or straight off the GitHub
# API, with no clone on disk.


class LocalGit:
    """History from a git repository on disk."""

    kind = "local"

    def __init__(self, repo: str) -> None:
        self.repo = str(repo)
        self._blobs: dict[str, str | None] = {}

    def _git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", self.repo, *args],
                              capture_output=True, text=True, check=True).stdout

    def list_commits(self, limit: int, sel: Selection) -> list[Commit]:
        if limit <= 0:
            return []
        args = ["log", f"--format={_FMT}", f"-n{limit}"]
        if not sel.include_merges:
            args.append("--no-merges")
        if sel.since:
            args.append(f"--since={sel.since}")
        if sel.until:
            args.append(f"--until={sel.until}")
        if sel.author:
            args.append(f"--author={sel.author}")
        if sel.rev_range:
            args.append(sel.rev_range)
        if sel.paths:
            args += ["--", *sel.paths]
        out = self._git(*args)
        commits: list[Commit] = []
        for line in out.splitlines():
            parts = line.split(_SEP)
            if len(parts) == 6:
                commits.append(Commit(*parts))
        return commits

    def commit_diff(self, commit: Commit) -> Diff:
        raw = self._git("show", commit.sha, "--format=", "--unified=3")
        return Diff(source="local", target=f"{self.repo}@{commit.short}",
                    files=parse_unified_diff(raw), raw=raw)

    def head_blob(self, path: str) -> str | None:
        if path not in self._blobs:
            try:
                self._blobs[path] = self._git("show", f"HEAD:{path}")
            except subprocess.CalledProcessError:
                self._blobs[path] = None
        return self._blobs[path]


class GitHubHistory:
    """History read straight off the GitHub API — no clone on disk.

    Same access pattern as the PR resolver: the `gh` CLI, already
    authenticated. Reading is unrestricted; posting stays gated.
    """

    kind = "github"

    def __init__(self, repo: str) -> None:
        self.repo = repo               # "owner/name"
        self._blobs: dict[str, str | None] = {}
        self._lock = threading.Lock()
        if not shutil.which("gh"):
            raise RuntimeError(
                f"remote history for {repo!r} needs the `gh` CLI (authenticated). "
                f"Install it, or clone the repo and pass a local path.")

    def _api(self, path: str, *extra: str, accept: str | None = None) -> str:
        cmd = ["gh", "api"]
        if accept:
            cmd += ["-H", f"Accept: {accept}"]
        cmd += [path, *extra]
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=True).stdout

    def list_commits(self, limit: int, sel: Selection) -> list[Commit]:
        if limit <= 0:
            return []
        out: list[Commit] = []
        page = 1
        while len(out) < limit:
            per_page = min(100, limit - len(out))
            args = [f"-Fper_page={per_page}", f"-Fpage={page}"]
            # The API takes ISO-8601 instants, not git's relative dates.
            if sel.since:
                args.append(f"-fsince={sel.since}")
            if sel.until:
                args.append(f"-funtil={sel.until}")
            if sel.author:
                args.append(f"-fauthor={sel.author}")
            if sel.rev_range:
                args.append(f"-fsha={sel.rev_range}")
            for p in (sel.paths or [])[:1]:   # the API takes a single path filter
                args.append(f"-fpath={p}")
            rows = json.loads(self._api(f"repos/{self.repo}/commits", *args) or "[]")
            if not rows:
                break
            for r in rows:
                if not sel.include_merges and len(r.get("parents", [])) > 1:
                    continue
                c = r.get("commit", {}).get("author", {}) or {}
                sha = r.get("sha", "")
                out.append(Commit(
                    sha=sha, short=sha[:7],
                    author=c.get("name", "unknown"), email=c.get("email", ""),
                    date=c.get("date", ""),
                    subject=(r.get("commit", {}).get("message", "")
                             .splitlines() or [""])[0],
                ))
                if len(out) >= limit:
                    break
            if len(rows) < per_page:
                break
            page += 1
        return out

    def commit_diff(self, commit: Commit) -> Diff:
        raw = self._api(f"repos/{self.repo}/commits/{commit.sha}",
                        accept="application/vnd.github.diff")
        return Diff(source="github", target=f"{self.repo}@{commit.short}",
                    files=parse_unified_diff(raw), raw=raw)

    def head_blob(self, path: str) -> str | None:
        # Reachability asks about the same handful of files repeatedly, and each
        # miss is a network round trip — cache, and guard it for the workers.
        with self._lock:
            if path in self._blobs:
                return self._blobs[path]
        try:
            blob = self._api(f"repos/{self.repo}/contents/{path}",
                             accept="application/vnd.github.raw")
        except subprocess.CalledProcessError:
            blob = None
        with self._lock:
            self._blobs[path] = blob
        return blob


_REPO_RE = re.compile(r"^(?:https://github\.com/)?(?P<repo>[\w.-]+/[\w.-]+?)(?:\.git)?/?$")


def resolve_source(target: str):
    """Local path if it is one, else an `owner/repo` read through the API.

    A path that exists on disk always wins, so a local directory that happens to
    look like `owner/repo` is never silently reviewed from the internet instead.
    """
    t = str(target).strip()
    if Path(t).expanduser().exists():
        return LocalGit(str(Path(t).expanduser()))
    m = _REPO_RE.match(t)
    if m and not t.startswith((".", "/", "~")):
        return GitHubHistory(m.group("repo"))
    raise RuntimeError(
        f"no such path {t!r}, and it is not an 'owner/repo' GitHub reference")


def reachability(source, diff: Diff, path: str, line: int) -> HeadStatus:
    """Is the code this finding points at still in HEAD?

    Checks the commit's own added lines rather than the line number, because a
    line number from an old commit means nothing in today's file.
    """
    dfile = diff.file(path)
    if dfile is None:
        # The model named a file this commit didn't touch — we can't place it.
        return HeadStatus.UNKNOWN
    blob = source.head_blob(path)
    if blob is None:
        return HeadStatus.ABSENT

    added = [t.strip() for _, t in
             ((n, t) for h in dfile.hunks for n, t in h.added) if t.strip()]
    if not added:
        return HeadStatus.UNKNOWN

    # Prefer the exact line the finding cites; fall back to whether any of the
    # commit's added code survived.
    cited = next((t.strip() for h in dfile.hunks for n, t in h.added
                  if n == line and t.strip()), None)
    if cited is not None:
        return HeadStatus.PRESENT if cited in blob else HeadStatus.ABSENT
    return HeadStatus.PRESENT if any(a in blob for a in added) else HeadStatus.ABSENT


def _attribute(f: Finding, commit: Commit, status: HeadStatus, diff: Diff) -> Finding:
    """Stamp provenance onto a finding: which commit introduced it, and whether
    the code is still live. Provenance goes in `evidence` so every renderer and
    the disclosure draft carry it without a schema change.

    The fingerprint is stamped here, against the commit's own diff — downstream
    only has one diff to offer, and it is not this one (RISK-07: fingerprints
    are content-based, so they must see the content they describe).
    """
    from .waiver import fingerprint

    provenance = (f"introduced in {commit.short} by {commit.author} "
                  f"on {commit.date[:10]} — {commit.subject}\n"
                  f"still in HEAD: {status}")
    f.id = f"history-{commit.short}-{f.id}"
    f.evidence = (provenance + ("\n" + f.evidence if f.evidence else ""))
    f.fingerprint = fingerprint(f, diff)
    return f


@dataclass
class Sweep:
    """What one history sweep found, and what it did not look at."""

    findings: list[Finding]
    commits_reviewed: int
    commits_total: int
    notes: list[str]
    skipped: list[str]
    by_status: dict[str, int]
    source_kind: str = "local"

    @property
    def live(self) -> list[Finding]:
        """Findings whose code is still present at HEAD — the actionable set."""
        return [f for f in self.findings
                if f"still in HEAD: {HeadStatus.PRESENT}" in f.evidence]


def run_history_sweep(
    target: str,
    provider,
    config: Config,
    *,
    selection: Selection | None = None,
    source=None,
    events=None,
) -> Sweep:
    """Review each commit in the selection, newest first, under the budget.

    `target` is a local repo path or an `owner/repo` GitHub reference; pass an
    explicit `source` to override that resolution.
    """
    from .events import HISTORY_STAGES, Emitter
    ev = events if isinstance(events, Emitter) else Emitter(events)

    sel = selection or Selection()
    src = source if source is not None else resolve_source(target)
    budget = history_budget(config)
    workers = audit_concurrency(config)

    where = "GitHub API (no clone)" if src.kind == "github" else "local clone"
    ev.stage_started("select")
    ev.operation(f"listing commits in {target} via {where}", stage="select")
    # One extra so we can tell "exactly at the cap" from "more than the cap".
    found = src.list_commits(budget + 1, sel)
    total = len(found)
    reviewed = found[:budget]          # the hard cap — never exceeded

    notes: list[str] = []
    skipped: list[str] = []
    if not reviewed:
        notes.append("history: no commits matched the selection")
        ev.stage_skipped("select", "no commits matched the selection")
        return Sweep([], 0, 0, notes, skipped, {}, src.kind)
    ev.stage_completed("select", f"{len(reviewed)} commit(s) selected "
                                 f"(budget {budget})")

    # Explicit: "llm" is also a review-pipeline stage, and STAGE_LABELS resolves
    # that id to the review wording.
    ev.stage_started("llm", dict(HISTORY_STAGES)["llm"])
    ev.operation(f"reviewing {len(reviewed)} commit(s) with model:{provider.name}, "
                 f"{workers} at a time (budget {budget})", stage="llm")

    lock = threading.Lock()
    done = 0

    def _review(commit: Commit) -> list[Finding]:
        nonlocal done
        ev.api_request(f"model:{provider.name} reviewing {commit.label()}",
                       stage="llm", commit=commit.short)
        try:
            diff = src.commit_diff(commit)
            if not diff.files:
                with lock:
                    done += 1
                return []
            raw = provider.review(diff, "", [])
        except Exception as exc:      # one bad commit doesn't sink the sweep
            with lock:
                done += 1
                skipped.append(f"history:{commit.short} (error: {exc})")
                ev.error(f"{commit.short}: {str(exc)[:80]}", stage="llm")
            return []

        out = []
        for f in raw:
            try:
                status = reachability(src, diff, f.file, f.line)
            except Exception:
                status = HeadStatus.UNKNOWN
            out.append(_attribute(f, commit, status, diff))

        with lock:
            done += 1
            live = sum(1 for f in out
                       if f"still in HEAD: {HeadStatus.PRESENT}" in f.evidence)
            ev.output(f"{commit.short} → {len(out)} finding(s), {live} still live "
                      f"[{done}/{len(reviewed)}]", stage="llm",
                      commit=commit.short, findings=len(out), live=live)
        return out

    if workers == 1 or len(reviewed) <= 1:
        per_commit = [_review(c) for c in reviewed]
    else:
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="cosmo-history") as pool:
            # .map keeps input order, so the result does not depend on which
            # commit review happened to finish first.
            per_commit = list(pool.map(_review, reviewed))

    findings = [f for batch in per_commit for f in batch]

    by_status: dict[str, int] = {}
    for f in findings:
        for s in HeadStatus:
            if f"still in HEAD: {s}" in f.evidence:
                by_status[str(s)] = by_status.get(str(s), 0) + 1
                break

    notes.append(f"history: reviewed {len(reviewed)} commit(s) with "
                 f"model:{provider.name} (budget {budget})")
    if total > budget:
        notes.append(f"history: more than {budget} commit(s) matched — the rest were "
                     f"NOT reviewed; raise history.max_commits to cover more")
    # Coverage honesty: a sweep reviews commits, so the tree-level static tools
    # never ran. Say so rather than let a clean sweep imply a clean tree.
    skipped.append("static (history mode reviews commit diffs, not the work tree)")
    if by_status.get(str(HeadStatus.ABSENT)):
        notes.append(f"history: {by_status[str(HeadStatus.ABSENT)]} finding(s) point at "
                     f"code no longer in HEAD — could be fixed, could be refactored; "
                     f"they are annotated, not waived")

    ev.stage_completed("llm", f"{len(findings)} finding(s) across "
                              f"{len(reviewed)} commit(s); "
                              f"{by_status.get(str(HeadStatus.PRESENT), 0)} still in HEAD")
    return Sweep(findings=findings, commits_reviewed=len(reviewed),
                 commits_total=total, notes=notes, skipped=skipped,
                 by_status=by_status, source_kind=src.kind)
