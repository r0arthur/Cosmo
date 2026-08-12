"""Diff resolver (architecture §3, build step 3).

Normalizes local `git diff` and GitHub PR diffs into one internal shape
(file, hunk, added lines + line numbers, surrounding context) before anything
downstream touches it. The provider split (local vs GitHub) is kept behind
`resolve_diff` so GitLab/Bitbucket can be added later without touching callers.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_PR_RE = re.compile(r"^(?:https://github\.com/(?P<repo>[^/]+/[^/]+)/pull/(?P<n1>\d+)"
                    r"|(?P<repo2>[^/\s#]+/[^/\s#]+)#(?P<n2>\d+))$")


@dataclass
class Hunk:
    header: str
    added: list[tuple[int, str]] = field(default_factory=list)  # (new_line_no, text)
    context: list[str] = field(default_factory=list)            # all lines, for fingerprint context


@dataclass
class DiffFile:
    path: str
    hunks: list[Hunk] = field(default_factory=list)

    def added_line_texts(self) -> list[str]:
        return [t for h in self.hunks for _, t in h.added]


@dataclass
class Diff:
    source: str                 # "local" | "github"
    target: str
    files: list[DiffFile] = field(default_factory=list)
    raw: str = ""

    def file(self, path: str) -> DiffFile | None:
        return next((f for f in self.files if f.path == path), None)


def parse_unified_diff(raw: str) -> list[DiffFile]:
    """Minimal unified-diff parser. Tracks new-file line numbers for added lines."""
    files: list[DiffFile] = []
    cur: DiffFile | None = None
    hunk: Hunk | None = None
    new_ln = 0
    for line in raw.splitlines():
        if line.startswith("diff --git") or line.startswith("+++ "):
            if line.startswith("+++ "):
                path = line[4:].strip()
                path = path[2:] if path.startswith("b/") else path
                if path == "/dev/null":
                    continue
                cur = DiffFile(path=path)
                files.append(cur)
                hunk = None
            continue
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            new_ln = int(m.group(1)) if m else 0
            hunk = Hunk(header=line)
            if cur is not None:
                cur.hunks.append(hunk)
            continue
        if hunk is None or cur is None:
            continue
        if line.startswith("+"):
            hunk.added.append((new_ln, line[1:]))
            hunk.context.append(line[1:])
            new_ln += 1
        elif line.startswith("-"):
            hunk.context.append(line[1:])
        else:
            hunk.context.append(line[1:] if line.startswith(" ") else line)
            new_ln += 1
    return files


def _run(cmd: list[str], cwd: str | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=True).stdout


def _resolve_github(repo: str, number: str) -> Diff:
    """Read a PR diff via the `gh` CLI (§3; same access pattern as code-review plugin).

    Reading is unrestricted; posting is gated separately (§12 / output.gate).
    """
    if not shutil.which("gh"):
        raise RuntimeError("GitHub target requested but `gh` CLI is not installed")
    raw = _run(["gh", "pr", "diff", number, "-R", repo])
    return Diff(source="github", target=f"{repo}#{number}", files=parse_unified_diff(raw), raw=raw)


def _resolve_local(path: Path) -> Diff:
    if (path / ".git").exists() or (path.is_dir() and shutil.which("git")
                                    and _is_git_repo(path)):
        # Working-tree changes vs HEAD. A staged-only mode (--staged) is a v2 flag.
        raw = _run(["git", "-C", str(path), "diff", "HEAD"])
        if not raw.strip():
            raw = _run(["git", "-C", str(path), "diff"])
        return Diff(source="local", target=str(path), files=parse_unified_diff(raw), raw=raw)
    # Not a repo: treat file(s) as fully-added so the pipeline still has something to chew on.
    return _whole_tree_as_added(path)


def _is_git_repo(path: Path) -> bool:
    try:
        _run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"])
        return True
    except Exception:
        return False


def _whole_tree_as_added(path: Path) -> Diff:
    files: list[DiffFile] = []
    paths = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
    for p in paths:
        try:
            text = p.read_text(errors="replace")
        except Exception:
            continue
        hunk = Hunk(header="@@ whole-file @@")
        for i, ln in enumerate(text.splitlines(), start=1):
            hunk.added.append((i, ln))
            hunk.context.append(ln)
        files.append(DiffFile(path=str(p), hunks=[hunk]))
    return Diff(source="local", target=str(path), files=files, raw="")


def resolve_diff(target: str) -> Diff:
    """Entry point: dispatch a target string to the right resolver."""
    m = _PR_RE.match(target.strip())
    if m:
        repo = m.group("repo") or m.group("repo2")
        number = m.group("n1") or m.group("n2")
        return _resolve_github(repo, number)
    return _resolve_local(Path(target).expanduser())
