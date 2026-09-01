"""Commit-history sweep — reviewing a repo's past for vulnerabilities.

Hermetic: builds real throwaway git repos and drives them with a fake provider.
No network, no model.

The two properties under test are the ones the feature rests on: the commit
budget is structural (concurrency can never widen it), and reachability is
three-valued and never auto-waives — "the line is gone" is not proof of a fix.
"""
import subprocess

import pytest

from cosmo.config import Config, load_config
from cosmo.findings import Finding
from cosmo.history import (
    Commit,
    GitHubHistory,
    HeadStatus,
    LocalGit,
    Selection,
    clamp_requested,
    history_budget,
    reachability,
    resolve_source,
    run_history_sweep,
)
from cosmo.severity import Severity


# --- a real, tiny git repo --------------------------------------------------

def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def _repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "dev@example.test")
    _git(r, "config", "user.name", "Test Dev")
    return r


def _commit(repo, path, text, message):
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    _git(repo, "add", path)
    _git(repo, "commit", "-q", "-m", message)


class _Provider:
    """Flags the first added line of the first file in each commit."""

    name = "fake"
    vendor = "local"
    exports_source = False
    roles = {"primary_review"}

    def __init__(self, severity=Severity.HIGH):
        self.severity = severity
        self.calls = 0

    def available(self):
        return True

    def review(self, diff, context, findings_so_far):
        self.calls += 1
        if not diff.files:
            return []
        f = diff.files[0]
        added = [(n, t) for h in f.hunks for n, t in h.added if t.strip()]
        if not added:
            return []
        line, _ = added[0]
        return [Finding(id="1", title="Unsafe input", severity=self.severity,
                        source="model:fake", file=f.path, line=line)]


def _cfg(max_commits=50, concurrency=1):
    return Config(data={"threshold": "info",
                        "history": {"max_commits": max_commits},
                        "llm_audit": {"concurrency": concurrency}})


# --- listing and diffing ----------------------------------------------------

def test_lists_commits_newest_first(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    _commit(r, "b.py", "y = 2\n", "second")
    commits = LocalGit(str(r)).list_commits(10, Selection())
    assert [c.subject for c in commits] == ["second", "first"]
    assert commits[0].author == "Test Dev"
    assert len(commits[0].sha) == 40


def test_commit_diff_carries_the_added_lines(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "password = 'hunter2'\n", "add secret")
    src = LocalGit(str(r))
    diff = src.commit_diff(src.list_commits(1, Selection())[0])
    assert diff.file("a.py") is not None
    assert "password = 'hunter2'" in diff.file("a.py").added_line_texts()


def test_selection_filters_by_author_and_path(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "touch a")
    _commit(r, "b.py", "y = 2\n", "touch b")
    src = LocalGit(str(r))
    assert len(src.list_commits(10, Selection(author="Test Dev"))) == 2
    only_b = src.list_commits(10, Selection(paths=["b.py"]))
    assert [c.subject for c in only_b] == ["touch b"]


# --- reachability: the signal that separates live from already-fixed --------

def test_reachability_present_when_the_line_survives(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "token = 'abc'\n", "introduce")
    _commit(r, "b.py", "unrelated = 1\n", "later, elsewhere")
    src = LocalGit(str(r))
    target = [c for c in src.list_commits(10, Selection()) if c.subject == "introduce"][0]
    diff = src.commit_diff(target)
    assert reachability(src, diff, "a.py", 1) is HeadStatus.PRESENT


def test_reachability_absent_when_the_line_was_removed(tmp_path):
    """The vulnerable line was later deleted — a fix, or a refactor. Either way
    it is no longer reachable, and the sweep must say so."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "token = 'abc'\n", "introduce")
    _commit(r, "a.py", "token = load_secret()\n", "remediate")
    src = LocalGit(str(r))
    target = [c for c in src.list_commits(10, Selection()) if c.subject == "introduce"][0]
    diff = src.commit_diff(target)
    assert reachability(src, diff, "a.py", 1) is HeadStatus.ABSENT


def test_reachability_absent_when_the_file_is_gone(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "token = 'abc'\n", "introduce")
    _git(r, "rm", "-q", "a.py")
    _git(r, "commit", "-q", "-m", "delete it")
    src = LocalGit(str(r))
    target = [c for c in src.list_commits(10, Selection()) if c.subject == "introduce"][0]
    diff = src.commit_diff(target)
    assert reachability(src, diff, "a.py", 1) is HeadStatus.ABSENT


def test_reachability_unknown_when_the_file_is_not_in_the_commit(tmp_path):
    """Never guess: a file this commit didn't touch cannot be placed, and
    'unknown' must not be read as either safe or vulnerable."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "introduce")
    src = LocalGit(str(r))
    diff = src.commit_diff(src.list_commits(1, Selection())[0])
    assert reachability(src, diff, "nowhere.py", 1) is HeadStatus.UNKNOWN


# --- the budget is structural ----------------------------------------------

def test_sweep_never_exceeds_the_commit_budget(tmp_path):
    r = _repo(tmp_path)
    for i in range(10):
        _commit(r, f"f{i}.py", f"x = {i}\n", f"commit {i}")
    p = _Provider()
    sweep = run_history_sweep(str(r), p, _cfg(max_commits=3))
    assert p.calls == 3
    assert sweep.commits_reviewed == 3


def test_concurrency_cannot_widen_the_budget(tmp_path):
    """The list is truncated before dispatch, so workers change rate, not count."""
    r = _repo(tmp_path)
    for i in range(12):
        _commit(r, f"f{i}.py", f"x = {i}\n", f"commit {i}")
    p = _Provider()
    run_history_sweep(str(r), p, _cfg(max_commits=4, concurrency=8))
    assert p.calls == 4


def test_commits_past_the_budget_are_reported_not_dropped(tmp_path):
    r = _repo(tmp_path)
    for i in range(6):
        _commit(r, f"f{i}.py", f"x = {i}\n", f"commit {i}")
    sweep = run_history_sweep(str(r), _Provider(), _cfg(max_commits=2))
    assert any("NOT reviewed" in n for n in sweep.notes)


def test_max_commits_flag_can_only_lower_the_ceiling(tmp_path):
    """A CLI flag is held to the same tier rule as a repo's cosmo.yaml — it
    cannot buy a bigger model bill than the operator allowed."""
    cfg = Config(data={"history": {"max_commits": 25}})
    assert clamp_requested(cfg, None) == 25        # unset → the ceiling
    assert clamp_requested(cfg, 10) == 10          # lower → honoured
    assert clamp_requested(cfg, 9999) == 25        # higher → clamped back
    assert clamp_requested(cfg, -5) == 0           # nonsense → floored, not negative


def test_default_budget_and_repo_clamp(tmp_path):
    assert history_budget(Config(data={})) == 200
    (tmp_path / "cosmo.yaml").write_text("history:\n  max_commits: 10\n")
    assert history_budget(load_config(str(tmp_path))) == 10
    (tmp_path / "cosmo.yaml").write_text("history:\n  max_commits: 99999\n")
    cfg = load_config(str(tmp_path))          # operator ceiling 200
    assert history_budget(cfg) == 200
    assert any("max_commits" in w for w in cfg.warnings)


# --- attribution ------------------------------------------------------------

def test_findings_carry_the_commit_that_introduced_them(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "token = 'abc'\n", "add the token")
    sweep = run_history_sweep(str(r), _Provider(), _cfg())
    f = sweep.findings[0]
    assert "add the token" in f.evidence
    assert "Test Dev" in f.evidence
    assert f.id.startswith("history-")
    assert f.fingerprint                      # stamped against its own commit


def test_live_set_is_only_what_is_still_in_head(tmp_path):
    """Reachability is per *commit*, not per file.

    `a.py` is flagged twice — once for the line the remediation removed (absent)
    and once for the line that replaced it (present). Judging by filename would
    conflate the two.
    """
    r = _repo(tmp_path)
    _commit(r, "a.py", "token = 'abc'\n", "introduce")
    _commit(r, "b.py", "other = 'xyz'\n", "second")
    _commit(r, "a.py", "token = load()\n", "remediate")
    sweep = run_history_sweep(str(r), _Provider(), _cfg())

    def _for(subject):
        # Match the subject field, not the whole blob: "introduced in <sha>" in
        # the provenance prefix contains "introduce".
        return next(f for f in sweep.findings if f"— {subject}\n" in f.evidence)

    assert "still in HEAD: absent" in _for("introduce").evidence
    assert "still in HEAD: present" in _for("second").evidence
    assert "still in HEAD: present" in _for("remediate").evidence
    assert _for("second") in sweep.live
    assert _for("introduce") not in sweep.live
    assert sweep.by_status.get("absent") == 1


def test_absent_findings_are_annotated_not_waived(tmp_path):
    """RISK-04 discipline: code being gone is not proof it was ever a fix."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "token = 'abc'\n", "introduce")
    _commit(r, "a.py", "token = load()\n", "remediate")
    sweep = run_history_sweep(str(r), _Provider(), _cfg())
    gone = [f for f in sweep.findings if "still in HEAD: absent" in f.evidence]
    assert gone
    assert all(not f.waived for f in gone)


def test_sweep_reports_that_static_did_not_run(tmp_path):
    """A clean sweep must not imply a clean work tree."""
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "one")
    sweep = run_history_sweep(str(r), _Provider(), _cfg())
    assert any("static" in s for s in sweep.skipped)


def test_empty_selection_is_not_an_error(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "one")
    sweep = run_history_sweep(str(r), _Provider(), _cfg(),
                              selection=Selection(author="nobody@nowhere"))
    assert sweep.findings == [] and sweep.commits_reviewed == 0


# --- where the history comes from ------------------------------------------

def test_local_path_wins_over_a_github_looking_name(tmp_path, monkeypatch):
    """A directory named like 'owner/repo' must never be silently swapped for a
    repository on the internet."""
    nested = tmp_path / "owner" / "repo"
    nested.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    assert isinstance(resolve_source("owner/repo"), LocalGit)


def test_owner_repo_resolves_to_the_github_source(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/gh")
    src = resolve_source("torvalds/linux")
    assert isinstance(src, GitHubHistory) and src.repo == "torvalds/linux"


def test_github_source_needs_the_gh_cli(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda n: None)
    with pytest.raises(RuntimeError, match="gh"):
        GitHubHistory("torvalds/linux")


def test_unknown_target_is_rejected(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/gh")
    with pytest.raises(RuntimeError, match="owner/repo"):
        resolve_source("./definitely/not/here")


def test_github_source_parses_the_commit_listing(monkeypatch):
    """The API shape, without the network: merges dropped, fields mapped."""
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/gh")
    src = GitHubHistory("acme/app")
    payload = """[
      {"sha": "aaaaaaaaaaaaaaaa", "parents": [{"sha": "p1"}],
       "commit": {"message": "fix: bounds check\\n\\nbody",
                  "author": {"name": "Dev A", "email": "a@x.test",
                             "date": "2024-05-01T10:00:00Z"}}},
      {"sha": "bbbbbbbbbbbbbbbb", "parents": [{"sha": "p1"}, {"sha": "p2"}],
       "commit": {"message": "Merge branch 'x'",
                  "author": {"name": "Dev B", "email": "b@x.test",
                             "date": "2024-05-02T10:00:00Z"}}}
    ]"""
    monkeypatch.setattr(src, "_api", lambda *a, **k: payload)
    commits = src.list_commits(10, Selection())
    assert [c.subject for c in commits] == ["fix: bounds check"]   # merge dropped
    assert commits[0].author == "Dev A" and commits[0].short == "aaaaaaa"


def test_github_head_blob_is_cached(monkeypatch):
    """Reachability asks about the same files repeatedly; each miss is a round trip."""
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/gh")
    src = GitHubHistory("acme/app")
    calls = []
    monkeypatch.setattr(src, "_api", lambda *a, **k: calls.append(a) or "content")
    assert src.head_blob("a.py") == "content"
    assert src.head_blob("a.py") == "content"
    assert len(calls) == 1
