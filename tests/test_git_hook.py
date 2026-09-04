"""Git hook trigger adapter — step 13."""
import os
import subprocess

import pytest

from cosmo.config import Config
from cosmo.diff import resolve_diff
from cosmo.findings import Finding
from cosmo.severity import Severity
from cosmo.triggers import install_hook, render_hook_output, run_git_hook


def _git(cwd, *args):
    subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True, text=True)


def _repo(tmp_path):
    d = str(tmp_path)
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@t.co")
    _git(d, "config", "user.name", "t")
    (tmp_path / "seed.py").write_text("x = 1\n")
    _git(d, "add", "seed.py")
    _git(d, "commit", "-qm", "init")
    return d


class _Provider:
    name = "claude"

    def __init__(self, sev):
        self.sev = sev

    def available(self):
        return True

    def review(self, diff, context, findings_so_far):
        return [Finding(id="m0", title="Command injection", severity=self.sev,
                        source="model:claude", file="app.py", line=1,
                        category="CWE-78", security_sensitive=True)]


# --- staged diff resolution -------------------------------------------------

def test_resolves_staged_diff_only(tmp_path):
    d = _repo(tmp_path)
    (tmp_path / "unstaged.py").write_text("print('nope')\n")   # not staged
    (tmp_path / "app.py").write_text("os.system(x)\n")
    _git(d, "add", "app.py")                                   # staged

    diff = resolve_diff(f"staged:{d}")
    paths = [f.path for f in diff.files]
    assert any(p.endswith("app.py") for p in paths)
    assert not any(p.endswith("unstaged.py") for p in paths)  # unstaged excluded


# --- blocking semantics -----------------------------------------------------

def test_non_blocking_never_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    d = _repo(tmp_path)
    (tmp_path / "app.py").write_text("os.system(x)\n")
    _git(d, "add", "app.py")

    # A critical finding, but blocking is off → exit 0 (commit proceeds).
    import cosmo.engine as engine
    monkeypatch.setattr(engine, "resolve_primary", lambda cfg, cli_model=None: (_Provider(Severity.CRITICAL), []))
    report, code = run_git_hook(Config(data={}), staged_path=d, blocking_override=False)
    assert code == 0


def test_blocking_fails_on_critical(tmp_path, monkeypatch):
    d = _repo(tmp_path)
    (tmp_path / "app.py").write_text("os.system(x)\n")
    _git(d, "add", "app.py")

    # Inject the provider through the engine resolution path.
    import cosmo.engine as engine
    monkeypatch.setattr(engine, "resolve_primary", lambda cfg, cli_model=None: (_Provider(Severity.CRITICAL), []))
    report, code = run_git_hook(Config(data={}), staged_path=d, blocking_override=True)
    assert code == 1
    assert any(f.severity is Severity.CRITICAL for f in report.findings)


def test_hook_threshold_defaults_to_critical(tmp_path, monkeypatch):
    d = _repo(tmp_path)
    (tmp_path / "app.py").write_text("weak = 1\n")
    _git(d, "add", "app.py")
    # A HIGH finding is below the hook's critical floor → filtered out → exit 0.
    import cosmo.engine as engine
    monkeypatch.setattr(engine, "resolve_primary", lambda cfg, cli_model=None: (_Provider(Severity.HIGH), []))
    report, code = run_git_hook(Config(data={}), staged_path=d, blocking_override=True)
    assert code == 0
    assert all(f.severity is not Severity.HIGH or f.waived for f in report.findings)


# --- output + install -------------------------------------------------------

def test_render_hook_output_blocked_message():
    f = Finding(id="1", title="RCE", severity=Severity.CRITICAL, source="model:claude",
                file="a.py", line=2, category="CWE-78")
    out = render_hook_output(type("R", (), {"findings": [f], "skipped_stages": []})(), exit_code=1)
    assert "CRITICAL" in out and "commit blocked" in out


def test_install_hook_writes_executable(tmp_path):
    _repo(tmp_path)
    path = install_hook(str(tmp_path), hook_type="pre-commit", blocking=True)
    assert os.path.exists(path) and os.access(path, os.X_OK)
    body = open(path).read()
    assert "cosmo hook" in body and "--blocking" in body


def test_install_hook_rejects_non_repo(tmp_path):
    with pytest.raises(RuntimeError):
        install_hook(str(tmp_path / "not-a-repo"))
