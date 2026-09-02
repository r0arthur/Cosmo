"""Version and update checking (`cosmo tools`).

The property under test throughout: a version cosmo could not determine is never
reported as a version that is fine. Two real tools forced that distinction —
Debian's gitleaks prints "version is set by build process" instead of a number,
and the find-sec-bugs launcher has no version flag at all — and a failed network
check is the same class of not-knowing.

Hermetic: every probe and every fetch is stubbed, so no scanner and no network
is required.
"""
import subprocess
import urllib.error

import pytest

from cosmo.static import Tool
from cosmo.versions import (CHECK_FAILED, CURRENT, MISSING, OUTDATED,
                            UNCHECKED, UNKNOWN_VERSION, check_cosmo,
                            check_tools, compare, fetch_latest, parse_version,
                            probe)


def _tool(name="alpha", *, version_argv=("--version",), latest="pypi:alpha"):
    return Tool(name, (name,), lambda *a, **k: [], f"{name} coverage",
                f"install {name}", project=name, author="someone",
                license="MIT", homepage="https://example.invalid",
                version_argv=version_argv, latest=latest)


def _run(stdout="", stderr=""):
    def fake(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, stdout, stderr)
    return fake


@pytest.fixture
def installed(monkeypatch):
    """Pretend the tool is on PATH, and script its version output."""
    def _setup(stdout="", stderr="", present=True):
        import cosmo.versions as v
        monkeypatch.setattr(v.shutil, "which",
                            lambda b: f"/usr/bin/{b}" if present else None)
        monkeypatch.setattr(v.subprocess, "run", _run(stdout, stderr))
    return _setup


# --- parsing the shapes tools actually print --------------------------------

@pytest.mark.parametrize("text,expected", [
    ("1.176.0", "1.176.0"),                      # semgrep
    ("bandit 1.9.4\n  python version = 3.13.5", "1.9.4"),
    ("Version: 0.74.0\nVulnerability DB:\n  Version: 2", "0.74.0"),   # trivy
    ("trufflehog 3.97.2", "3.97.2"),
    ("v8.30.1", "8.30.1"),                       # a release tag
    ("version-1.14.0", "1.14.0"),                # find-sec-bugs' tag style
    ("1.29", "1.29"),
])
def test_parse_version_handles_every_shape_seen(text, expected):
    assert parse_version(text) == expected


@pytest.mark.parametrize("text", [
    "version is set by build process",            # Debian's gitleaks, verbatim
    "", None, "no numbers here",
])
def test_a_missing_version_parses_to_none_not_a_guess(text):
    assert parse_version(text) is None


def test_versions_compare_numerically_not_as_strings():
    """1.176.0 is newer than 1.9.4, which string ordering gets backwards."""
    assert compare("1.176.0", "1.9.4") == CURRENT
    assert compare("1.9.4", "1.176.0") == OUTDATED


def test_being_ahead_of_the_latest_release_is_not_a_problem():
    """A pre-release or a distro patch revision is not something to nag about."""
    assert compare("8.31.0", "8.30.1") == CURRENT
    assert compare("8.30.1", "8.30.1") == CURRENT


# --- probing ----------------------------------------------------------------

def test_a_tool_not_on_path_is_missing(installed):
    installed(present=False)
    s = probe(_tool())
    assert s.state == MISSING and not s.installed
    assert s.install == "install alpha"          # the row stays actionable


def test_an_installed_tool_reports_its_version(installed):
    installed(stdout="alpha 2.3.4")
    s = probe(_tool())
    assert s.installed and s.version == "2.3.4" and s.state == UNCHECKED


def test_a_tool_that_answers_on_stderr_is_still_read(installed):
    installed(stdout="", stderr="alpha 2.3.4")
    assert probe(_tool()).version == "2.3.4"


def test_an_installed_tool_with_no_version_string_is_unknown_not_current(installed):
    """Debian's gitleaks. Installed, running, and mute about its version —
    which is not the same as being fine."""
    installed(stdout="version is set by build process")
    s = probe(_tool())
    assert s.installed and s.version is None
    assert s.state == UNKNOWN_VERSION
    assert "no version string" in s.note


def test_a_tool_with_no_version_flag_is_not_even_asked(installed):
    """find-sec-bugs' launcher swallows -version and prints nothing."""
    installed(stdout="should not be read")
    s = probe(_tool(version_argv=()))
    assert s.state == UNKNOWN_VERSION
    assert "no version flag" in s.note
    assert s.version is None


def test_a_hanging_version_command_does_not_hang_the_check(monkeypatch):
    import cosmo.versions as v
    monkeypatch.setattr(v.shutil, "which", lambda b: f"/usr/bin/{b}")

    def boom(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 20)

    monkeypatch.setattr(v.subprocess, "run", boom)
    s = probe(_tool())
    assert s.state == UNKNOWN_VERSION and "failed" in s.note


# --- fetching the latest ----------------------------------------------------

def test_pypi_and_github_sources_are_both_understood(monkeypatch):
    import cosmo.versions as v
    monkeypatch.setattr(v, "_get_json", lambda url: (
        {"info": {"version": "1.176.0"}} if "pypi" in url
        else {"tag_name": "v8.30.1"}))
    assert fetch_latest("pypi:semgrep") == ("1.176.0", "")
    assert fetch_latest("github:gitleaks/gitleaks") == ("8.30.1", "")


def test_a_project_with_no_releases_is_not_an_error(monkeypatch):
    """cosmo's own repo is in exactly this state — 404 from releases/latest."""
    import cosmo.versions as v

    def notfound(url):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(v, "_get_json", notfound)
    version, note = fetch_latest("github:owner/repo")
    assert version is None
    assert "no releases" in note


def test_an_unconfigured_source_says_so(monkeypatch):
    version, note = fetch_latest("")
    assert version is None and "no update source" in note


# --- the states that must not be collapsed ----------------------------------

def test_offline_reports_a_failed_check_not_a_clean_bill(monkeypatch, installed):
    """The whole point. No network must never render as 'up to date'."""
    import cosmo.versions as v
    installed(stdout="alpha 2.3.4")
    monkeypatch.setattr(v, "_get_json",
                        lambda url: (_ for _ in ()).throw(OSError("no route to host")))
    s = check_tools(check_updates=True, tools=(_tool(),))[0]
    assert s.state == CHECK_FAILED
    assert s.state != CURRENT
    assert "update check failed" in s.note


def test_a_known_latest_against_an_unknown_installed_stays_unknown(monkeypatch, installed):
    """gitleaks: we learn 8.30.1 is current and still cannot say whether this
    copy is it. Reporting 'up to date' or 'outdated' would both be invented."""
    import cosmo.versions as v
    installed(stdout="version is set by build process")
    monkeypatch.setattr(v, "_get_json", lambda url: {"tag_name": "v8.30.1"})
    s = check_tools(check_updates=True,
                    tools=(_tool(latest="github:o/r"),))[0]
    assert s.state == UNKNOWN_VERSION
    assert s.latest == "8.30.1"
    assert "cannot compare" in s.note


def test_an_outdated_tool_is_flagged(monkeypatch, installed):
    import cosmo.versions as v
    installed(stdout="alpha 1.0.0")
    monkeypatch.setattr(v, "_get_json", lambda url: {"info": {"version": "2.0.0"}})
    s = check_tools(check_updates=True, tools=(_tool(),))[0]
    assert s.state == OUTDATED and s.needs_attention


def test_no_network_call_happens_without_check_updates(monkeypatch, installed):
    """`cosmo tools` is offline by default; a review run must never phone home."""
    import cosmo.versions as v
    installed(stdout="alpha 1.0.0")

    def forbidden(url):
        raise AssertionError(f"unexpected network call to {url}")

    monkeypatch.setattr(v, "_get_json", forbidden)
    statuses = check_tools(check_updates=False, tools=(_tool(),))
    assert statuses[0].state == UNCHECKED
    assert check_cosmo(check_updates=False).state == UNCHECKED


def test_registry_order_survives_the_parallel_fetch(monkeypatch, installed):
    import cosmo.versions as v
    installed(stdout="x 1.0.0")
    monkeypatch.setattr(v, "_get_json", lambda url: {"info": {"version": "1.0.0"}})
    tools = tuple(_tool(n) for n in ("a", "b", "c", "d"))
    assert [s.name for s in check_tools(True, tools)] == ["a", "b", "c", "d"]


# --- cosmo's own version ----------------------------------------------------

def test_cosmo_reports_its_own_version():
    from cosmo import __version__
    assert check_cosmo().version == __version__


def test_cosmo_update_check_survives_a_repo_with_no_releases(monkeypatch):
    import cosmo.versions as v

    def notfound(url):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(v, "_get_json", notfound)
    s = check_cosmo(check_updates=True)
    assert s.state == CHECK_FAILED and "no releases" in s.note
