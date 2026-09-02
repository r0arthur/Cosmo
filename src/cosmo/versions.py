"""Version and update checking for cosmo and the scanners it drives.

Two things this file is careful about.

**It never guesses.** Every state a tool can be in is distinct and reported as
itself: installed with a known version, installed but *unable to say* which
version, not installed, or checked-and-the-check-failed. Collapsing "I could not
determine this" into "up to date" would be the same defect the whole tool exists
to avoid — an unchecked result wearing a clean one's clothes. Two real cases
forced this: Debian's gitleaks prints `version is set by build process` instead
of a version, and the find-sec-bugs launcher script exposes no version flag at
all.

**It does not touch the network unless asked.** `cosmo tools` is offline: it runs
each scanner's own version command locally and stops there. Only
`--check-updates` reaches out, and only to release metadata for the projects
listed in the registry — PyPI and the GitHub releases API, read-only, carrying
nothing about the repo under review. That is the same trusted-egress category as
cosmo's existing GitHub reads, and deliberately not something a review run does
behind your back.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

from . import __version__
from .static import TOOLS, Tool

# A version command should answer instantly; a scanner that hangs on `--version`
# must not hang `cosmo tools`.
PROBE_TIMEOUT = 20
FETCH_TIMEOUT = 10

# The first dotted number in the output. Deliberately loose, because every tool
# frames it differently: `1.176.0`, `bandit 1.9.4`, `Version: 0.74.0`,
# `trufflehog 3.97.2`. Release tags need the same treatment — `v0.74.0` and
# `version-1.14.0` are both real.
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")

# --- states -----------------------------------------------------------------

CURRENT = "current"          # installed, and matches the latest we could find
OUTDATED = "outdated"        # installed, and older than the latest
UNKNOWN_VERSION = "unknown"  # installed, but it will not say which version
MISSING = "missing"          # not on PATH
UNCHECKED = "unchecked"      # installed; no update check was requested
CHECK_FAILED = "check-failed"  # an update check ran and could not get an answer


@dataclass
class Status:
    """One row of `cosmo tools`."""

    name: str
    installed: bool
    path: Optional[str] = None
    version: Optional[str] = None
    latest: Optional[str] = None
    state: str = UNCHECKED
    note: str = ""
    covers: str = ""
    install: str = ""

    @property
    def needs_attention(self) -> bool:
        return self.state in (OUTDATED, MISSING)


def parse_version(text: str | None) -> Optional[str]:
    """The first dotted number in a version string, or None if there isn't one.

    None is a real answer, not a failure to handle: `gitleaks version` on a
    Debian build prints "version is set by build process".
    """
    if not text:
        return None
    m = _VERSION.search(str(text))
    if not m:
        return None
    parts = [p for p in m.groups() if p is not None]
    return ".".join(parts)


def _key(version: str) -> tuple[int, ...]:
    """Sortable form. Compared as integers, so 1.176.0 outranks 1.9.4 — which
    it does not do as a string."""
    return tuple(int(p) for p in version.split("."))


def compare(installed: str, latest: str) -> str:
    """CURRENT if the installed version is at least the latest we found.

    Ahead-of-latest counts as current: a pre-release build or a distro patch
    revision is not something to nag about.
    """
    try:
        return CURRENT if _key(installed) >= _key(latest) else OUTDATED
    except (TypeError, ValueError):
        return UNKNOWN_VERSION


# --- probing what is installed ----------------------------------------------

def probe(tool: Tool) -> Status:
    """Ask one installed tool for its version. Never raises."""
    base = Status(name=tool.name, installed=False, covers=tool.covers,
                  install=tool.install, state=MISSING)
    binary = tool.resolve()
    if binary is None:
        return base

    base.installed = True
    base.path = shutil.which(binary)
    base.state = UNCHECKED
    if not tool.version_argv:
        base.state = UNKNOWN_VERSION
        base.note = "this tool's launcher exposes no version flag"
        return base

    try:
        proc = subprocess.run([binary, *tool.version_argv], capture_output=True,
                              text=True, timeout=PROBE_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        base.state = UNKNOWN_VERSION
        base.note = f"version command failed: {exc}"
        return base

    # Some tools answer on stderr; take whichever stream has a version in it.
    version = parse_version(proc.stdout) or parse_version(proc.stderr)
    if version is None:
        base.state = UNKNOWN_VERSION
        base.note = "this build reports no version string"
        return base
    base.version = version
    return base


# --- asking upstream what the latest is -------------------------------------

def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        # GitHub rejects requests with no User-Agent.
        "User-Agent": f"cosmo/{__version__}",
    })
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return json.loads(r.read())


def fetch_latest(spec: str) -> tuple[Optional[str], str]:
    """Look up the newest published version. Returns (version, note).

    A note with no version is a failed check, and the caller reports it as such
    rather than as "up to date".
    """
    kind, _, ref = str(spec or "").partition(":")
    try:
        if kind == "pypi":
            return parse_version(_get_json(
                f"https://pypi.org/pypi/{ref}/json")["info"]["version"]), ""
        if kind == "github":
            tag = _get_json(
                f"https://api.github.com/repos/{ref}/releases/latest")["tag_name"]
            return parse_version(tag), ""
        return None, f"no update source configured for {spec!r}"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # Not an error worth alarming about: the project simply has no
            # published release. cosmo's own repo is in exactly this state.
            return None, "upstream publishes no releases"
        return None, f"update check failed: HTTP {exc.code}"
    except Exception as exc:                      # offline, DNS, TLS, bad JSON
        return None, f"update check failed: {exc}"


def _resolve_latest(status: Status, tool: Tool) -> Status:
    latest, note = fetch_latest(tool.latest)
    if latest is None:
        if status.state != UNKNOWN_VERSION:
            status.state = CHECK_FAILED
        status.note = "; ".join(x for x in (status.note, note) if x)
        return status
    status.latest = latest
    if status.version:
        status.state = compare(status.version, latest)
    else:
        # Installed but mute about its version: we know what is current and
        # still cannot say whether this copy is it. Say exactly that.
        status.state = UNKNOWN_VERSION
        status.note = "; ".join(x for x in (
            status.note, f"cannot compare against {latest}") if x)
    return status


def check_tools(check_updates: bool = False,
                tools: tuple[Tool, ...] = TOOLS) -> list[Status]:
    """Status for every registered scanner, in registry order."""
    statuses = [probe(t) for t in tools]
    if not check_updates:
        return statuses

    # Independent HTTP reads; run them together so the check takes as long as
    # the slowest one rather than the sum. `map` keeps registry order.
    with ThreadPoolExecutor(max_workers=min(8, len(tools) or 1),
                            thread_name_prefix="cosmo-version") as pool:
        return list(pool.map(lambda pair: _resolve_latest(*pair),
                             zip(statuses, tools)))


def check_cosmo(check_updates: bool = False,
                source: str = "github:r0arthur/Cosmo") -> Status:
    """cosmo's own version, and whether a newer one is published."""
    status = Status(name="cosmo", installed=True, version=__version__,
                    state=UNCHECKED, covers="this tool")
    if not check_updates:
        return status
    latest, note = fetch_latest(source)
    if latest is None:
        status.state = CHECK_FAILED
        status.note = note
        return status
    status.latest = latest
    status.state = compare(__version__, latest)
    return status
