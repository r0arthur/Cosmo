"""Fetching and installing the static scanners cosmo drives.

Five of the seven (`gitleaks`, `trivy`, `opengrep`, `trufflehog`,
`find-sec-bugs`) are standalone binaries with no PyPI package, so `pip` cannot
put them on `PATH` the way it does `semgrep`/`bandit`. This module is the one
place that fetches them — invoked automatically by `scripts/install.sh` for a
local install, and available anywhere else as `cosmo tools --install`, so a
`.deb` install or a manual `pip install -e` gets the same path rather than a
second implementation.

Two things this module is careful about, because it is a *security* tool
downloading binaries onto the machine that runs it:

**Verified where verification exists.** gitleaks, trivy and trufflehog each
publish a `..._checksums.txt` of the release; every asset is checked against it
and a mismatch is a hard failure, not a warning — an installer that logs a
checksum failure and continues anyway did not really check it. opengrep signs
its release with sigstore/cosign rather than plain sha256, and find-sec-bugs
publishes no checksum at all; both are downloaded over HTTPS only, and that gap
is reported to the caller rather than presented as equivalent to a verified
install.

**Never guessed.** Asset names are read off the release's real `assets` array
and matched by pattern, not constructed from a template — a constructed
filename that happens to be wrong fails as a 404, a matched one simply finds
nothing for an unsupported platform. Every filename pattern below was checked
against a real release before being written down; a project changing its
naming convention makes installation of *that tool* fail closed (nothing
selected, reported as unsupported) rather than silently fetching whatever the
old pattern happens to still match.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import __version__

FETCH_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 180


class BootstrapError(RuntimeError):
    """Installation could not complete. The message is shown to the operator."""


@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    size: int


@dataclass(frozen=True)
class InstallResult:
    tool: str
    installed: bool
    path: Optional[str] = None
    verified: Optional[bool] = None   # None = no checksum published to check against
    note: str = ""


def _platform_key() -> tuple[str, str]:
    """(`Linux`|`Darwin`|..., normalized arch) — `amd64`/`arm64`, the two this
    module actually resolves assets for."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine
    return platform.system(), arch


def _get(url: str, timeout: int = FETCH_TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"cosmo/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.URLError as exc:
        raise BootstrapError(f"could not reach {url}: {exc}") from exc


# How many recent releases to look back through for one whose assets have
# actually finished uploading. Observed live against trufflehog: GitHub marks a
# release non-draft (so `/releases/latest` returns it) before its CI has
# finished attaching binaries — `/releases/latest` gave a release published
# minutes earlier with `assets: []`, while the one from the day before had all
# nine. Reporting that as "no asset matches this platform" would blame the
# platform for what is actually a publishing race.
_RELEASE_LOOKBACK = 5


def _latest_release(repo: str) -> dict:
    try:
        data = json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest"))
    except json.JSONDecodeError as exc:
        raise BootstrapError(f"{repo}: release metadata was not valid JSON") from exc
    if "assets" not in data:
        raise BootstrapError(f"{repo}: no releases published")
    if data["assets"]:
        return data

    # The newest release has no assets yet. Walk back through recent releases
    # for one that does, rather than fail on what is very likely a transient
    # window between "release created" and "CI finished uploading binaries".
    stale_tag = data.get("tag_name", "?")
    try:
        history = json.loads(
            _get(f"https://api.github.com/repos/{repo}/releases?per_page={_RELEASE_LOOKBACK}"))
    except json.JSONDecodeError as exc:
        raise BootstrapError(f"{repo}: release history was not valid JSON") from exc
    for candidate in history:
        if candidate.get("assets") and not candidate.get("draft"):
            candidate["_cosmo_fallback_from"] = stale_tag
            return candidate

    raise BootstrapError(
        f"{repo}: the latest release ({stale_tag}) has no assets published yet, "
        f"and none of the last {_RELEASE_LOOKBACK} releases does either — this "
        f"looks like more than a brief publishing gap. Try again shortly, or "
        f"install {repo.split('/')[-1]} manually.")


def _pick(assets: list[dict], pattern: str) -> Optional[Asset]:
    rx = re.compile(pattern)
    for a in assets:
        if rx.fullmatch(a["name"]):
            return Asset(a["name"], a["browser_download_url"], a.get("size", 0))
    return None


def _download(asset: Asset, dest: Path) -> None:
    dest.write_bytes(_get(asset.url, timeout=DOWNLOAD_TIMEOUT))
    if asset.size and dest.stat().st_size != asset.size:
        raise BootstrapError(
            f"{asset.name}: downloaded {dest.stat().st_size} bytes, "
            f"release declared {asset.size} — truncated or interrupted transfer")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify(path: Path, asset_name: str, checksums_text: str) -> bool:
    """Check `path` against a `sha256sum`-format checksums file.

    A mismatch raises rather than returning False: a caller that logged the
    failure and installed the binary anyway would not really have checked it.
    """
    wanted = None
    for line in checksums_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == asset_name:
            wanted = parts[0].lower()
            break
    if wanted is None:
        raise BootstrapError(f"{asset_name}: not listed in the published checksums file")
    got = _sha256(path)
    if got != wanted:
        raise BootstrapError(
            f"{asset_name}: checksum mismatch — expected {wanted}, got {got}. "
            f"Refusing to install a binary that does not match what the "
            f"publisher signed.")
    return True


def _extract_tar_member(archive: Path, member: str, dest: Path) -> None:
    with tarfile.open(archive) as tf:
        try:
            src = tf.extractfile(member)
        except KeyError:
            src = None
        if src is None:
            raise BootstrapError(f"{archive.name}: no {member!r} inside the archive")
        dest.write_bytes(src.read())


def _extract_zip_tree(archive: Path, dest_dir: Path) -> None:
    """Unpack a zip, normalizing CRLF line endings in any shell script.

    find-sec-bugs' distribution ships `findsecbugs.sh` with Windows line
    endings — `#!/bin/bash\\r` — which fails to find an interpreter on Linux
    and macOS. Verified against the real archive before writing this, not
    assumed.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            target = dest_dir / info.filename
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info.filename)
            if info.filename.endswith(".sh") and b"\r\n" in data:
                data = data.replace(b"\r\n", b"\n")
            target.write_bytes(data)


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _symlink(target: Path, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)


# --- per-tool installers -----------------------------------------------------
#
# Each returns an InstallResult and raises BootstrapError on a hard failure
# (network, checksum mismatch, corrupt archive). "Not supported on this
# platform" is not an error — it is a normal InstallResult(installed=False).

def _fallback_note(release: dict) -> str:
    stale = release.get("_cosmo_fallback_from")
    if not stale:
        return ""
    return (f"latest release ({stale}) has no assets published yet — "
           f"installed {release.get('tag_name', 'the previous release')} instead")


def _install_archive_binary(
    *, tool: str, repo: str, bindir: Path, toolsdir: Path,
    asset_pattern: str, member: str, checksums_pattern: Optional[str],
) -> InstallResult:
    release = _latest_release(repo)
    fallback = _fallback_note(release)
    assets = release["assets"]
    asset = _pick(assets, asset_pattern)
    if asset is None:
        sysname, arch = _platform_key()
        return InstallResult(tool, False,
                             note=f"no {tool} release asset matches this platform "
                                  f"({sysname}/{arch}) — install it manually")

    with tempfile.TemporaryDirectory(prefix=f"cosmo-{tool}-") as tmp:
        tmp = Path(tmp)
        archive = tmp / asset.name
        _download(asset, archive)

        verified: Optional[bool] = None
        if checksums_pattern is not None:
            sums_asset = _pick(assets, checksums_pattern)
            if sums_asset is None:
                verified = False
            else:
                sums = _get(sums_asset.url).decode("utf-8", "replace")
                verified = _verify(archive, asset.name, sums)

        dest_dir = toolsdir / tool
        dest_dir.mkdir(parents=True, exist_ok=True)
        binary = dest_dir / tool
        _extract_tar_member(archive, member, binary)
        _make_executable(binary)

    _symlink(binary, bindir / tool)
    parts = []
    if not verified:
        parts.append("no checksum published for this asset — downloaded over "
                     "HTTPS, not hash-verified")
    if fallback:
        parts.append(fallback)
    return InstallResult(tool, True, path=str(binary), verified=verified,
                         note="; ".join(parts))


def install_gitleaks(bindir: Path, toolsdir: Path) -> InstallResult:
    sysname, arch = _platform_key()
    sys_word = {"Linux": "linux", "Darwin": "darwin"}.get(sysname)
    if sys_word is None:
        return InstallResult("gitleaks", False, note=f"unsupported OS: {sysname}")
    arch_word = "arm64" if arch == "arm64" else "x64"
    return _install_archive_binary(
        tool="gitleaks", repo="gitleaks/gitleaks", bindir=bindir, toolsdir=toolsdir,
        asset_pattern=rf"gitleaks_[\d.]+_{sys_word}_{arch_word}\.tar\.gz",
        member="gitleaks",
        checksums_pattern=r"gitleaks_[\d.]+_checksums\.txt")


def install_trufflehog(bindir: Path, toolsdir: Path) -> InstallResult:
    sysname, arch = _platform_key()
    sys_word = {"Linux": "linux", "Darwin": "darwin"}.get(sysname)
    if sys_word is None:
        return InstallResult("trufflehog", False, note=f"unsupported OS: {sysname}")
    arch_word = "arm64" if arch == "arm64" else "amd64"
    return _install_archive_binary(
        tool="trufflehog", repo="trufflesecurity/trufflehog",
        bindir=bindir, toolsdir=toolsdir,
        asset_pattern=rf"trufflehog_[\d.]+_{sys_word}_{arch_word}\.tar\.gz",
        member="trufflehog",
        checksums_pattern=r"trufflehog_[\d.]+_checksums\.txt")


def install_trivy(bindir: Path, toolsdir: Path) -> InstallResult:
    sysname, arch = _platform_key()
    sys_word = {"Linux": "Linux", "Darwin": "macOS"}.get(sysname)
    if sys_word is None:
        return InstallResult("trivy", False, note=f"unsupported OS: {sysname}")
    arch_word = "ARM64" if arch == "arm64" else "64bit"
    return _install_archive_binary(
        tool="trivy", repo="aquasecurity/trivy", bindir=bindir, toolsdir=toolsdir,
        asset_pattern=rf"trivy_[\d.]+_{sys_word}-{arch_word}\.tar\.gz",
        member="trivy",
        checksums_pattern=r"trivy_[\d.]+_checksums\.txt")


def install_opengrep(bindir: Path, toolsdir: Path) -> InstallResult:
    """Raw executable, no archive — and no plain-sha256 checksum published.

    opengrep signs releases with sigstore (a `.sig`/`.cert` pair per asset),
    which needs the `cosign` CLI or a from-scratch Rekor-log verification to
    check — out of scope here. The download is HTTPS-only, and that is
    reported rather than glossed over as a verified install.
    """
    sysname, arch = _platform_key()
    family = {"Linux": "manylinux", "Darwin": "osx"}.get(sysname)
    if family is None:
        return InstallResult("opengrep", False, note=f"unsupported OS: {sysname}")
    arch_word = ("aarch64" if arch == "arm64" and family == "manylinux" else
                "arm64" if arch == "arm64" else "x86")
    asset_name = f"opengrep_{family}_{arch_word}"

    release = _latest_release("opengrep/opengrep")
    fallback = _fallback_note(release)
    asset = next((Asset(a["name"], a["browser_download_url"], a.get("size", 0))
                 for a in release["assets"] if a["name"] == asset_name), None)
    if asset is None:
        return InstallResult("opengrep", False,
                             note=f"no opengrep release asset named {asset_name!r} "
                                  f"— install it manually")

    dest_dir = toolsdir / "opengrep"
    dest_dir.mkdir(parents=True, exist_ok=True)
    binary = dest_dir / "opengrep"
    with tempfile.TemporaryDirectory(prefix="cosmo-opengrep-") as tmp:
        raw = Path(tmp) / asset_name
        _download(asset, raw)
        shutil.move(str(raw), binary)
    _make_executable(binary)
    _symlink(binary, bindir / "opengrep")
    note = ("opengrep publishes sigstore signatures, not a plain checksum "
           "file — downloaded over HTTPS, not hash-verified")
    if fallback:
        note += f"; {fallback}"
    return InstallResult("opengrep", True, path=str(binary), verified=False, note=note)


def install_findsecbugs(bindir: Path, toolsdir: Path) -> InstallResult:
    """The one multi-file install: a `lib/` of jars plus a launcher script.

    The launcher resolves its own directory through any symlink chain
    (`while [ -h "$SOURCE" ]; do ...`), so a plain symlink into `bindir` works
    the same way the pip-installed tools' symlinks do.
    """
    release = _latest_release("find-sec-bugs/find-sec-bugs")
    fallback = _fallback_note(release)
    asset = _pick(release["assets"], r"findsecbugs-cli-[\d.]+\.zip")
    if asset is None:
        return InstallResult("find-sec-bugs", False,
                             note="no findsecbugs-cli zip in the latest release")

    dest_dir = toolsdir / "find-sec-bugs"
    with tempfile.TemporaryDirectory(prefix="cosmo-fsb-") as tmp:
        archive = Path(tmp) / asset.name
        _download(asset, archive)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        _extract_zip_tree(archive, dest_dir)

    launcher = dest_dir / "findsecbugs.sh"
    _make_executable(launcher)
    _symlink(launcher, bindir / "findsecbugs")
    note = ("find-sec-bugs publishes no checksum file — downloaded over HTTPS, "
           "not hash-verified. Needs a JVM on PATH to actually run (not "
           "installed here).")
    if fallback:
        note += f" {fallback}."
    return InstallResult("find-sec-bugs", True, path=str(launcher), verified=False,
                         note=note)


INSTALLERS: dict[str, Callable[[Path, Path], InstallResult]] = {
    "gitleaks": install_gitleaks,
    "trivy": install_trivy,
    "opengrep": install_opengrep,
    "trufflehog": install_trufflehog,
    "find-sec-bugs": install_findsecbugs,
}

# The name `install()` is asked for (matching `Tool.name` in the static
# registry, and so `INSTALLERS`' keys) versus the name the symlink actually
# gets in `bindir` (matching `Tool.binaries[0]`, what `shutil.which` looks
# for). Every installer but find-sec-bugs's uses the same string for both, so
# this table only needs the one exception — but it is what `uninstall` and
# `describe`-style callers must consult instead of assuming the two match.
LINK_NAME: dict[str, str] = {"find-sec-bugs": "findsecbugs"}


def install(tool: str, *, bindir: Path, toolsdir: Path) -> InstallResult:
    fn = INSTALLERS.get(tool)
    if fn is None:
        raise BootstrapError(
            f"cosmo does not know how to fetch {tool!r} — it has no pip "
            f"package, so it is not one of {sorted(INSTALLERS)}")
    return fn(bindir, toolsdir)


def uninstall(tool: str, *, bindir: Path, toolsdir: Path) -> bool:
    """Remove what `install()` put down for `tool`. True if anything was removed.

    Only ever touches `bindir`/`toolsdir` — the managed locations — mirroring
    the non-clobber discipline `install.sh` already applies to the pip-based
    tools: a copy the operator installed themselves, elsewhere on `PATH`, is
    never touched.
    """
    removed = False
    link = bindir / LINK_NAME.get(tool, tool)
    if link.is_symlink():
        target = os.path.realpath(link)
        if str(Path(toolsdir).resolve()) in target:
            link.unlink()
            removed = True
    tree = toolsdir / tool
    if tree.exists():
        shutil.rmtree(tree)
        removed = True
    return removed
