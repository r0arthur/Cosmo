"""Fetching the five scanners with no pip package (`cosmo tools --install`).

Hermetic: every network call goes through `bootstrap._get`, which is stubbed
to serve canned bytes keyed by URL — real release-JSON shapes and real small
archives built in-memory, not live GitHub. Two real bugs were caught building
this file against the *actual* releases before writing these tests, and both
get a regression test here:

* trufflehog's `/releases/latest` returned a release with `assets: []` —
  published, but its CI had not finished uploading binaries — which would
  otherwise have been reported as "no asset matches this platform", blaming
  the platform for a publishing race.
* find-sec-bugs' registry name (`find-sec-bugs`) and its actual binary name
  (`findsecbugs`) differ, and `uninstall()` looked for the wrong one — every
  other tool's symlink was removed, that one silently survived.
"""
import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from cosmo import bootstrap as bs


# --- building fake release data + archives -----------------------------------

def _release(tag="v1.2.3", assets=(), draft=False):
    return {
        "tag_name": tag,
        "draft": draft,
        "assets": [{"name": name, "browser_download_url": f"https://dl.example/{name}",
                   "size": size} for name, size in assets],
    }


def _tar_gz_bytes(member_name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(member_name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Router:
    """Maps URLs to canned bytes; stands in for `bootstrap._get`."""

    def __init__(self):
        self.routes: dict[str, bytes] = {}
        self.calls: list[str] = []

    def add(self, url: str, data: bytes) -> None:
        self.routes[url] = data

    def add_json(self, url: str, obj) -> None:
        self.add(url, json.dumps(obj).encode())

    def __call__(self, url, timeout=None):
        self.calls.append(url)
        if url not in self.routes:
            raise AssertionError(f"unexpected fetch: {url}")
        return self.routes[url]


@pytest.fixture
def router(monkeypatch):
    r = _Router()
    monkeypatch.setattr(bs, "_get", r)
    return r


def _releases_url(repo, latest=True):
    return (f"https://api.github.com/repos/{repo}/releases/latest" if latest
           else f"https://api.github.com/repos/{repo}/releases?per_page={bs._RELEASE_LOOKBACK}")


# --- platform resolution ------------------------------------------------------

@pytest.mark.parametrize("machine,expected", [
    ("x86_64", "amd64"), ("amd64", "amd64"),
    ("aarch64", "arm64"), ("arm64", "arm64"),
    ("riscv64", "riscv64"),          # unrecognised: passed through, not guessed
])
def test_platform_key_normalizes_architecture(monkeypatch, machine, expected):
    monkeypatch.setattr(bs.platform, "machine", lambda: machine)
    _, arch = bs._platform_key()
    assert arch == expected


# --- asset matching: verified against the real release asset lists ----------

# Captured from the real repositories before writing this file (see the
# module docstring in bootstrap.py) — not constructed from a template.
_GITLEAKS_ASSETS = [
    ("gitleaks_8.30.1_checksums.txt", 0),
    ("gitleaks_8.30.1_darwin_arm64.tar.gz", 0),
    ("gitleaks_8.30.1_darwin_x64.tar.gz", 0),
    ("gitleaks_8.30.1_linux_arm64.tar.gz", 0),
    ("gitleaks_8.30.1_linux_armv7.tar.gz", 0),
    ("gitleaks_8.30.1_linux_x64.tar.gz", 0),
    ("gitleaks_8.30.1_windows_x64.zip", 0),
]

_TRIVY_ASSETS = [
    ("trivy_0.74.0_checksums.txt", 0),
    ("trivy_0.74.0_Linux-64bit.tar.gz", 0),
    ("trivy_0.74.0_Linux-64bit.deb", 0),      # must NOT be picked over the tarball
    ("trivy_0.74.0_Linux-ARM64.tar.gz", 0),
    ("trivy_0.74.0_macOS-64bit.tar.gz", 0),
    ("trivy_0.74.0_macOS-ARM64.tar.gz", 0),
]

_TRUFFLEHOG_ASSETS = [
    ("trufflehog_3.97.2_checksums.txt", 0),
    ("trufflehog_3.97.2_linux_amd64.tar.gz", 0),
    ("trufflehog_3.97.2_linux_arm64.tar.gz", 0),
    ("trufflehog_3.97.2_darwin_amd64.tar.gz", 0),
    ("trufflehog_3.97.2_darwin_arm64.tar.gz", 0),
]

_OPENGREP_ASSETS = [
    ("opengrep_manylinux_x86", 0), ("opengrep_manylinux_x86.sig", 0),
    ("opengrep_manylinux_aarch64", 0),
    ("opengrep_osx_x86", 0), ("opengrep_osx_arm64", 0),
]


def _install(monkeypatch, machine, system):
    monkeypatch.setattr(bs.platform, "machine", lambda: machine)
    monkeypatch.setattr(bs.platform, "system", lambda: system)


def _stage(router, tool, repo, assets, tar_member, checksums_asset=None):
    """Stage a release with every `.tar.gz` asset a real download, each with
    its own checksum line — not just the first one, or a test asking for the
    darwin/arm64 asset would end up checking its bytes against the linux/amd64
    file's hash and fail regardless of whether the code under test is right.

    The checksum published by every real project here (gitleaks, trivy,
    trufflehog) is over the downloaded `.tar.gz` archive itself, not the
    extracted binary inside it — and `gzip` stamps each archive with its own
    mtime, so two archives built from identical inner content still differ
    byte-for-byte and need their own hash computed from the actual archive
    bytes, not derived once from the shared payload.
    """
    router.add_json(_releases_url(repo), _release(assets=assets))
    payload = f"content for {tool}".encode()
    sums = []
    for name, _ in assets:
        if name.endswith(".tar.gz") and tar_member:
            archive = _tar_gz_bytes(tar_member, payload)
            router.add(f"https://dl.example/{name}", archive)
            sums.append(f"{_sha256(archive)}  {name}")
    if checksums_asset:
        router.add(f"https://dl.example/{checksums_asset}",
                  ("\n".join(sums) + "\n").encode())
    return payload


@pytest.mark.parametrize("machine,system,expected_asset", [
    ("x86_64", "Linux", "gitleaks_8.30.1_linux_x64.tar.gz"),
    ("aarch64", "Linux", "gitleaks_8.30.1_linux_arm64.tar.gz"),
    ("arm64", "Darwin", "gitleaks_8.30.1_darwin_arm64.tar.gz"),
    ("x86_64", "Darwin", "gitleaks_8.30.1_darwin_x64.tar.gz"),
])
def test_gitleaks_picks_the_right_asset_per_platform(
        tmp_path, router, monkeypatch, machine, system, expected_asset):
    _install(monkeypatch, machine, system)
    _stage(router, "gitleaks", "gitleaks/gitleaks", _GITLEAKS_ASSETS, "gitleaks",
          checksums_asset="gitleaks_8.30.1_checksums.txt")
    r = bs.install_gitleaks(tmp_path / "bin", tmp_path / "tools")
    assert r.installed and r.verified is True
    assert (tmp_path / "bin" / "gitleaks").resolve() == (tmp_path / "tools" / "gitleaks" / "gitleaks")


def test_gitleaks_on_an_unsupported_os_is_declined_not_failed(tmp_path, router, monkeypatch):
    _install(monkeypatch, "x86_64", "Windows")
    r = bs.install_gitleaks(tmp_path / "bin", tmp_path / "tools")
    assert r.installed is False
    assert "unsupported OS" in r.note
    assert router.calls == []              # never even asked the network


def test_trivy_does_not_pick_the_deb_over_the_tarball(tmp_path, router, monkeypatch):
    """`Linux-64bit.deb` and `Linux-64bit.tar.gz` share a prefix; a substring
    match (rather than a full-pattern one) could pick the wrong asset."""
    _install(monkeypatch, "x86_64", "Linux")
    _stage(router, "trivy", "aquasecurity/trivy", _TRIVY_ASSETS, "trivy",
          checksums_asset="trivy_0.74.0_checksums.txt")
    r = bs.install_trivy(tmp_path / "bin", tmp_path / "tools")
    assert r.installed and r.verified is True
    assert any(c.endswith("Linux-64bit.tar.gz") for c in router.calls)
    assert not any(c.endswith("Linux-64bit.deb") for c in router.calls)


def test_trufflehog_darwin_arm64(tmp_path, router, monkeypatch):
    _install(monkeypatch, "arm64", "Darwin")
    _stage(router, "trufflehog", "trufflesecurity/trufflehog", _TRUFFLEHOG_ASSETS,
          "trufflehog", checksums_asset="trufflehog_3.97.2_checksums.txt")
    r = bs.install_trufflehog(tmp_path / "bin", tmp_path / "tools")
    assert r.installed and r.verified is True


# --- checksum verification: refuse on mismatch, not warn -------------------

def test_a_checksum_mismatch_refuses_to_install(tmp_path, router, monkeypatch):
    """A caller that logged the mismatch and installed anyway would not really
    have checked it."""
    _install(monkeypatch, "x86_64", "Linux")
    router.add_json(_releases_url("gitleaks/gitleaks"),
                    _release(assets=[("gitleaks_8.30.1_linux_x64.tar.gz", 0),
                                     ("gitleaks_8.30.1_checksums.txt", 0)]))
    router.add("https://dl.example/gitleaks_8.30.1_linux_x64.tar.gz",
              _tar_gz_bytes("gitleaks", b"real content"))
    # A checksums file naming the asset but with the wrong hash.
    router.add("https://dl.example/gitleaks_8.30.1_checksums.txt",
              b"0" * 64 + "  gitleaks_8.30.1_linux_x64.tar.gz\n".encode())

    with pytest.raises(bs.BootstrapError, match="checksum mismatch"):
        bs.install_gitleaks(tmp_path / "bin", tmp_path / "tools")
    assert not (tmp_path / "bin" / "gitleaks").exists()


def test_a_missing_checksums_asset_installs_but_says_unverified(tmp_path, router, monkeypatch):
    _install(monkeypatch, "x86_64", "Linux")
    router.add_json(_releases_url("gitleaks/gitleaks"),
                    _release(assets=[("gitleaks_8.30.1_linux_x64.tar.gz", 0)]))
    router.add("https://dl.example/gitleaks_8.30.1_linux_x64.tar.gz",
              _tar_gz_bytes("gitleaks", b"content"))
    r = bs.install_gitleaks(tmp_path / "bin", tmp_path / "tools")
    assert r.installed is True
    assert r.verified is False
    assert "no checksum published" in r.note


def test_a_truncated_download_is_rejected(tmp_path, router, monkeypatch):
    _install(monkeypatch, "x86_64", "Linux")
    router.add_json(_releases_url("gitleaks/gitleaks"),
                    _release(assets=[("gitleaks_8.30.1_linux_x64.tar.gz", 99999)]))
    router.add("https://dl.example/gitleaks_8.30.1_linux_x64.tar.gz",
              _tar_gz_bytes("gitleaks", b"short"))   # far smaller than declared
    with pytest.raises(bs.BootstrapError, match="truncated|interrupted"):
        bs.install_gitleaks(tmp_path / "bin", tmp_path / "tools")


# --- the "latest release has no assets yet" race, found against real data ---

def test_falls_back_when_the_latest_release_has_no_assets_yet(tmp_path, router, monkeypatch):
    """Observed live: trufflehog's /releases/latest returned a release
    published minutes earlier with assets: [] while the previous day's release
    had all nine. Must not be reported as 'no asset matches this platform' —
    that blames the platform for a publishing race."""
    _install(monkeypatch, "x86_64", "Linux")
    router.add_json(_releases_url("trufflesecurity/trufflehog"),
                    _release(tag="v3.97.3", assets=[]))
    router.add_json(_releases_url("trufflesecurity/trufflehog", latest=False), [
        _release(tag="v3.97.3", assets=[]),
        _release(tag="v3.97.2", assets=[(n, 0) for n, _ in _TRUFFLEHOG_ASSETS]),
    ])
    archive = _tar_gz_bytes("trufflehog", b"content")
    router.add("https://dl.example/trufflehog_3.97.2_linux_amd64.tar.gz", archive)
    router.add("https://dl.example/trufflehog_3.97.2_checksums.txt",
              f"{_sha256(archive)}  trufflehog_3.97.2_linux_amd64.tar.gz\n".encode())

    r = bs.install_trufflehog(tmp_path / "bin", tmp_path / "tools")
    assert r.installed is True
    assert "v3.97.3" in r.note and "v3.97.2" in r.note
    assert "no assets published yet" in r.note


def test_gives_up_after_the_lookback_window_finds_nothing(tmp_path, router, monkeypatch):
    _install(monkeypatch, "x86_64", "Linux")
    router.add_json(_releases_url("trufflesecurity/trufflehog"),
                    _release(tag="v3.97.3", assets=[]))
    router.add_json(_releases_url("trufflesecurity/trufflehog", latest=False),
                    [_release(tag=f"v3.97.{i}", assets=[]) for i in range(3, -1, -1)])
    with pytest.raises(bs.BootstrapError, match="no assets published"):
        bs.install_trufflehog(tmp_path / "bin", tmp_path / "tools")


def test_a_draft_release_is_not_used_as_a_fallback(tmp_path, router, monkeypatch):
    _install(monkeypatch, "x86_64", "Linux")
    router.add_json(_releases_url("trufflesecurity/trufflehog"),
                    _release(tag="v3.97.3", assets=[]))
    router.add_json(_releases_url("trufflesecurity/trufflehog", latest=False), [
        _release(tag="v3.97.3", assets=[]),
        _release(tag="v3.97.2-draft", assets=[("x", 0)], draft=True),
    ])
    with pytest.raises(bs.BootstrapError, match="no assets published"):
        bs.install_trufflehog(tmp_path / "bin", tmp_path / "tools")


# --- opengrep: raw binary, sigstore not plain sha256 -------------------------

@pytest.mark.parametrize("machine,system,expected", [
    ("x86_64", "Linux", "opengrep_manylinux_x86"),
    ("aarch64", "Linux", "opengrep_manylinux_aarch64"),
    ("x86_64", "Darwin", "opengrep_osx_x86"),
    ("arm64", "Darwin", "opengrep_osx_arm64"),
])
def test_opengrep_picks_the_right_raw_binary(tmp_path, router, monkeypatch,
                                             machine, system, expected):
    _install(monkeypatch, machine, system)
    router.add_json(_releases_url("opengrep/opengrep"), _release(assets=_OPENGREP_ASSETS))
    router.add(f"https://dl.example/{expected}", b"\x7fELF fake binary")
    r = bs.install_opengrep(tmp_path / "bin", tmp_path / "tools")
    assert r.installed is True
    assert r.verified is False
    assert "sigstore" in r.note
    assert (tmp_path / "tools" / "opengrep" / "opengrep").read_bytes() == b"\x7fELF fake binary"


def test_opengrep_binary_is_made_executable(tmp_path, router, monkeypatch):
    import stat
    _install(monkeypatch, "x86_64", "Linux")
    router.add_json(_releases_url("opengrep/opengrep"), _release(assets=_OPENGREP_ASSETS))
    router.add("https://dl.example/opengrep_manylinux_x86", b"binary")
    bs.install_opengrep(tmp_path / "bin", tmp_path / "tools")
    mode = (tmp_path / "tools" / "opengrep" / "opengrep").stat().st_mode
    assert mode & stat.S_IXUSR


# --- find-sec-bugs: CRLF fixup, and the link-name mismatch ------------------

def test_findsecbugs_strips_crlf_from_the_launcher(tmp_path, router, monkeypatch):
    """The distributed launcher has Windows line endings — `#!/bin/bash\\r` —
    which fails to find an interpreter on Linux/macOS. Verified against the
    real archive before writing this."""
    zip_bytes = _zip_bytes({
        "findsecbugs.sh": b"#!/bin/bash\r\necho hi\r\n",
        "lib/asm-9.7.1.jar": b"fake jar bytes",
    })
    router.add_json(_releases_url("find-sec-bugs/find-sec-bugs"),
                    _release(assets=[("findsecbugs-cli-1.14.0.zip", 0)]))
    router.add("https://dl.example/findsecbugs-cli-1.14.0.zip", zip_bytes)

    r = bs.install_findsecbugs(tmp_path / "bin", tmp_path / "tools")
    assert r.installed is True
    launcher = tmp_path / "tools" / "find-sec-bugs" / "findsecbugs.sh"
    assert b"\r" not in launcher.read_bytes()
    assert (tmp_path / "tools" / "find-sec-bugs" / "lib" / "asm-9.7.1.jar").exists()


def test_findsecbugs_symlink_uses_its_binary_name_not_its_registry_name(
        tmp_path, router, monkeypatch):
    """The registry key is `find-sec-bugs`; the binary `Tool.resolve()` looks
    for is `findsecbugs` (no hyphen). Installing under the wrong name would
    leave cosmo unable to find what was just installed."""
    router.add_json(_releases_url("find-sec-bugs/find-sec-bugs"),
                    _release(assets=[("findsecbugs-cli-1.14.0.zip", 0)]))
    router.add("https://dl.example/findsecbugs-cli-1.14.0.zip",
              _zip_bytes({"findsecbugs.sh": b"#!/bin/bash\necho hi\n"}))
    bs.install_findsecbugs(tmp_path / "bin", tmp_path / "tools")
    assert (tmp_path / "bin" / "findsecbugs").is_symlink()
    assert not (tmp_path / "bin" / "find-sec-bugs").exists()


# --- uninstall: symmetric with install, never touches a foreign copy --------

def test_uninstall_removes_what_install_put_down(tmp_path, router, monkeypatch):
    _install(monkeypatch, "x86_64", "Linux")
    _stage(router, "gitleaks", "gitleaks/gitleaks", _GITLEAKS_ASSETS, "gitleaks",
          checksums_asset="gitleaks_8.30.1_checksums.txt")
    bindir, toolsdir = tmp_path / "bin", tmp_path / "tools"
    bs.install_gitleaks(bindir, toolsdir)
    assert (bindir / "gitleaks").exists()

    removed = bs.uninstall("gitleaks", bindir=bindir, toolsdir=toolsdir)
    assert removed is True
    assert not (bindir / "gitleaks").exists()
    assert not (toolsdir / "gitleaks").exists()


def test_uninstall_uses_the_binary_name_for_find_sec_bugs(tmp_path, router, monkeypatch):
    """The bug this session actually hit: every other tool's link name equals
    its registry key, so `uninstall("find-sec-bugs", ...)` looked for a
    `bindir/find-sec-bugs` symlink that was never created — the real one, at
    `bindir/findsecbugs`, survived uninstall while every other tool's did not."""
    router.add_json(_releases_url("find-sec-bugs/find-sec-bugs"),
                    _release(assets=[("findsecbugs-cli-1.14.0.zip", 0)]))
    router.add("https://dl.example/findsecbugs-cli-1.14.0.zip",
              _zip_bytes({"findsecbugs.sh": b"#!/bin/bash\necho hi\n"}))
    bindir, toolsdir = tmp_path / "bin", tmp_path / "tools"
    bs.install_findsecbugs(bindir, toolsdir)
    assert (bindir / "findsecbugs").exists()

    removed = bs.uninstall("find-sec-bugs", bindir=bindir, toolsdir=toolsdir)
    assert removed is True
    assert not (bindir / "findsecbugs").exists()
    assert not (toolsdir / "find-sec-bugs").exists()


def test_uninstall_never_touches_a_symlink_installed_elsewhere(tmp_path):
    """The non-clobber discipline `install.sh` already applies to the
    pip-based tools: a copy the operator installed themselves, outside the
    managed tools dir, must survive."""
    other = tmp_path / "elsewhere" / "gitleaks"
    other.parent.mkdir(parents=True)
    other.write_text("not ours")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "gitleaks").symlink_to(other)

    removed = bs.uninstall("gitleaks", bindir=bindir, toolsdir=tmp_path / "tools")
    assert removed is False
    assert (bindir / "gitleaks").resolve() == other.resolve()


def test_uninstall_of_a_never_installed_tool_is_a_harmless_noop(tmp_path):
    assert bs.uninstall("trivy", bindir=tmp_path / "bin",
                        toolsdir=tmp_path / "tools") is False


# --- the registry-level dispatch --------------------------------------------

def test_install_dispatches_by_name(tmp_path, router, monkeypatch):
    _install(monkeypatch, "x86_64", "Linux")
    _stage(router, "gitleaks", "gitleaks/gitleaks", _GITLEAKS_ASSETS, "gitleaks",
          checksums_asset="gitleaks_8.30.1_checksums.txt")
    r = bs.install("gitleaks", bindir=tmp_path / "bin", toolsdir=tmp_path / "tools")
    assert r.tool == "gitleaks" and r.installed


def test_install_of_an_unknown_tool_names_what_it_does_know(tmp_path):
    with pytest.raises(bs.BootstrapError, match="gitleaks"):
        bs.install("nonesuch", bindir=tmp_path / "bin", toolsdir=tmp_path / "tools")


def test_semgrep_and_bandit_are_not_in_the_fetch_registry():
    """They come from pip, not a GitHub release — `cosmo tools --install
    semgrep` should be rejected, not silently do nothing."""
    assert "semgrep" not in bs.INSTALLERS
    assert "bandit" not in bs.INSTALLERS
    assert set(bs.INSTALLERS) == {"gitleaks", "trivy", "opengrep", "trufflehog",
                                  "find-sec-bugs"}


# --- a release with no releases at all --------------------------------------

def test_a_repo_with_no_releases_is_a_clear_error(tmp_path, router, monkeypatch):
    router.add(_releases_url("gitleaks/gitleaks"),
              json.dumps({"message": "Not Found"}).encode())
    with pytest.raises(bs.BootstrapError, match="no releases"):
        bs.install_gitleaks(tmp_path / "bin", tmp_path / "tools")


# --- LINK_NAME must agree with what the static registry actually resolves ---

def test_link_names_match_what_the_static_registry_resolves():
    """The bug this session hit: `INSTALLERS`' key (`find-sec-bugs`) and the
    symlink `install_findsecbugs` actually creates (`findsecbugs`) can drift
    apart from each other without anything noticing. Pin every fetchable
    tool's `LINK_NAME` against `Tool.binaries[0]` in the static registry, so a
    future tool added to one side without the other fails a test instead of
    leaving an uninstallable — or unfindable — symlink.
    """
    from cosmo.static import TOOLS_BY_NAME

    for name in bs.INSTALLERS:
        tool = TOOLS_BY_NAME.get(name)
        assert tool is not None, f"{name} is in bootstrap.INSTALLERS but not " \
                                 f"in the static.TOOLS registry"
        assert bs.LINK_NAME.get(name, name) == tool.binaries[0], (
            f"{name}: bootstrap installs the symlink as "
            f"{bs.LINK_NAME.get(name, name)!r}, but Tool.resolve() looks for "
            f"{tool.binaries[0]!r} first — cosmo would not find what it just "
            f"installed")
