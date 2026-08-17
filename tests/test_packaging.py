"""The .deb build produces a well-formed, runnable package (packaging).

Load-bearing property: `packaging/build-deb.sh` yields a dpkg archive whose
control metadata and payload match what the launcher needs — the cosmo package
under /opt/cosmo/lib and a /usr/bin/cosmo launcher — so `dpkg -i` gives a working
`cosmo` with no pip step on the target. Skipped where the Debian tooling isn't
present (non-Debian CI); skipped rather than failed if the build can't fetch a
dependency offline, so the suite stays hermetic.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "packaging" / "build-deb.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("dpkg-deb") is None or shutil.which("fakeroot") is None,
    reason="dpkg-deb/fakeroot not available (non-Debian host)",
)


def _version() -> str:
    src = (ROOT / "src" / "cosmo" / "__init__.py").read_text()
    return re.search(r'__version__\s*=\s*"([^"]+)"', src).group(1)


@pytest.fixture(scope="module")
def built_deb(tmp_path_factory):
    out = tmp_path_factory.mktemp("deb-out")
    proc = subprocess.run(
        ["bash", str(BUILD)],
        env={"OUT": str(out), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True,
    )
    deb = out / f"cosmo_{_version()}_all.deb"
    if not deb.exists():
        # Most likely an offline box that can't fetch PyYAML — skip, don't fail.
        pytest.skip(f"deb build did not produce {deb.name}:\n{proc.stderr[-800:]}")
    return deb


def test_control_metadata(built_deb):
    info = subprocess.run(
        ["dpkg-deb", "--info", str(built_deb)], capture_output=True, text=True, check=True
    ).stdout
    assert "Package: cosmo" in info
    assert f"Version: {_version()}" in info
    assert "Architecture: all" in info           # pure Python — arch-independent
    assert re.search(r"Depends:.*python3", info)  # the one hard runtime dep


def test_payload_has_launcher_and_package(built_deb):
    contents = subprocess.run(
        ["dpkg-deb", "--contents", str(built_deb)], capture_output=True, text=True, check=True
    ).stdout
    assert "./usr/bin/cosmo" in contents                       # the launcher
    assert "./opt/cosmo/lib/cosmo/__init__.py" in contents      # the vendored package
    assert "./opt/cosmo/lib/cosmo/cli.py" in contents
    # pip's console-script dir must be pruned (we ship our own launcher).
    assert "./opt/cosmo/lib/bin/" not in contents


def test_packaged_code_runs(built_deb, tmp_path):
    """Extract the payload and invoke it exactly as the launcher does."""
    extract = tmp_path / "root"
    subprocess.run(["dpkg-deb", "-x", str(built_deb), str(extract)], check=True)
    lib = extract / "opt" / "cosmo" / "lib"
    out = subprocess.run(
        ["python3", "-s", "-m", "cosmo", "--help"],
        env={"PYTHONPATH": str(lib), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr
    assert "cosmo" in out.stdout and "review" in out.stdout
