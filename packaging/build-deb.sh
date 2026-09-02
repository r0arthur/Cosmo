#!/usr/bin/env bash
# Build a self-contained cosmo .deb — no fpm, no dh-python, just dpkg-deb.
#
#   ./packaging/build-deb.sh            # -> dist/cosmo_<version>_all.deb
#   OUT=/tmp ./packaging/build-deb.sh   # choose the output dir
#
# Layout the package installs:
#   /opt/cosmo/lib/     cosmo + its Python deps (flat, version-independent)
#   /usr/bin/cosmo      launcher: runs the system python3 against /opt/cosmo/lib
#
# The launcher calls `python3 -m cosmo`, so nothing depends on a hardcoded venv
# path — the package works whatever Python 3.10+ the target ships, and PyYAML's
# optional C extension degrades to pure Python if the ABI differs. The static
# scanners (semgrep, opengrep, gitleaks, trufflehog, bandit, trivy,
# find-sec-bugs) and the `claude` CLI are companions the user installs
# separately; cosmo names each missing one under `skipped:` rather than
# quietly scanning less. Only the two that exist as Debian packages are listed
# in Suggests — semgrep, opengrep, trufflehog, trivy and find-sec-bugs are
# upstream binaries with no Debian package, so naming them there would point
# apt at nothing. None is a Depends: a hard dependency would make cosmo
# uninstallable rather than degraded, which is the opposite of the contract.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$REPO/dist}"

VERSION="$(python3 - "$REPO/src/cosmo/__init__.py" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
print(re.search(r'__version__\s*=\s*"([^"]+)"', src).group(1))
PY
)"
ARCH="all"                      # pure Python — no compiled cosmo code
PKG="cosmo_${VERSION}_${ARCH}"
STAGE="$(mktemp -d)"
ROOT="$STAGE/$PKG"
trap 'rm -rf "$STAGE"' EXIT

echo "building $PKG.deb"
echo "  version: $VERSION"
echo "  stage:   $ROOT"

# --- payload: cosmo + deps into a flat, importable dir -----------------------
LIB="$ROOT/opt/cosmo/lib"
mkdir -p "$LIB" "$ROOT/usr/bin" "$ROOT/DEBIAN" "$OUT"
python3 -m pip install --quiet --target "$LIB" "$REPO"
# Drop bytecode caches and pip's generated console-script dir — not needed
# (we ship our own /usr/bin/cosmo launcher) and they only bloat the package.
find "$LIB" -name '__pycache__' -type d -prune -exec rm -rf {} +
rm -rf "$LIB/bin"

# --- launcher ----------------------------------------------------------------
# `-s` drops the user site-dir so the vendored lib is authoritative; PYTHONPATH
# puts it on the path. (No `-E`: that would also discard PYTHONPATH.)
cat > "$ROOT/usr/bin/cosmo" <<'SH'
#!/bin/sh
# cosmo launcher (installed by the .deb). Runs the packaged code with the
# system Python against the vendored library dir under /opt/cosmo.
exec env PYTHONPATH=/opt/cosmo/lib /usr/bin/python3 -s -m cosmo "$@"
SH
chmod 0755 "$ROOT/usr/bin/cosmo"

# --- control metadata --------------------------------------------------------
INSTALLED_KB="$(du -sk "$ROOT/opt" "$ROOT/usr" | awk '{s+=$1} END {print s}')"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: cosmo
Version: $VERSION
Section: devel
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.10)
Recommends: git
Suggests: gitleaks, bandit
Installed-Size: $INSTALLED_KB
Maintainer: r0arthur <karthur0822@gmail.com>
Homepage: https://github.com/r0arthur/Cosmo
Description: Security review and zero-day discovery tool
 cosmo runs a guarded static + AI security review over a diff, a GitHub PR, a
 whole project, or a repository's commit history, and ships as both a CLI and a
 Claude Code plugin.
 .
 The AI review is model-pluggable: Claude by default, with Codex, DeepSeek, and a
 local Llama endpoint also supported, so source that must not leave your network
 can be pinned to a local model.
 .
 The static scan needs no account. For the AI review, install the 'claude' CLI
 (uses your Claude Code subscription) and run: cosmo review . --model claude-cli.
 .
 The static stage drives seven scanners if they are on PATH — semgrep, opengrep,
 gitleaks, trufflehog, bandit, trivy and find-sec-bugs. None is required: each
 one that is missing is named in the report's skipped list, so a narrower scan
 never reads as a clean one.
EOF

# --- build -------------------------------------------------------------------
# fakeroot so the packaged files are owned root:root without needing real root.
fakeroot dpkg-deb --build --root-owner-group "$ROOT" "$OUT/$PKG.deb" >/dev/null
echo
echo "built: $OUT/$PKG.deb"
echo "install:  sudo dpkg -i $OUT/$PKG.deb"
echo "remove:   sudo dpkg -r cosmo"
