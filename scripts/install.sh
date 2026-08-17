#!/usr/bin/env bash
# One-command local install for cosmo (no root, no .deb).
#
# Creates an isolated virtualenv, installs cosmo (+ the static scanner) into it,
# and drops a `cosmo` launcher on your PATH. Re-running it upgrades in place.
#
#   curl-free:  ./scripts/install.sh
#   options:    PREFIX=~/.local  VENV=~/.local/share/cosmo/venv  ./scripts/install.sh
#               NO_SEMGREP=1 ./scripts/install.sh    # skip the static scanner
#
# Everything is confined to the venv + one symlink; `./scripts/install.sh --uninstall`
# removes both.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"
VENV="${VENV:-$PREFIX/share/cosmo/venv}"
LINK="$BINDIR/cosmo"

if [[ "${1:-}" == "--uninstall" ]]; then
    rm -f "$LINK"
    # Only remove the semgrep symlink if it points into our venv (don't clobber
    # a semgrep the user installed themselves).
    if [[ -L "$BINDIR/semgrep" && "$(readlink "$BINDIR/semgrep")" == "$VENV/"* ]]; then
        rm -f "$BINDIR/semgrep"
    fi
    rm -rf "$VENV"
    echo "removed $LINK and $VENV"
    exit 0
fi

echo "cosmo install"
echo "  repo:  $REPO"
echo "  venv:  $VENV"
echo "  bin:   $LINK"

python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
# cosmo itself + the Anthropic SDK (for the API-key provider; the claude-cli
# provider needs no SDK). The static scanner is separate and optional.
"$VENV/bin/pip" install --quiet -e "$REPO"

if [[ -z "${NO_SEMGREP:-}" ]]; then
    echo "  + installing semgrep (static scanner) — set NO_SEMGREP=1 to skip"
    "$VENV/bin/pip" install --quiet semgrep || \
        echo "  ! semgrep install failed; the static stage will show as skipped:"
fi

mkdir -p "$BINDIR"
ln -sf "$VENV/bin/cosmo" "$LINK"
# cosmo finds semgrep via PATH, but it lives in the venv's bin (not on PATH).
# Symlink it next to cosmo so the static stage actually runs, not `skipped:`.
if [[ -x "$VENV/bin/semgrep" ]]; then
    ln -sf "$VENV/bin/semgrep" "$BINDIR/semgrep"
fi

echo
echo "installed: $("$LINK" --version 2>/dev/null || echo cosmo)"
case ":$PATH:" in
    *":$BINDIR:"*) echo "run: cosmo --help" ;;
    *) echo "NOTE: $BINDIR is not on your PATH. Add it:"
       echo "      export PATH=\"$BINDIR:\$PATH\"" ;;
esac
echo "AI review: install & log in to the 'claude' CLI, then: cosmo review . --model claude-cli"
