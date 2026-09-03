#!/usr/bin/env bash
# One-command local install for cosmo (no root, no .deb).
#
# Creates an isolated virtualenv, installs cosmo + all seven static scanners,
# and drops a `cosmo` launcher on your PATH. Re-running it upgrades in place.
#
#   curl-free:  ./scripts/install.sh
#   options:    PREFIX=~/.local  VENV=~/.local/share/cosmo/venv  ./scripts/install.sh
#               NO_SEMGREP=1     ./scripts/install.sh    # skip semgrep (pip)
#               NO_BANDIT=1      ./scripts/install.sh    # skip bandit (pip)
#               NO_GITLEAKS=1    ./scripts/install.sh    # skip gitleaks (GitHub release)
#               NO_TRIVY=1       ./scripts/install.sh    # skip trivy (GitHub release)
#               NO_OPENGREP=1    ./scripts/install.sh    # skip opengrep (GitHub release)
#               NO_TRUFFLEHOG=1  ./scripts/install.sh    # skip trufflehog (GitHub release)
#               NO_FINDSECBUGS=1 ./scripts/install.sh    # skip find-sec-bugs (GitHub release)
#               NO_SCANNERS=1    ./scripts/install.sh    # skip all seven — cosmo alone
#
# The two pip-installable scanners (semgrep, bandit) go into the venv; the
# other five have no pip package, so `cosmo tools --install` fetches their
# GitHub release binaries instead — verified against the release's published
# checksum where one exists (gitleaks, trivy, trufflehog), downloaded over
# HTTPS only where it does not (opengrep, find-sec-bugs; both note this rather
# than reporting an unverified download as equivalent to a verified one). A
# tool this machine's OS/arch has no release asset for is skipped, not failed.
#
# Everything is confined to the venv, a tools dir, and their symlinks;
# `./scripts/install.sh --uninstall` removes all of it.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"
VENV="${VENV:-$PREFIX/share/cosmo/venv}"
TOOLSDIR="$PREFIX/share/cosmo/tools"
LINK="$BINDIR/cosmo"

if [[ "${1:-}" == "--uninstall" ]]; then
    # Run before the venv is removed — it needs a working `cosmo` to know what
    # it put down. Best-effort: a venv already gone (a prior partial uninstall)
    # must not stop the rest of the cleanup.
    if [[ -x "$VENV/bin/python3" ]]; then
        "$VENV/bin/python3" - "$BINDIR" "$TOOLSDIR" <<'PY' || true
import sys
from pathlib import Path
from cosmo import bootstrap
bindir, toolsdir = Path(sys.argv[1]), Path(sys.argv[2])
for name in bootstrap.INSTALLERS:
    bootstrap.uninstall(name, bindir=bindir, toolsdir=toolsdir)
PY
    fi
    rm -f "$LINK"
    # Only remove a scanner symlink if it points into our venv — don't clobber
    # one the user installed themselves.
    for tool in semgrep bandit; do
        if [[ -L "$BINDIR/$tool" && "$(readlink "$BINDIR/$tool")" == "$VENV/"* ]]; then
            rm -f "$BINDIR/$tool"
        fi
    done
    rm -rf "$VENV" "$TOOLSDIR"
    echo "removed $LINK, $VENV, and $TOOLSDIR"
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
        echo "  ! semgrep install failed; that scanner will show as skipped:"
fi

if [[ -z "${NO_BANDIT:-}" ]]; then
    echo "  + installing bandit (Python checks) — set NO_BANDIT=1 to skip"
    "$VENV/bin/pip" install --quiet bandit || \
        echo "  ! bandit install failed; that scanner will show as skipped:"
fi

mkdir -p "$BINDIR"
ln -sf "$VENV/bin/cosmo" "$LINK"
# cosmo finds a scanner via PATH, but these live in the venv's bin (not on
# PATH). Symlink them next to cosmo so they actually run, rather than each
# reporting itself as `skipped:`.
for tool in semgrep bandit; do
    if [[ -x "$VENV/bin/$tool" ]]; then
        ln -sf "$VENV/bin/$tool" "$BINDIR/$tool"
    fi
done

# The five scanners with no pip package: fetch them from their GitHub
# releases in one `cosmo tools --install` call (it already continues past a
# single tool's failure on its own, so one call is enough — and it means the
# "not on PATH" note below prints once, not five times). NO_<TOOL>=1 drops
# just that tool from the list; NO_SCANNERS=1 skips the whole step.
# (No associative arrays: macOS still ships bash 3.2, which lacks them.)
if [[ -z "${NO_SCANNERS:-}" ]]; then
    fetch=()
    for pair in "gitleaks:NO_GITLEAKS" "trivy:NO_TRIVY" "opengrep:NO_OPENGREP" \
                "trufflehog:NO_TRUFFLEHOG" "find-sec-bugs:NO_FINDSECBUGS"; do
        tool="${pair%%:*}"
        skip_var="${pair##*:}"
        if [[ -n "${!skip_var:-}" ]]; then
            echo "  - skipping $tool (\$$skip_var set)"
        else
            fetch+=("$tool")
        fi
    done
    if [[ ${#fetch[@]} -gt 0 ]]; then
        echo "  + fetching ${fetch[*]} (GitHub releases) — NO_<TOOL>=1 to skip one, NO_SCANNERS=1 for all"
        "$VENV/bin/python3" -m cosmo.cli tools --install "${fetch[@]}" \
            --bindir "$BINDIR" --toolsdir "$TOOLSDIR" || \
            echo "  ! one or more scanner fetches failed; those will show as skipped:"
    fi
else
    echo "  - NO_SCANNERS set: skipping gitleaks, trivy, opengrep, trufflehog, find-sec-bugs"
fi

echo
echo "installed: $("$LINK" --version 2>/dev/null || echo cosmo)"
case ":$PATH:" in
    *":$BINDIR:"*) echo "run: cosmo --help" ;;
    *) echo "NOTE: $BINDIR is not on your PATH. Add it:"
       echo "      export PATH=\"$BINDIR:\$PATH\"" ;;
esac
echo "AI review: install & log in to the 'claude' CLI, then: cosmo review . --model claude-cli"
