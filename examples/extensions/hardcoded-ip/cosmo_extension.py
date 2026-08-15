"""Example cosmo extension: flag hard-coded IPv4 literals in changed files.

Drop this directory somewhere and point the OPERATOR config at it:

    # operator-config.yaml  (the trusted tier — never the scanned repo's cosmo.yaml)
    extensions:
      paths: ["/abs/path/to/examples/extensions/hardcoded-ip"]
      enabled: ["hardcoded-ip"]        # discovery ≠ activation: this line arms it

The extension's name is the directory basename ("hardcoded-ip"). Until the
operator lists that name under `extensions.enabled`, cosmo will *discover* this
module but never import or run it.

It contributes all three extension surfaces:
  * a detector  — extra finding source, output normalized like any other finding,
  * a skill     — review guidance injected when a matching file changes,
  * a command   — exposed interactively as `/x-ipcheck` (namespaced; it can never
                  shadow a guarded builtin like /report or /scope).
"""
from __future__ import annotations

import re
from pathlib import Path

from cosmo.extensions import Extension
from cosmo.findings import Finding
from cosmo.severity import Severity
from cosmo.skills.loader import Skill

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# Ignore the obvious non-secrets so the detector isn't pure noise.
_IGNORE = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def detect_hardcoded_ips(target: str, config) -> list[Finding]:
    root = Path(target)
    root = root if root.is_dir() else root.parent
    out: list[Finding] = []
    for path in root.rglob("*.py"):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in _IPV4.finditer(line):
                if m.group(0) in _IGNORE:
                    continue
                rel = str(path.relative_to(root))
                out.append(Finding(
                    id=f"hardcoded-ip:{rel}:{i}",
                    title=f"Hard-coded IP literal {m.group(0)}",
                    severity=Severity.LOW,
                    source="ext:hardcoded-ip",      # re-stamped by cosmo anyway
                    file=rel,
                    line=i,
                    category="CWE-798",
                    evidence=line.strip()[:200],
                    remediation="Move host addresses to configuration/DNS.",
                ))
    return out


_SKILL = Skill(
    name="hardcoded-ip",
    description="Look harder at network endpoints in changed code.",
    applies_to=["**/*.py"],
    instructions=(
        "When reviewing changed Python, treat any hard-coded IP address as a smell: "
        "check whether it pins traffic to an attacker-influenceable host, bypasses "
        "egress controls, or leaks internal topology."
    ),
    origin="ext:hardcoded-ip",     # cosmo overrides origin/trust on activation
)


def _cmd_ipcheck(session, args) -> str:
    findings = detect_hardcoded_ips(session.target, session.config)
    return f"/x-ipcheck: {len(findings)} hard-coded IP literal(s) in {session.target}"


COSMO_EXTENSION = Extension(
    name="hardcoded-ip",
    version="1.0",
    description="Flags hard-coded IPv4 literals (detector + skill + /x-ipcheck).",
    skills=[_SKILL],
    detectors={"ipv4": detect_hardcoded_ips},
    commands={"ipcheck": _cmd_ipcheck},
)
