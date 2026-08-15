"""Custom extension contract + registry (custom plugins/skills for cosmo).

A researcher extends cosmo without forking it by shipping an *extension*: a
Python module that contributes any of

  * **skills**     — custom review guidance (same SKILL.md convention as §10),
  * **detectors**  — extra finding sources, `callable(target, config) -> [Finding]`,
  * **commands**   — extra interactive slash-commands, exposed under `/x-<name>`.

The security spine (unchanged from the rest of cosmo) is carried here too:

  * **Discovery ≠ activation.** An extension is only imported and run if the
    operator lists its name in `extensions.enabled`. Because `extensions` is a
    safety-tier config section (§15), a *scanned repo can never enable one* — it
    can ship extension code, but that code stays inert unless the operator, the
    trusted tier, opts in. Enabling an extension is a full-trust act (it runs
    in-process), so it is deliberately operator-only.
  * **No impersonation of guarded commands.** A custom command can never take the
    name of a builtin (`/report`, `/scope`, …); it is namespaced to `/x-<name>`,
    so a plugin cannot shadow the gated command a user expects.
  * **Custom findings still flow through the gate.** Detector output is
    normalized into the shared `Finding` shape (tagged `source="ext:<name>"`) and
    returned for the normal aggregation → waiver → public-comment-gate path. An
    extension cannot emit a finding straight to a public surface.
  * **Trust of custom skills follows activation.** An enabled extension's skills
    are authoritative unless the operator lists the extension in
    `extensions.reference_only`, in which case they load as UNTRUSTED reference
    (RISK-03), exactly like repo-provided skills.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..config import Config
from ..findings import Finding
from ..skills.loader import Skill

# A detector: given a target path/ref and the resolved config, yield findings.
Detector = Callable[[str, Config], "list[Finding]"]
# A command handler mirrors the interactive dispatch signature.
CommandHandler = Callable[["object", "list[str]"], str]


@dataclass
class Extension:
    """What a custom plugin contributes. Constructed by the extension module and
    exposed as module-level `COSMO_EXTENSION`, or returned from `register()`."""
    name: str
    version: str = "0"
    description: str = ""
    skills: list[Skill] = field(default_factory=list)
    detectors: dict[str, Detector] = field(default_factory=dict)
    commands: dict[str, CommandHandler] = field(default_factory=dict)


def normalize_extension_findings(name: str, raw: object) -> list[Finding]:
    """Force detector output through the shared Finding shape.

    A detector cannot return an arbitrary object and have it treated as a
    finding: anything that is not already a `Finding` is rejected. The source is
    stamped `ext:<name>` so downstream (aggregation, waiver, the §11 gate) treats
    it like any other finding — there is no privileged path for extension output.
    """
    out: list[Finding] = []
    for item in (raw or []):
        if not isinstance(item, Finding):
            raise TypeError(
                f"extension {name!r} detector returned {type(item).__name__}, "
                f"not a cosmo Finding — extension findings must use the shared shape"
            )
        # Re-stamp source so provenance is unambiguous and un-spoofable.
        item.source = f"ext:{name}"
        out.append(item)
    return out
