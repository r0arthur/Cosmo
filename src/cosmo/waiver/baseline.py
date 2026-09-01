"""Waiver / baseline suppression (architecture §11, build step 5, RISK-07).

Prioritized early because noise kills adoption before any other stage compounds
it. The load-bearing detail is the fingerprint: it is **content-based, not
line-based**, so an unrelated edit above a finding doesn't shift its line and
cause a spurious re-alert — or, under a loose match, silently suppress a
genuinely new nearby instance.

The fingerprint is:  hash(rule/source key + category + normalized sink line +
normalized surrounding context). Normalization strips whitespace and replaces
string/number literals with placeholders, so cosmetic edits don't change it but
a real change to the sink does.

MVP stores the baseline as JSON at <target>/.cosmo/baseline.json. Migrating to
the SQLite trend store is build step 15 (§14), out of MVP scope.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..diff import Diff
from ..findings import Finding

_STRING_LIT = re.compile(r"""(['"]).*?\1""")
_NUM_LIT = re.compile(r"\b\d+\b")
_WS = re.compile(r"\s+")


def _normalize(line: str) -> str:
    line = _STRING_LIT.sub("STR", line)
    line = _NUM_LIT.sub("N", line)
    return _WS.sub(" ", line).strip()


def _sink_and_context(finding: Finding, diff: Diff) -> tuple[str, list[str]]:
    """Pull the sink line + a few surrounding added lines from the diff."""
    df = diff.file(finding.file)
    if df is None:
        return finding.title, []
    added = [(ln, txt) for h in df.hunks for ln, txt in h.added]
    sink = ""
    idx = None
    for i, (ln, txt) in enumerate(added):
        if ln == finding.line:
            sink, idx = txt, i
            break
    if idx is None:
        # Fall back to title when the exact line isn't in the diff (e.g. whole-file mode).
        return finding.title, [t for _, t in added[:3]]
    ctx = [t for _, t in added[max(0, idx - 2): idx + 3]]
    return sink, ctx


def fingerprint(finding: Finding, diff: Diff) -> str:
    sink, ctx = _sink_and_context(finding, diff)
    key = "|".join(
        [
            finding.source.split(":")[0],           # static/model/... (not the per-run id)
            finding.category or "",
            _normalize(sink),
            " ".join(_normalize(c) for c in ctx),
        ]
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class Baseline:
    path: Path
    waived: dict[str, dict] = field(default_factory=dict)  # fingerprint -> {reason, ...}

    @classmethod
    def load(cls, target_dir: str) -> "Baseline":
        p = Path(target_dir)
        p = (p if p.is_dir() else p.parent) / ".cosmo" / "baseline.json"
        waived = {}
        if p.is_file():
            waived = json.loads(p.read_text()).get("waived", {})
        return cls(path=p, waived=waived)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"waived": self.waived}, indent=2))

    def waive(self, fp: str, reason: str = "") -> None:
        self.waived[fp] = {"reason": reason}

    def unwaive(self, fp: str) -> None:
        self.waived.pop(fp, None)

    def apply(self, findings: list[Finding], diff: Diff) -> list[Finding]:
        """Stamp fingerprints and mark waived findings. Suppression = filter these out.

        An already-stamped fingerprint is kept: a history sweep fingerprints each
        finding against the commit that introduced it, and `diff` here cannot
        stand in for a hundred different commits.
        """
        for f in findings:
            if f.fingerprint is None:
                f.fingerprint = fingerprint(f, diff)
            if f.fingerprint in self.waived:
                f.waived = True
                f.waived_reason = self.waived[f.fingerprint].get("reason", "")
        return findings
