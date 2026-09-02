"""Static pre-filter (architecture §5, build step 6).

Deterministic, cheap, high-confidence first pass that runs BEFORE the LLM stage;
its output is passed forward as context so the model doesn't re-derive what a
tool already caught (§5, §15 cost control).

Each runner is optional: if the tool isn't installed the stage is recorded as
skipped rather than failing the scan. Dependency auditing (npm audit / pip-audit
/ osv-scanner) is a documented stub — the interface is here, wired into the same
Finding shape, ready to fill in.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..findings import ConfirmationStatus, Finding
from ..severity import Severity


def run_static_prefilter(target_dir: str, events=None) -> tuple[list[Finding], list[str]]:
    """Returns (findings, skipped_stages)."""
    from ..events import Emitter
    ev = events if isinstance(events, Emitter) else Emitter(events)

    findings: list[Finding] = []
    skipped: list[str] = []
    root = Path(target_dir)
    if root.is_file():
        root = root.parent

    for name, runner in (("semgrep", _run_semgrep), ("gitleaks", _run_gitleaks)):
        if not shutil.which(name):
            skipped.append(f"static:{name} (not installed)")
            ev.stage_skipped("static", f"{name} not installed — that stage is skipped")
            continue
        try:
            found = runner(str(root), ev)
            findings += found
            ev.output(f"{name}: {len(found)} finding(s)", stage="static",
                      tool=name, findings=len(found))
        except Exception as exc:  # a broken tool run shouldn't sink the whole scan
            skipped.append(f"static:{name} (error: {exc})")
            ev.error(f"{name} failed: {exc}", stage="static")

    # Dependency audit — STUB (§5). Wire npm audit / pip-audit / osv-scanner here,
    # mapping each advisory to a Finding(source="static", category="CWE-1104", ...).
    skipped.append("static:dep-audit (stub — not implemented in MVP)")
    ev.stage_skipped("static", "dep-audit is a documented stub, not implemented")

    return findings, skipped


def _sh(cmd: list[str], ev=None) -> str:
    if ev is not None:
        ev.execute(cmd, stage="static")
    # These scanners exit non-zero when they find issues; don't raise on that.
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def _semgrep_remediation(meta: dict, extra: dict) -> str:
    """Prose guidance if the rule carries it, else semgrep's autofix, labelled.

    `metadata.fix` is human-readable advice, but `extra.fix` is the *replacement
    text* semgrep would substitute — so the rule for `subprocess(shell=True)`
    yields the bare string "False". Rendered unlabelled that reads as
    "fix: False", which is worse than saying nothing.
    """
    prose = meta.get("fix")
    if isinstance(prose, str) and prose.strip():
        return prose.strip()
    autofix = extra.get("fix")
    if isinstance(autofix, str) and autofix.strip():
        return f"replace with `{autofix.strip()}`"
    return ""


def _run_semgrep(root: str, ev=None) -> list[Finding]:
    out = _sh(["semgrep", "--config", "auto", "--json", "--quiet", root], ev)
    data = json.loads(out or "{}")
    findings: list[Finding] = []
    for i, r in enumerate(data.get("results", [])):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
        findings.append(
            Finding(
                id=f"static-semgrep-{i}",
                title=extra.get("message", r.get("check_id", "semgrep finding"))[:200],
                severity=Severity.parse(extra.get("severity", "medium")),
                source="static",
                file=r.get("path", ""),
                line=int(r.get("start", {}).get("line", 0) or 0),
                confidence=0.7,
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category=str(cwe) if cwe else None,
                evidence=r.get("check_id", ""),
                remediation=_semgrep_remediation(meta, extra),
                # Semgrep security rules are security-relevant, but "sensitive enough
                # to withhold publicly" is decided at the gate by severity+status.
                security_sensitive=False,
            )
        )
    return findings


def _run_gitleaks(root: str, ev=None) -> list[Finding]:
    # gitleaks writes its report to a file; use a temp path within the tree's scratch.
    report = Path(root) / ".cosmo-gitleaks.json"
    try:
        _sh(["gitleaks", "detect", "--no-banner", "--report-format", "json",
             "--report-path", str(report), "--source", root], ev)
        rows = json.loads(report.read_text()) if report.exists() else []
    finally:
        report.unlink(missing_ok=True)
    findings: list[Finding] = []
    for i, r in enumerate(rows or []):
        findings.append(
            Finding(
                id=f"static-gitleaks-{i}",
                title=f"Secret leaked: {r.get('RuleID', 'unknown rule')}",
                severity=Severity.HIGH,
                source="static",
                file=r.get("File", ""),
                line=int(r.get("StartLine", 0) or 0),
                confidence=0.9,
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category="CWE-798",  # use of hard-coded credentials
                evidence=r.get("Description", ""),
                remediation="Rotate the exposed secret and remove it from the repo/history.",
                security_sensitive=True,  # a live secret → gate must withhold public detail
            )
        )
    return findings
