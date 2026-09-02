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
            # `skipped` lets a runner report a *partial* result — gitleaks can
            # scan the tree but time out on history, which is neither a clean
            # pass nor a failed stage.
            found = runner(str(root), ev, skipped)
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


# The gitleaks history pass walks every commit. That is bounded work on a normal
# clone, but a *partial* clone (`--filter=blob:none`) has to fetch each blob over
# the network, so a large repo can run for many minutes. Bound it and report the
# shortfall rather than letting cosmo appear to hang.
GITLEAKS_HISTORY_TIMEOUT = 60


def _sh(cmd: list[str], ev=None, timeout: int | None = None) -> str:
    if ev is not None:
        ev.execute(cmd, stage="static")
    # These scanners exit non-zero when they find issues; don't raise on that.
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout


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


def _run_semgrep(root: str, ev=None, skipped: list[str] | None = None) -> list[Finding]:
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


def _gitleaks_scan(root: str, mode_args: list[str], tag: str, ev=None,
                   timeout: int | None = None) -> list[dict]:
    """One gitleaks pass. Returns its raw rows."""
    report = Path(root) / f".cosmo-gitleaks-{tag}.json"
    try:
        _sh(["gitleaks", "detect", "--no-banner", *mode_args, "--report-format",
             "json", "--report-path", str(report), "--source", root], ev, timeout)
        if not report.exists():
            # gitleaks exits 1 when it finds leaks, so the exit code cannot tell
            # success from failure. A missing report can: gitleaks writes one —
            # even an empty array — on every completed run. Raising surfaces the
            # failure under `skipped:` instead of passing an empty result off as
            # a clean scan.
            raise RuntimeError(f"gitleaks {tag} scan wrote no report — did not complete")
        return json.loads(report.read_text()) or []
    finally:
        report.unlink(missing_ok=True)


def _run_gitleaks(root: str, ev=None, skipped: list[str] | None = None) -> list[Finding]:
    """Scan the working tree, and git history too when there is any.

    Two passes, because neither alone is sufficient:

    * `--no-git` reads the files as they are on disk. Without it gitleaks walks
      *commits* and misses a secret sitting uncommitted in the working tree —
      exactly what the pre-commit hook exists to catch. On a non-git target it
      found nothing at all and still exited 0, so cosmo reported "no findings"
      over a plaintext key.
    * The default git pass still matters for a secret that was committed and
      later deleted. It is gone from disk but not from history, and it still
      needs rotating.
    """
    rows = _gitleaks_scan(root, ["--no-git"], "tree", ev)
    if (Path(root) / ".git").exists():
        try:
            rows += _gitleaks_scan(root, [], "history", ev,
                                   timeout=GITLEAKS_HISTORY_TIMEOUT)
        except subprocess.TimeoutExpired:
            # The tree results are still good, so this is a partial result, not a
            # failed stage — report the shortfall and keep what we have. Silently
            # dropping it would present tree-only coverage as a full scan.
            note = (f"static:gitleaks history pass timed out after "
                    f"{GITLEAKS_HISTORY_TIMEOUT}s — working tree scanned, git "
                    f"history NOT scanned (large repo, or a partial clone "
                    f"fetching blobs over the network)")
            if skipped is not None:
                skipped.append(note)
            if ev is not None:
                ev.stage_skipped("static", note)

    # The passes overlap on any secret that is both committed and still on disk.
    seen: set[tuple] = set()
    unique: list[dict] = []
    for r in rows:
        key = (r.get("RuleID"), r.get("File"), r.get("StartLine"))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    rows = unique
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
