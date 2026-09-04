"""One runner per static scanner: invoke it, normalize its output.

Every runner has the same shape —

    runner(root: str, ev, skipped: list[str] | None) -> list[Finding]

— and the same two obligations. It normalizes into the shared `Finding` schema,
so nothing downstream knows which tool a finding came from; and it appends to
`skipped` when it produces a *partial* result, which is neither a clean pass nor
a failed stage. gitleaks scanning the working tree but timing out on history is
the case that taught us the difference.

Which of these run, and how their absence is reported, is `prefilter.py`.
"""
from __future__ import annotations

import json
import os
import os.path
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from ..findings import ConfirmationStatus, Finding
from ..severity import Severity


# The gitleaks history pass walks every commit. That is bounded work on a normal
# clone, but a *partial* clone (`--filter=blob:none`) has to fetch each blob over
# the network, so a large repo can run for many minutes. Bound it and report the
# shortfall rather than letting cosmo appear to hang.
GITLEAKS_HISTORY_TIMEOUT = 60

# Per-tool ceilings. Every scanner gets one: the gitleaks history pass hung a
# scan of a 3695-commit partial clone for minutes before this existed.
SEMGREP_TIMEOUT = 900   # covers semgrep and opengrep
BANDIT_TIMEOUT = 300
TRIVY_TIMEOUT = 600      # generous: a cold run downloads a vulnerability DB


# Every scanner process currently in flight. A scan runs several at once, each
# in a worker thread blocked reading its child's output — and Ctrl-C is
# delivered to the *main* thread only, so without a way to reach these the
# interrupt lands, the pool's shutdown waits for the workers, and cosmo appears
# to hang behind a semgrep run that has minutes left.
_running: set[subprocess.Popen] = set()
_running_lock = threading.Lock()


# After SIGTERM, how long a scanner gets to wind down before it is killed. Short:
# this path only runs when the operator has already decided to abandon the scan.
TERMINATE_GRACE = 2.0


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    """Signal a scanner *and everything it spawned*.

    `proc.terminate()` reaches only the direct child, which is not enough:
    semgrep's launcher spawns `semgrep-core`, and on Ctrl-C that grandchild
    survived, outlived cosmo, and carried on burning CPU after the process the
    operator interrupted was gone. Each scanner is therefore started in its own
    process group (`start_new_session`) so the whole group can be signalled.
    """
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (OSError, AttributeError):
        # Already reaped, or a platform without process groups.
        try:
            proc.terminate()
        except OSError:
            pass


def terminate_running_scanners(grace: float = TERMINATE_GRACE) -> int:
    """Stop every scanner in flight, and everything it spawned.

    Returns how many were signalled. Called when the run is being abandoned
    (Ctrl-C): stopping the children is what lets the worker threads return,
    which is what lets the pool shut down instead of appearing to hang.
    """
    with _running_lock:
        procs = list(_running)
    for proc in procs:
        _signal_group(proc, signal.SIGTERM)
    # A scanner that ignores SIGTERM would keep the pool waiting forever, so the
    # grace period is bounded and then it is killed.
    deadline = time.monotonic() + grace
    for proc in procs:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _signal_group(proc, signal.SIGKILL)
    return len(procs)


def _sh(cmd: list[str], ev=None, timeout: int | None = None) -> str:
    if ev is not None:
        ev.execute(cmd, stage="static")
    # These scanners exit non-zero when they find issues; don't raise on that.
    # Popen rather than subprocess.run so the child is reachable while it runs.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    with _running_lock:
        _running.add(proc)
    try:
        out, _ = proc.communicate(timeout=timeout)
        return out or ""
    except subprocess.TimeoutExpired:
        # communicate() leaves the child running on timeout; kill the whole
        # group and reap, or the scan finishes with an orphan still working.
        _signal_group(proc, signal.SIGKILL)
        proc.communicate()
        raise
    finally:
        with _running_lock:
            _running.discard(proc)


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


def _semgrep_evidence(check_id: str, meta: dict, lines: str | None = None,
                      tool: str = "semgrep") -> str:
    """Triage material for a semgrep hit.

    Deliberately *not* built from `extra.lines` (the matched source): on the OSS
    engine that field reads "requires login", so a report built on it would show
    that string instead of code. What is actually present is the rule that fired,
    semgrep's own grading of it, the full CWE/OWASP text, and the rule's
    references — which together are enough to decide whether a hit is real
    without re-running the scanner.
    """
    parts: list[str] = []
    if check_id:
        parts.append(f"{tool} rule: {check_id}")
    grades = [f"{k}={meta[k]}" for k in ("confidence", "impact", "likelihood")
              if meta.get(k)]
    if grades:
        parts.append(f"{tool} rating: " + "  ".join(grades))
    # Only opengrep and a logged-in semgrep return real source here.
    matched = " ".join(str(lines or "").split())
    if matched and matched != "requires login":
        parts.append(f"matched: {matched[:200]}")
    for key, label in (("cwe", "CWE"), ("owasp", "OWASP")):
        val = meta.get(key)
        items = val if isinstance(val, list) else ([val] if val else [])
        if items:
            parts.append(f"{label}: " + "; ".join(str(i) for i in items))
    refs = [meta.get("shortlink"), meta.get("source-rule-url")]
    refs += list(meta.get("references") or [])
    seen: set[str] = set()
    for ref in refs:
        if ref and str(ref) not in seen:
            seen.add(str(ref))
            parts.append(str(ref))
        if len(seen) >= 4:
            break
    return "\n".join(parts)


def _semgrep_like_findings(data: dict, tool: str) -> list[Finding]:
    """Map the semgrep JSON schema into Findings.

    opengrep is a fork of semgrep and emits the same `results[].{check_id, path,
    start, extra}` shape, so one mapper serves both. The one place they differ is
    `extra.lines`: semgrep's OSS engine returns the string "requires login"
    there, opengrep returns the matched source — which is why the evidence
    builder takes it as an argument instead of assuming either.
    """
    findings: list[Finding] = []
    for i, r in enumerate(data.get("results", [])):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
        findings.append(
            Finding(
                id=f"static-{tool}-{i}",
                title=extra.get("message", r.get("check_id", "semgrep finding"))[:200],
                severity=Severity.parse(extra.get("severity", "medium")),
                source=f"static:{tool}",
                file=r.get("path", ""),
                line=int(r.get("start", {}).get("line", 0) or 0),
                confidence=0.7,
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category=str(cwe) if cwe else None,
                evidence=_semgrep_evidence(r.get("check_id", ""), meta,
                                           extra.get("lines"), tool),
                remediation=_semgrep_remediation(meta, extra),
                # Semgrep security rules are security-relevant, but "sensitive enough
                # to withhold publicly" is decided at the gate by severity+status.
                security_sensitive=False,
            )
        )
    return findings


def _run_semgrep(root: str, ev=None, skipped: list[str] | None = None) -> list[Finding]:
    out = _sh(["semgrep", "--config", "auto", "--json", "--quiet", root], ev,
              SEMGREP_TIMEOUT)
    return _semgrep_like_findings(json.loads(out or "{}"), "semgrep")


def _run_opengrep(root: str, ev=None, skipped: list[str] | None = None) -> list[Finding]:
    """The semgrep fork. Same rule format, same JSON, no login for the source.

    Running both is not redundant work for nothing — they have diverged on rules
    and on engine — but it does mean two hits on one line. The engine's dedupe
    collapses those on (file, line, category), keeping the higher severity.
    """
    out = _sh(["opengrep", "scan", "--config", "auto", "--json", "--quiet", root],
              ev, SEMGREP_TIMEOUT)
    return _semgrep_like_findings(json.loads(out or "{}"), "opengrep")


def _redact(secret: str, *, inline: bool = False) -> str:
    """Enough of a credential to recognise it, never enough to use it.

    A report is a file on disk that gets attached to tickets and pasted into
    chat. Copying the secret into it verbatim mints a second live copy of the
    thing the finding says to rotate — but a bare "a secret is here" is not
    triageable either: the `phc_` prefix on a PostHog key is what tells an
    operator it is public by design.
    """
    s = str(secret or "")
    if len(s) <= 12:
        return f"<redacted, {len(s)} chars>"
    stub = f"{s[:6]}…{s[-4:]}"
    # Inside a quoted match line the length would land inside the quotes and
    # read as part of the value, so it is only appended when standing alone.
    return stub if inline else f"{stub} ({len(s)} chars)"


def _gitleaks_evidence(row: dict) -> str:
    """What the operator needs to judge a leak without re-running gitleaks."""
    parts = [f"gitleaks rule: {row.get('RuleID', 'unknown')}"]
    if row.get("Description"):
        parts.append(str(row["Description"]))
    secret = str(row.get("Secret") or "")
    match = " ".join(str(row.get("Match") or "").split())
    if match:
        # Keep the surrounding line — the variable name is often the whole
        # answer — with the credential itself replaced.
        if secret:
            match = match.replace(secret, _redact(secret, inline=True))
        parts.append(f"match: {match[:200]}")
    elif secret:
        parts.append(f"secret: {_redact(secret)}")
    if row.get("Entropy"):
        parts.append(f"entropy: {row['Entropy']}")
    commit = str(row.get("Commit") or "")
    if commit:
        who = str(row.get("Author") or "").strip()
        when = str(row.get("Date") or "").strip()
        where = f"in commit {commit[:12]}"
        if who:
            where += f" by {who}"
        if when:
            where += f" on {when}"
        parts.append(f"found {where}")
    return "\n".join(parts)


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
    # Keep the richer row: the working-tree pass runs first but reports no
    # commit, so dropping the later duplicate would throw away the one piece of
    # provenance that says when the secret entered the repo.
    merged: dict[tuple, dict] = {}
    for r in rows:
        key = (r.get("RuleID"), r.get("File"), r.get("StartLine"))
        prior = merged.get(key)
        if prior is None:
            merged[key] = r
        elif not prior.get("Commit") and r.get("Commit"):
            merged[key] = {**r, "File": prior.get("File", r.get("File"))}
    rows = list(merged.values())
    findings: list[Finding] = []
    for i, r in enumerate(rows or []):
        findings.append(
            Finding(
                id=f"static-gitleaks-{i}",
                title=f"Secret leaked: {r.get('RuleID', 'unknown rule')}",
                severity=Severity.HIGH,
                source="static:gitleaks",
                file=r.get("File", ""),
                line=int(r.get("StartLine", 0) or 0),
                confidence=0.9,
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category="CWE-798",  # use of hard-coded credentials
                evidence=_gitleaks_evidence(r),
                remediation="Rotate the exposed secret and remove it from the repo/history.",
                security_sensitive=True,  # a live secret → gate must withhold public detail
            )
        )
    return findings


# --- bandit (Python AST checks) ---------------------------------------------

# Bandit's own grading of a rule. Kept separate from severity: `severity` says
# how bad it would be, `confidence` says how sure bandit is that it is real —
# and a LOW-confidence HIGH-severity hit is the classic false positive.
_BANDIT_CONFIDENCE = {"HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4}

# Tests whose flagged line *is* the credential. Bandit ships the source snippet
# in `code`; for these it would copy the secret into the report, which is the
# thing the finding says to rotate.
_BANDIT_SECRET_TESTS = {"B105", "B106", "B107"}


# Bandit puts the offending value straight into its message:
#     Possible hardcoded password: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
# Rendered as a finding title that copies the credential into the report, the
# terminal, and the ticket it gets pasted into.
_QUOTED = re.compile(r"'([^']{4,})'|\"([^\"]{4,})\"")


def _redact_quoted(text: str) -> str:
    """Redact the quoted value in a tool message that embeds a secret."""
    def _sub(m: "re.Match") -> str:
        value = m.group(1) or m.group(2)
        return f"'{_redact(value, inline=True)}'"
    return _QUOTED.sub(_sub, str(text))


def _bandit_evidence(r: dict) -> str:
    parts = [f"bandit test: {r.get('test_id', '?')} ({r.get('test_name', '')})".strip()]
    conf = r.get("issue_confidence")
    if conf:
        parts.append(f"bandit confidence: {conf}")
    if r.get("more_info"):
        parts.append(str(r["more_info"]))
    code = str(r.get("code") or "").strip()
    if code and r.get("test_id") not in _BANDIT_SECRET_TESTS:
        parts.append("code:")
        parts.extend(f"  {ln}" for ln in code.splitlines()[:6])
    return "\n".join(parts)


def _bandit_title(r: dict) -> str:
    text = str(r.get("issue_text") or r.get("test_id") or "bandit finding")
    if r.get("test_id") in _BANDIT_SECRET_TESTS:
        return _redact_quoted(text)
    return text


def _run_bandit(root: str, ev=None, skipped: list[str] | None = None) -> list[Finding]:
    """Python-only AST checks. Silent (zero results) on a repo with no Python."""
    out = _sh(["bandit", "-r", "-f", "json", "-q", root], ev, BANDIT_TIMEOUT)
    data = json.loads(out or "{}")

    # Files bandit could not parse are coverage it did not have. Reporting the
    # count keeps a partial pass from reading as a complete one.
    errors = data.get("errors") or []
    if errors and skipped is not None:
        skipped.append(f"static:bandit ({len(errors)} file(s) could not be parsed "
                       f"— not scanned)")

    findings: list[Finding] = []
    for i, r in enumerate(data.get("results", [])):
        cwe = (r.get("issue_cwe") or {}).get("id")
        findings.append(
            Finding(
                id=f"static-bandit-{i}",
                title=_bandit_title(r),
                severity=Severity.parse(r.get("issue_severity", "medium")),
                source="static:bandit",
                file=str(r.get("filename", "")),
                line=int(r.get("line_number", 0) or 0),
                confidence=_BANDIT_CONFIDENCE.get(
                    str(r.get("issue_confidence", "")).upper(), 0.5),
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category=f"CWE-{cwe}" if cwe else None,
                evidence=_bandit_evidence(r),
                security_sensitive=False,
            )
        )
    return findings


# --- trivy (dependency CVEs + IaC misconfiguration) -------------------------

# Trivy grades UNKNOWN when a source gave no severity. Mapping it to INFO keeps
# it in the report but below any working floor, rather than inventing a level.
_TRIVY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}


def _trivy_severity(value) -> Severity:
    return _TRIVY_SEVERITY.get(str(value or "").upper(), Severity.MEDIUM)


def _package_lines(result: dict) -> dict[str, int]:
    """Map a package UID to the manifest line that declares it.

    A vulnerability row names its package but carries no location; the line
    lives on the sibling `Packages` entry, joined by `Identifier.UID`. Without
    this every CVE would report line 0 and no editor could jump to it.
    """
    lines: dict[str, int] = {}
    for pkg in result.get("Packages") or []:
        uid = (pkg.get("Identifier") or {}).get("UID")
        locs = pkg.get("Locations") or []
        if uid and locs:
            lines[uid] = int(locs[0].get("StartLine", 0) or 0)
    return lines


def _trivy_vulnerabilities(result: dict, root: str, start: int) -> list[Finding]:
    lines = _package_lines(result)
    target = os.path.join(root, str(result.get("Target", "")))
    out: list[Finding] = []
    for i, v in enumerate(result.get("Vulnerabilities") or [], start):
        uid = (v.get("PkgIdentifier") or {}).get("UID", "")
        cwes = v.get("CweIDs") or []
        fixed = v.get("FixedVersion")
        evidence = [f"trivy: {v.get('VulnerabilityID', '?')} in "
                    f"{v.get('PkgName', '?')} {v.get('InstalledVersion', '?')}"]
        if v.get("PrimaryURL"):
            evidence.append(str(v["PrimaryURL"]))
        if v.get("Description"):
            evidence.append(str(v["Description"]))
        out.append(
            Finding(
                id=f"static-trivy-vuln-{i}",
                title=f"{v.get('VulnerabilityID', 'vulnerability')}: "
                      f"{v.get('Title') or v.get('PkgName', '')}".strip(": "),
                severity=_trivy_severity(v.get("Severity")),
                source="static:trivy",
                file=target,
                line=lines.get(uid, 0),
                confidence=0.9,          # a CVE against a pinned version is a fact
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category=str(cwes[0]) if cwes else "CWE-1104",
                evidence="\n".join(evidence),
                remediation=(f"Upgrade {v.get('PkgName', '')} "
                             f"{v.get('InstalledVersion', '')} → {fixed}."
                             if fixed else
                             f"No fixed version published for "
                             f"{v.get('PkgName', '')} yet — assess exposure or "
                             f"replace the dependency."),
                security_sensitive=False,   # a public CVE is already public
            )
        )
    return out


def _trivy_misconfigurations(result: dict, root: str, start: int) -> list[Finding]:
    target = os.path.join(root, str(result.get("Target", "")))
    out: list[Finding] = []
    for i, m in enumerate(result.get("Misconfigurations") or [], start):
        cause = m.get("CauseMetadata") or {}
        evidence = [f"trivy: {m.get('ID', '?')} ({m.get('Type', '')})".strip(" ()")]
        if m.get("Message"):
            evidence.append(str(m["Message"]))
        if m.get("PrimaryURL"):
            evidence.append(str(m["PrimaryURL"]))
        out.append(
            Finding(
                id=f"static-trivy-misconfig-{i}",
                title=str(m.get("Title") or m.get("ID", "misconfiguration")),
                severity=_trivy_severity(m.get("Severity")),
                source="static:trivy",
                file=target,
                line=int(cause.get("StartLine", 0) or 0),
                confidence=0.8,
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category="CWE-16",       # configuration
                evidence="\n".join(evidence),
                remediation=str(m.get("Resolution") or ""),
                security_sensitive=False,
            )
        )
    return out


def _run_trivy(root: str, ev=None, skipped: list[str] | None = None) -> list[Finding]:
    """Dependency CVEs and IaC misconfiguration — the `dep-audit` stub, filled.

    Secret scanning is deliberately left off: gitleaks already runs, and a third
    opinion on the same file costs time without adding coverage.

    Trivy fetches a vulnerability database on first use, so a cold run on a
    machine with no network fails here rather than silently reporting zero CVEs.
    That surfaces under `skipped:` like any other tool error.
    """
    out = _sh(["trivy", "fs", "--scanners", "vuln,misconfig", "--format", "json",
               "--quiet", "--no-progress", root], ev, TRIVY_TIMEOUT)
    if not out.strip():
        raise RuntimeError("trivy produced no JSON — the run did not complete "
                           "(commonly: vulnerability DB could not be fetched)")
    data = json.loads(out)

    findings: list[Finding] = []
    for result in data.get("Results") or []:
        findings += _trivy_vulnerabilities(result, root, len(findings))
        findings += _trivy_misconfigurations(result, root, len(findings))
    return findings


# --- trufflehog v3 (secrets, optionally verified against the provider) -------

TRUFFLEHOG_TIMEOUT = 600


def _trufflehog_evidence(row: dict) -> str:
    """`Raw` holds the credential itself and never reaches this string."""
    parts = [f"trufflehog detector: {row.get('DetectorName', 'unknown')}"]
    if row.get("DetectorDescription"):
        parts.append(str(row["DetectorDescription"]))
    secret = str(row.get("Raw") or "")
    shown = str(row.get("Redacted") or "").strip() or (_redact(secret) if secret else "")
    if shown:
        parts.append(f"secret: {shown}")
    if row.get("Verified"):
        parts.append("VERIFIED: trufflehog authenticated this credential against "
                     "the provider — it is live, and rotating it is urgent.")
    else:
        parts.append("unverified: matched by pattern; not tested against the provider")
    if row.get("DecoderName") and row["DecoderName"] != "PLAIN":
        parts.append(f"found inside a {row['DecoderName']}-encoded blob")
    return "\n".join(parts)


def _run_trufflehog(root: str, ev=None, skipped: list[str] | None = None,
                    verify: bool = False) -> list[Finding]:
    """Secret detection with a live-credential check cosmo does not run by default.

    trufflehog's distinguishing feature is *verification*: it calls the
    credential's own provider to see whether it still works. That is also why it
    is off unless an operator asks for it — verification transmits candidate
    secrets out of the network to third parties that are not the model provider
    and never pass the egress broker. A repo cannot turn it on; the key has
    no clamp rule, so the safety merge ignores and warns on a repo value.

    Output is JSON-lines on stdout; its own logs go to stderr, which `_sh` drops.
    """
    argv = ["trufflehog", "filesystem", "--json", "--no-update"]
    if not verify:
        argv.append("--no-verification")
    argv.append(root)
    out = _sh(argv, ev, TRUFFLEHOG_TIMEOUT)

    findings: list[Finding] = []
    for i, line in enumerate(out.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not row.get("DetectorName"):
            continue          # a progress/log record, not a finding
        loc = ((row.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        verified = bool(row.get("Verified"))
        findings.append(
            Finding(
                id=f"static-trufflehog-{i}",
                title=(f"{'Verified live' if verified else 'Possible'} secret: "
                       f"{row.get('DetectorName')}"),
                severity=Severity.CRITICAL if verified else Severity.HIGH,
                source="static:trufflehog",
                file=str(loc.get("file", "")),
                line=int(loc.get("line", 0) or 0),
                # A credential the provider just accepted is not a guess.
                confidence=0.99 if verified else 0.7,
                confirmation_status=(ConfirmationStatus.CONFIRMED if verified
                                     else ConfirmationStatus.UNCONFIRMED),
                category="CWE-798",
                evidence=_trufflehog_evidence(row),
                remediation="Rotate the exposed secret and remove it from the "
                            "repo/history.",
                security_sensitive=True,
            )
        )
    return findings


# --- find-sec-bugs (Java, via SpotBugs — needs compiled bytecode) -----------

FINDSECBUGS_TIMEOUT = 900

# The distribution ships a shell wrapper, and installs differ on whether the
# `.sh` survives on PATH. Accept either rather than make the tool look absent.
_FINDSECBUGS_BINARIES = ("findsecbugs", "findsecbugs.sh")


def _findsecbugs_bin() -> str:
    for name in _FINDSECBUGS_BINARIES:
        if shutil.which(name):
            return name
    return _FINDSECBUGS_BINARIES[0]

# SpotBugs' SARIF writer derives `level` from its own bug rank, so this is the
# tool's opinion rather than one invented here. Most find-sec-bugs detectors land
# on `warning`.
_SARIF_LEVEL = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
                "note": Severity.LOW, "none": Severity.INFO}

# Where a JVM build leaves its class files. find-sec-bugs analyses bytecode, not
# source: without one of these there is nothing for it to read.
_CLASS_DIRS = ("target/classes", "target/test-classes", "build/classes",
               "build/intermediates/javac", "out/production", "bin/classes",
               "classes")


def _bytecode_roots(root: Path) -> list[str]:
    found = [str(root / d) for d in _CLASS_DIRS if (root / d).is_dir()]
    if found:
        return found
    # A packaged build is just as analysable as a class directory.
    jars = sorted(str(p) for d in ("target", "build/libs", "build")
                  for p in (root / d).glob("*.jar")) if root.is_dir() else []
    return jars[:20]


def _has_java_source(root: Path) -> bool:
    return any(root.rglob("*.java"))


def _cwe_by_rule(driver: dict) -> dict[str, str]:
    """Rule id → CWE, read off the SARIF taxonomy relationships."""
    out: dict[str, str] = {}
    for rule in driver.get("rules") or []:
        for rel in rule.get("relationships") or []:
            target = rel.get("target") or {}
            if (target.get("toolComponent") or {}).get("name") == "CWE" and target.get("id"):
                out[rule.get("id", "")] = f"CWE-{target['id']}"
                break
    return out


def _help_by_rule(driver: dict) -> dict[str, str]:
    return {r.get("id", ""): str(r.get("helpUri") or "")
            for r in driver.get("rules") or []}


def _resolve_source(uri: str, root: Path, index: dict[str, str]) -> str:
    """SpotBugs reports a bare source file name — the path is not in the bytecode.

    Reported as-is it would be `Vuln.java`, which no editor can open and no
    waiver fingerprint can anchor to. Resolve it against the tree when the name
    is unambiguous; leave it alone when it is not, rather than guessing.
    """
    return index.get(uri, uri)


def _run_findsecbugs(root: str, ev=None, skipped: list[str] | None = None) -> list[Finding]:
    """Java taint analysis. Reads compiled classes, so a repo must be built.

    Being unable to run here is *lost coverage*, not a non-event: the Java in the
    tree went unreviewed by the one tool in the set that understands it. That is
    reported. A repo with no Java at all is a different case and says nothing.
    """
    base = Path(root)
    roots = _bytecode_roots(base)
    if not roots:
        if _has_java_source(base) and skipped is not None:
            skipped.append(
                "static:find-sec-bugs (Java source found but no compiled classes "
                "— it analyses bytecode; build the project first, e.g. `mvn -q "
                "compile`, so target/classes exists)")
        return []

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "findsecbugs.sarif"
        _sh([_findsecbugs_bin(), "-sarif", "-output", str(report), "-quiet",
             *roots], ev, FINDSECBUGS_TIMEOUT)
        if not report.exists():
            raise RuntimeError("find-sec-bugs wrote no SARIF report — "
                               "the analysis did not complete")
        data = json.loads(report.read_text() or "{}")

    runs = data.get("runs") or []
    if not runs:
        return []
    driver = (runs[0].get("tool") or {}).get("driver") or {}
    cwes, helps = _cwe_by_rule(driver), _help_by_rule(driver)
    index = {p.name: str(p) for p in base.rglob("*.java")}

    findings: list[Finding] = []
    for i, res in enumerate(runs[0].get("results") or []):
        rule = str(res.get("ruleId", ""))
        loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
        uri = str((loc.get("artifactLocation") or {}).get("uri", ""))
        evidence = [f"find-sec-bugs rule: {rule}"]
        where = ((res.get("locations") or [{}])[0].get("logicalLocations") or [{}])[0]
        if where.get("fullyQualifiedName"):
            evidence.append(f"in {where['fullyQualifiedName']}")
        for arg in res.get("message", {}).get("arguments") or []:
            evidence.append(f"sink: {arg}")
        if helps.get(rule):
            evidence.append(helps[rule])
        findings.append(
            Finding(
                id=f"static-findsecbugs-{i}",
                title=str((res.get("message") or {}).get("text") or rule),
                severity=_SARIF_LEVEL.get(str(res.get("level", "warning")),
                                          Severity.MEDIUM),
                source="static:find-sec-bugs",
                file=_resolve_source(uri, base, index),
                line=int((loc.get("region") or {}).get("startLine", 0) or 0),
                confidence=0.7,
                confirmation_status=ConfirmationStatus.UNCONFIRMED,
                category=cwes.get(rule),
                evidence="\n".join(evidence),
                security_sensitive=False,
            )
        )
    return findings
