"""Interactive session state (architecture §7 — interactive command layer).

The same engine as batch mode: a session runs `run_review` and answers follow-up
questions from in-session findings state without re-scanning. The critical design
property is that **guardrails apply identically in interactive and batch mode** —
this state object holds session *preferences* (model, threshold, fuzz duration),
but every safety decision still routes through the same enforced code (the config
trust tiers, the fuzz duration cap, the public-comment gate). Nothing here can
loosen a safety-tier setting.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from ..config import Config
from ..engine import run_review
from ..findings import Finding, Report
from ..providers.registry import resolve_primary


@dataclass
class Session:
    config: Config
    target: str
    findings: list[Finding] = field(default_factory=list)
    session_model: str | None = None          # /model — a preference (§8 resolution)
    threshold_override: str | None = None      # /threshold — a preference floor
    fuzz_duration: int | None = None           # /duration — capped by fuzzing.max_duration
    running_campaigns: dict[str, int] = field(default_factory=dict)  # name -> remaining s
    notes: list[str] = field(default_factory=list)
    # What the scan did NOT cover. Dropped here once, which let `/report` render
    # an incomplete scan as a complete one — the one thing every other surface
    # in cosmo is built to prevent. Carried forward from every scan and audit.
    skipped_stages: list[str] = field(default_factory=list)
    external=None                              # /scope — lazily created ExternalTargetMode
    extensions=None                            # LoadedExtensions — lazily activated
    # Injected so the REPL stays hermetic in tests; defaults to the real engine.
    scanner=None
    confirmer=None
    # Live output sink (set by the REPL) so a long command like /audit can stream
    # progress as it runs instead of returning one blob at the end.
    writer=None
    # Background-audit state (a /audit runs on its own thread so the REPL stays
    # responsive). The lock guards `findings` because that thread mutates it while
    # the main thread reads it for /status, /report, etc.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    audit_thread=None            # threading.Thread | None — the running audit, if any
    audit_total: int = 0         # files this audit will review
    audit_done: int = 0          # files completed so far
    audit_skipped: int = 0       # files that errored

    def emit(self, msg: str) -> None:
        """Stream a line to the session output now, if a writer is attached."""
        if self.writer is not None:
            self.writer(msg)

    def audit_running(self) -> bool:
        return self.audit_thread is not None and self.audit_thread.is_alive()

    def advance_audit(self) -> None:
        """Count one audited file. Separate from `merge_findings` because the
        audit runs several reviews at once — `+= 1` from N workers loses updates.
        (Its own acquisition, not nested: `_lock` is not reentrant.)"""
        with self._lock:
            self.audit_done += 1

    def snapshot_findings(self) -> list[Finding]:
        """A stable copy of findings, safe to read while a background audit writes."""
        with self._lock:
            return list(self.findings)

    def merge_findings(self, new: list[Finding]) -> int:
        """Fold newly-found findings into session state, deduped by location+title
        (per-file audit reviews restart their ids, so id alone would collide).
        Thread-safe: the background audit merges each file's results as they land.
        Returns how many were actually added."""
        with self._lock:
            seen = {(f.file, f.line, f.category or f.title) for f in self.findings}
            added = 0
            for f in new:
                key = (f.file, f.line, f.category or f.title)
                if key not in seen:
                    self.findings.append(f)
                    seen.add(key)
                    added += 1
            return added

    def loaded_extensions(self):
        """Operator-enabled extensions for this session, activated on first use.

        Discovery ≠ activation: only names in the safety-tier `extensions.enabled`
        are imported and run; a scanned repo cannot enable one."""
        if self.extensions is None:
            from ..extensions import load_enabled
            self.extensions = load_enabled(self.config)
        return self.extensions

    def extension_command(self, name: str):
        """Resolve a `/x-<name>` extension command, or None. Never consulted for a
        builtin name — dispatch checks builtins first, so no impersonation."""
        return self.loaded_extensions().command_table().get(name)

    def external_mode(self):
        """The §9 external-target driver for this session, created on first use."""
        if self.external is None:
            from ..external import ExternalTargetMode
            self.external = ExternalTargetMode(config=self.config)
        return self.external

    def effective_threshold(self) -> str:
        return self.threshold_override or self.config.threshold

    def scan(self) -> Report:
        """Run the same pipeline batch mode runs, honoring the session model +
        threshold. Provider resolution still applies the §8 data-governance gate;
        a session `/model` cannot fan a sensitive repo's source off-box."""
        scanner = self.scanner or run_review
        cfg = self.config
        if self.threshold_override:
            # A copy so the session floor never mutates the loaded (trust-tiered) config.
            cfg = Config(data={**self.config.data, "threshold": self.threshold_override},
                         warnings=list(self.config.warnings))
        provider, warns = resolve_primary(cfg, session_model=self.session_model)
        self.notes.extend(warns)
        report = scanner(self.target, cfg, provider=provider)
        self.findings = report.findings
        self.record_coverage(report)
        return report

    def record_coverage(self, report: Report) -> None:
        """Keep a scan's coverage record, deduped, so `/report` can show it.

        A re-scan or an audit re-reports stages it skipped again; the operator
        wants the union of what went unchecked, not the last run's slice of it.
        """
        with self._lock:
            for s in list(report.skipped_stages or []):
                if s not in self.skipped_stages:
                    self.skipped_stages.append(s)
            for n in list(report.notes or []):
                if n not in self.notes:
                    self.notes.append(n)

    def snapshot_report(self) -> Report:
        """The session's findings *and* its coverage, as one Report."""
        with self._lock:
            return Report(target=self.target, findings=list(self.findings),
                          skipped_stages=list(self.skipped_stages),
                          notes=list(self.notes))

    def find(self, finding_id: str) -> Finding | None:
        for f in self.findings:
            if f.id == finding_id or f.fingerprint == finding_id:
                return f
        return None
