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
    external=None                              # /scope — lazily created ExternalTargetMode
    # Injected so the REPL stays hermetic in tests; defaults to the real engine.
    scanner=None
    confirmer=None

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
        return report

    def find(self, finding_id: str) -> Finding | None:
        for f in self.findings:
            if f.id == finding_id or f.fingerprint == finding_id:
                return f
        return None
