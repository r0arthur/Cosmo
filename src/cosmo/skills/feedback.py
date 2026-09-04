"""Skills enhancement feedback loop.

Tracks per-skill confirmation rate over time, and when a skill proves noisy it
DRAFTS a proposed edit — never a silent auto-edit. Proposals are meant to go
through normal PR review, since skills live in git. Low-noise repo skills are
flagged as candidates for promotion to the org-level library.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .loader import ORG, REPO, Skill


@dataclass
class SkillStats:
    name: str
    origin: str
    matched: int = 0
    confirmed: int = 0        # finding attributed to this skill, confirmed / accepted
    false_positive: int = 0   # finding attributed to this skill, dismissed / not-reproducible

    @property
    def judged(self) -> int:
        return self.confirmed + self.false_positive

    @property
    def confirmation_rate(self) -> float | None:
        return self.confirmed / self.judged if self.judged else None


@dataclass
class SkillEditProposal:
    """A DRAFT change to a skill file. Never written to disk — applied via PR."""

    skill_name: str
    path: str
    rationale: str
    suggested_change: str


@dataclass
class SkillFeedback:
    stats: dict[str, SkillStats] = field(default_factory=dict)

    def _stat(self, skill: Skill) -> SkillStats:
        return self.stats.setdefault(skill.name, SkillStats(skill.name, skill.origin))

    def record_match(self, skill: Skill) -> None:
        self._stat(skill).matched += 1

    def record_outcome(self, skill: Skill, confirmed: bool) -> None:
        s = self._stat(skill)
        if confirmed:
            s.confirmed += 1
        else:
            s.false_positive += 1

    def noisy_skills(self, min_samples: int = 5, max_rate: float = 0.5) -> list[SkillStats]:
        return [
            s for s in self.stats.values()
            if s.judged >= min_samples and (s.confirmation_rate or 0.0) < max_rate
        ]

    def promotion_candidates(self, min_samples: int = 5, min_rate: float = 0.8) -> list[SkillStats]:
        return [
            s for s in self.stats.values()
            if s.origin == REPO and s.judged >= min_samples and (s.confirmation_rate or 0.0) >= min_rate
        ]

    def propose_tuning(self, skill: Skill) -> SkillEditProposal:
        """Draft (do not write) a tuning proposal for a noisy skill."""
        s = self._stat(skill)
        rate = s.confirmation_rate
        rate_str = f"{rate:.0%}" if rate is not None else "n/a"
        return SkillEditProposal(
            skill_name=skill.name,
            path=skill.path,
            rationale=(
                f"Skill {skill.name!r} has a {rate_str} confirmation rate over {s.judged} "
                f"judged findings ({s.false_positive} dismissed). Consider narrowing its "
                f"pattern/scope or retiring it."
            ),
            suggested_change=(
                "# PROPOSED (review via PR — not applied automatically)\n"
                f"# Tighten `applies_to` or the detection guidance in {skill.path} to reduce "
                f"false positives, or retire the rule if it stays noisy after tuning."
            ),
        )
