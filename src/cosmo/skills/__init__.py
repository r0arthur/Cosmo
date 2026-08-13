"""Skills system (architecture §10, build step 10).

Repo- and org-level skill files, a matcher that injects only skills relevant to
the changed files, a trusted/untrusted split so repo-provided skills can't
override the reviewer, and an enhancement loop that proposes (never auto-applies)
edits to noisy skills.
"""
from .feedback import SkillEditProposal, SkillFeedback, SkillStats
from .inject import build_skill_context
from .loader import ORG, REPO, Skill, load_skills
from .matcher import match_skills

__all__ = [
    "Skill", "ORG", "REPO", "load_skills", "match_skills", "build_skill_context",
    "SkillFeedback", "SkillStats", "SkillEditProposal",
]
