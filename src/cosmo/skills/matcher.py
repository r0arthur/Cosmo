"""Skill matcher.

Selects only skills relevant to files actually in the diff before injecting them
into the review prompt — so the model isn't handed rules for code that didn't
change, and the prompt stays small (cost control).
"""
from __future__ import annotations

from .loader import Skill


def match_skills(skills: list[Skill], changed_files: list[str]) -> list[Skill]:
    return [s for s in skills if any(s.matches(f) for f in changed_files)]
