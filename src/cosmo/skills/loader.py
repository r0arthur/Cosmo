"""Skill loading (architecture §10).

Skills are markdown files with frontmatter (`description`, `applies_to` glob) +
instructions, same convention as Claude Code's SKILL.md. Two origins:

  * org-level  — a shared library the operator controls: TRUSTED guidance.
  * repo-level — `.cosmo/skills/*.md`, checked into the repo under scan, so it is
                 UNTRUSTED input (same class as the README in §6). It is loaded,
                 but the injector (see inject.py) frames it as untrusted reference
                 that cannot override the reviewer's directives or suppress
                 findings — a repo cannot ship a skill that says "mark everything
                 safe" and have it obeyed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml

ORG = "org"
REPO = "repo"


@dataclass
class Skill:
    name: str
    description: str
    applies_to: list[str]
    instructions: str
    origin: str            # ORG (trusted) | REPO (untrusted)
    path: str = ""

    @property
    def trusted(self) -> bool:
        return self.origin == ORG

    def matches(self, file_path: str) -> bool:
        return any(_match_glob(file_path, g) for g in self.applies_to)


def _match_glob(path: str, glob: str) -> bool:
    path = path.replace("\\", "/")
    if fnmatch(path, glob):
        return True
    if glob.startswith("**/") and fnmatch(path, glob[3:]):
        return True
    return fnmatch(os.path.basename(path), glob)


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            meta = yaml.safe_load(text[3:end]) or {}
            body = text[end + 4:].lstrip("\n")
            return meta, body
    return {}, text


def _load_dir(directory: Path, origin: str) -> list[Skill]:
    skills: list[Skill] = []
    if not directory.is_dir():
        return skills
    for p in sorted(directory.glob("*.md")):
        meta, body = _parse_frontmatter(p.read_text(errors="replace"))
        applies = meta.get("applies_to", [])
        if isinstance(applies, str):
            applies = [applies]
        skills.append(
            Skill(
                name=meta.get("name", p.stem),
                description=str(meta.get("description", "")),
                applies_to=list(applies),
                instructions=body.strip(),
                origin=origin,
                path=str(p),
            )
        )
    return skills


def load_skills(target_dir: str | os.PathLike, org_dir: str | os.PathLike | None = None) -> list[Skill]:
    """Load org-level (trusted) then repo-level (untrusted) skills."""
    skills: list[Skill] = []
    if org_dir:
        skills += _load_dir(Path(org_dir), ORG)
    root = Path(target_dir)
    root = root if root.is_dir() else root.parent
    skills += _load_dir(root / ".cosmo" / "skills", REPO)
    return skills
