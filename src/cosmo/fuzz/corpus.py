"""Persistent seed corpus (architecture §7).

Carried forward between campaigns per repo so coverage compounds instead of
resetting each run. One directory per harness under `.cosmo/corpus/`, content-
addressed so re-adding an identical seed is a no-op.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


class SeedCorpus:
    def __init__(self, root: str | Path, harness_name: str):
        self.dir = Path(root) / ".cosmo" / "corpus" / _safe(harness_name)
        self.dir.mkdir(parents=True, exist_ok=True)

    def add(self, data: bytes) -> str:
        """Store a seed; returns its id. Identical content collapses to one file."""
        sid = hashlib.sha256(data).hexdigest()[:16]
        p = self.dir / sid
        if not p.exists():
            p.write_bytes(data)
        return sid

    def seeds(self) -> list[bytes]:
        return [p.read_bytes() for p in sorted(self.dir.iterdir()) if p.is_file()]

    def __len__(self) -> int:
        return sum(1 for p in self.dir.iterdir() if p.is_file())


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name) or "harness"
