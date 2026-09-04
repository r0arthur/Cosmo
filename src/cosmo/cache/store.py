"""Persistent cache store.

A lightweight JSON-backed key→value store at <target>/.cosmo/cache.json. The
findings/trend store (SQLite) is build step 14; this is just the
incremental-scan cache, kept simple and inspectable. Lives under .cosmo/, which
is gitignored, so it never lands in the scanned repo.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Cache:
    path: Path
    data: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def load(cls, target_dir: str, enabled: bool = True) -> "Cache":
        p = Path(target_dir)
        p = (p if p.is_dir() else p.parent) / ".cosmo" / "cache.json"
        data: dict[str, Any] = {}
        if enabled and p.is_file():
            try:
                data = json.loads(p.read_text())
            except (ValueError, OSError):
                data = {}
        return cls(path=p, data=data, enabled=enabled)

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        return self.data.get(key)

    def set(self, key: str, value: Any) -> None:
        if self.enabled:
            self.data[key] = value

    def save(self) -> bool:
        """Persist the cache. Best-effort: the cache is a performance optimization,
        so an unwritable target (read-only mount, missing dir, no permission) must
        never crash the review — it just means no incremental speedup next time.
        Returns True if written, False if skipped/failed."""
        if not self.enabled:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2))
            return True
        except OSError:
            return False
