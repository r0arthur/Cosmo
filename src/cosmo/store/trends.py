"""Trend + findings store (architecture §14).

A lightweight SQLite store recording findings and their lifecycle over time per
target: introduced vs. fixed, noisiest rules (feeds the §10 skills loop), and the
disclosure queue (§13). Kept separate from the aggregator — the engine stays
pure; a trigger adapter records each scan here.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..findings import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    target TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    category TEXT,
    source TEXT,
    status TEXT NOT NULL DEFAULT 'open',       -- open | fixed
    confirmation_status TEXT,
    waived INTEGER NOT NULL DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    fixed_at REAL,
    disclosure_status TEXT,                     -- reported|acknowledged|patched|disclosed
    PRIMARY KEY (target, fingerprint)
);
"""


@dataclass
class ScanSummary:
    introduced: int = 0
    reopened: int = 0
    fixed: int = 0
    open_total: int = 0


class TrendStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    @classmethod
    def for_target(cls, target: str) -> "TrendStore":
        p = Path(target)
        p = (p if p.is_dir() else p.parent) / ".cosmo" / "trends.db"
        return cls(p)

    def close(self) -> None:
        self._conn.close()

    # --- recording ----------------------------------------------------------

    def record_scan(self, target: str, findings: list[Finding], now: float | None = None) -> ScanSummary:
        now = now if now is not None else time.time()
        cur = self._conn
        summary = ScanSummary()
        seen_fps = set()

        for f in findings:
            if not f.fingerprint:
                continue
            seen_fps.add(f.fingerprint)
            row = cur.execute(
                "SELECT status FROM findings WHERE target=? AND fingerprint=?",
                (target, f.fingerprint),
            ).fetchone()
            if row is None:
                summary.introduced += 1
                cur.execute(
                    "INSERT INTO findings (target, fingerprint, title, severity, category, "
                    "source, status, confirmation_status, waived, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,'open',?,?,?,?)",
                    (target, f.fingerprint, f.title, str(f.severity), f.category, f.source,
                     f.confirmation_status.value, int(f.waived), now, now),
                )
            else:
                if row["status"] == "fixed":
                    summary.reopened += 1
                cur.execute(
                    "UPDATE findings SET status='open', fixed_at=NULL, last_seen=?, severity=?, "
                    "category=?, confirmation_status=?, waived=?, title=? "
                    "WHERE target=? AND fingerprint=?",
                    (now, str(f.severity), f.category, f.confirmation_status.value,
                     int(f.waived), f.title, target, f.fingerprint),
                )

        # Anything previously open for this target but absent now → fixed.
        open_rows = cur.execute(
            "SELECT fingerprint FROM findings WHERE target=? AND status='open'", (target,)
        ).fetchall()
        for r in open_rows:
            if r["fingerprint"] not in seen_fps:
                summary.fixed += 1
                cur.execute(
                    "UPDATE findings SET status='fixed', fixed_at=? WHERE target=? AND fingerprint=?",
                    (now, target, r["fingerprint"]),
                )

        cur.commit()
        summary.open_total = cur.execute(
            "SELECT COUNT(*) c FROM findings WHERE target=? AND status='open' AND waived=0", (target,)
        ).fetchone()["c"]
        return summary

    # --- queries ------------------------------------------------------------

    def open_findings(self, target: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM findings WHERE target=? AND status='open' AND waived=0 "
            "ORDER BY severity DESC", (target,)
        ).fetchall()

    def weekly_trend(self, target: str) -> dict[str, dict[str, int]]:
        """{iso-week: {introduced, fixed}} from first_seen / fixed_at."""
        out: dict[str, dict[str, int]] = {}

        def bucket(ts: float) -> str:
            d = datetime.fromtimestamp(ts, tz=timezone.utc).isocalendar()
            return f"{d.year}-W{d.week:02d}"

        for r in self._conn.execute(
            "SELECT first_seen, fixed_at FROM findings WHERE target=?", (target,)
        ):
            if r["first_seen"]:
                out.setdefault(bucket(r["first_seen"]), {"introduced": 0, "fixed": 0})["introduced"] += 1
            if r["fixed_at"]:
                out.setdefault(bucket(r["fixed_at"]), {"introduced": 0, "fixed": 0})["fixed"] += 1
        return dict(sorted(out.items()))

    def noisiest_rules(self, target: str, min_samples: int = 3) -> list[tuple[str, int, float]]:
        """(category, samples, waived_fraction) for categories judged noisy. Feeds §10."""
        rows = self._conn.execute(
            "SELECT category, COUNT(*) n, SUM(waived) w FROM findings "
            "WHERE target=? AND category IS NOT NULL GROUP BY category", (target,)
        ).fetchall()
        out = [(r["category"], r["n"], (r["w"] or 0) / r["n"]) for r in rows if r["n"] >= min_samples]
        return sorted(out, key=lambda x: x[2], reverse=True)

    def upsert(self, target: str, f: Finding, now: float | None = None) -> None:
        """Insert or refresh a single finding without the absent-as-fixed sweep
        that `record_scan` performs. Used by the disclosure workflow (§13) to
        ensure a finding is tracked before a status is attached to it."""
        now = now if now is not None else time.time()
        if not f.fingerprint:
            return
        exists = self._conn.execute(
            "SELECT 1 FROM findings WHERE target=? AND fingerprint=?",
            (target, f.fingerprint)).fetchone()
        if exists:
            self._conn.execute(
                "UPDATE findings SET last_seen=?, severity=?, category=?, "
                "confirmation_status=?, waived=?, title=? WHERE target=? AND fingerprint=?",
                (now, str(f.severity), f.category, f.confirmation_status.value,
                 int(f.waived), f.title, target, f.fingerprint))
        else:
            self._conn.execute(
                "INSERT INTO findings (target, fingerprint, title, severity, category, "
                "source, status, confirmation_status, waived, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,'open',?,?,?,?)",
                (target, f.fingerprint, f.title, str(f.severity), f.category, f.source,
                 f.confirmation_status.value, int(f.waived), now, now))
        self._conn.commit()

    # --- disclosure queue (§13) --------------------------------------------

    def set_disclosure_status(self, target: str, fingerprint: str, status: str) -> None:
        self._conn.execute(
            "UPDATE findings SET disclosure_status=? WHERE target=? AND fingerprint=?",
            (status, target, fingerprint),
        )
        self._conn.commit()

    def disclosure_queue(self, target: str | None = None) -> list[sqlite3.Row]:
        if target:
            return self._conn.execute(
                "SELECT * FROM findings WHERE disclosure_status IS NOT NULL AND target=?", (target,)
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM findings WHERE disclosure_status IS NOT NULL"
        ).fetchall()
