"""Incremental-scan helpers.

Serialize/deserialize findings for the cache, derive the per-file content map
from a diff, and cache-or-run a stage so an expensive stage only re-runs when its
inputs actually changed.
"""
from __future__ import annotations

from typing import Callable

from ..findings import ConfirmationStatus, Finding
from ..severity import Severity
from .store import Cache


def finding_to_dict(f: Finding) -> dict:
    return f.to_dict()


def finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d["id"],
        title=d["title"],
        severity=Severity.parse(d["severity"]),
        source=d["source"],
        file=d["file"],
        line=int(d["line"]),
        confidence=float(d.get("confidence", 0.5)),
        confirmation_status=ConfirmationStatus(d.get("confirmation_status", "unconfirmed")),
        category=d.get("category"),
        evidence=d.get("evidence", ""),
        exploit_scenario=d.get("exploit_scenario", ""),
        remediation=d.get("remediation", ""),
        security_sensitive=d.get("security_sensitive"),
        fingerprint=d.get("fingerprint"),
        waived=bool(d.get("waived", False)),
        waived_reason=d.get("waived_reason", ""),
        first_seen=float(d.get("first_seen", 0.0)),
        last_seen=float(d.get("last_seen", 0.0)),
    )


def diff_file_contents(diff) -> dict[str, str]:
    """Per-file content proxy from a diff: the joined added-line text per file.

    Enough to detect 'this file's changed lines are identical to last scan' —
    the granularity static/LLM caching keys on."""
    out: dict[str, str] = {}
    for f in diff.files:
        out[f.path] = "\n".join(t for h in f.hunks for _, t in h.added)
    return out


def cache_or_run(
    cache: Cache,
    key: str,
    run: Callable[[], list[Finding]],
) -> tuple[list[Finding], bool]:
    """Return (findings, hit). On miss, run the stage and store its result."""
    cached = cache.get(key)
    if cached is not None:
        return [finding_from_dict(d) for d in cached], True
    findings = run()
    cache.set(key, [finding_to_dict(f) for f in findings])
    return findings, False


def dynamic_still_valid(cache: Cache, key: str) -> bool:
    """A dynamic (sandbox) result is only reusable if its exact composite key is
    present — a moved lockfile/toolchain/file-set produces a different key."""
    return cache.get(key) is not None
