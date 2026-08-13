"""Context ingestion (architecture §4, build step 11).

Reads issues/comments/discussions to prioritize review. Produces a structured
signal set (never raw untrusted text, never ground truth) that nudges finding
prioritization and surfaces partial-fix hints. Reading only — never posts (§12).
"""
from .extract import ExtractedSignal, extract_all, extract_signal
from .ingest import ContextItem, fetch_context, repo_of
from .prioritize import PrioritySignals, apply_prioritization, build_priority_signals

__all__ = [
    "ContextItem", "fetch_context", "repo_of",
    "ExtractedSignal", "extract_signal", "extract_all",
    "PrioritySignals", "build_priority_signals", "apply_prioritization",
]
