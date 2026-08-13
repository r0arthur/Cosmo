"""Incremental scanning cache (architecture §15, build step 12).

Caches expensive stage results so only what changed since the last scan of a
branch is re-run. Cache keys differ by stage: static/LLM key on the changed
files' content; dynamic keys on a composite (file set + lockfile + toolchain).
Prerequisite for the git-hook adapter (step 13) to be fast enough to run inline.
"""
from .incremental import (
    cache_or_run,
    diff_file_contents,
    dynamic_still_valid,
    finding_from_dict,
    finding_to_dict,
)
from .keys import (
    MODEL_PROMPT_VERSION,
    STATIC_VERSION,
    content_hash,
    dynamic_key,
    files_digest,
    model_key,
    static_key,
)
from .store import Cache

__all__ = [
    "Cache",
    "content_hash", "files_digest", "static_key", "model_key", "dynamic_key",
    "STATIC_VERSION", "MODEL_PROMPT_VERSION",
    "cache_or_run", "diff_file_contents", "dynamic_still_valid",
    "finding_to_dict", "finding_from_dict",
]
