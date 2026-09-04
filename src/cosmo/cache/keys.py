"""Cache-key derivation (RISK: dynamic-cache soundness).

The whole point of this module is that **cache keys differ by stage because
their inputs do**:

  * Static / LLM results key on the changed files' own content (+ a stage/rule/
    prompt version). That's sound — the analysis reads those files.
  * Dynamic (sandbox) results must NOT key on a single file hash. A finding's
    reproducibility depends on dependency versions and cross-file callers, so an
    unchanged file can start or stop reproducing when a lockfile or toolchain
    moves. `dynamic_key` therefore keys on a COMPOSITE: the relevant file set +
    the dependency-lockfile hash + the base-image/toolchain version. Any of them
    moving invalidates the entry.
"""
from __future__ import annotations

import hashlib

STATIC_VERSION = "static-v1"      # bump when the static rule set changes
MODEL_PROMPT_VERSION = "prompt-v1"  # bump when the review prompt changes


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode(errors="replace")).hexdigest()[:16]


def files_digest(file_contents: dict[str, str]) -> str:
    """Order-independent digest of a {path: content} map."""
    h = hashlib.sha256()
    for path in sorted(file_contents):
        h.update(path.encode())
        h.update(b"\0")
        h.update(content_hash(file_contents[path]).encode())
        h.update(b"\n")
    return h.hexdigest()[:16]


def static_key(file_contents: dict[str, str], rule_version: str = STATIC_VERSION) -> str:
    return f"static:{rule_version}:{files_digest(file_contents)}"


def model_key(
    file_contents: dict[str, str],
    model: str,
    context: str = "",
    prompt_version: str = MODEL_PROMPT_VERSION,
) -> str:
    ctx = content_hash(context)
    return f"model:{model}:{prompt_version}:{ctx}:{files_digest(file_contents)}"


def dynamic_key(
    file_contents: dict[str, str],
    lockfile_hash: str,
    toolchain_version: str,
) -> str:
    """Composite key — the load-bearing one. Not a single file hash."""
    return (
        f"dynamic:{toolchain_version}:{lockfile_hash}:{files_digest(file_contents)}"
    )
