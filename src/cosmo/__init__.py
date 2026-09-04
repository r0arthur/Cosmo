"""cosmo — security review and zero-day discovery tool.

Model-pluggable: Claude is the default and the fallback, but the provider
layer also drives Codex, DeepSeek, and a local Llama endpoint, and the
data-governance gate exists so a sensitive repo can be pinned to a local model.
cosmo additionally *ships as* a Claude Code plugin — that is a distribution
surface, not a requirement.

The full architecture (build steps 1–20 of cosmo-architecture.md): core engine +
multi-model provider layer, config trust tiers, diff resolver, output
adapters + fail-closed public-comment gate, waiver/baseline, static
pre-filter, the single egress broker, dynamic sandbox confirmation,
skills + context ingestion, incremental scanning, git-hook and GitHub Action
adapters, trend store + compliance mapping, manual fuzzing, the
interactive command layer, coordinated disclosure, authorized
external-target mode, and Claude Code plugin/skill integration.
Cosmo reuses Claude Code's auth/session/tool-use; it does not fork it.
"""
from .config import Config, load_config
from .engine import run_review
from .findings import Finding, Report

__version__ = "0.1.0"
__all__ = ["Config", "load_config", "run_review", "Finding", "Report", "__version__"]
