"""cosmo — Claude-Code-based security review and zero-day discovery tool.

The full architecture (build steps 1–20 of cosmo-architecture.md): core engine +
multi-model provider layer, config trust tiers (§15), diff resolver, output
adapters + fail-closed public-comment gate (§11), waiver/baseline, static
pre-filter, the single egress broker (§9a), dynamic sandbox confirmation (§6),
skills + context ingestion, incremental scanning, git-hook and GitHub Action
adapters, trend store + compliance mapping (§14), manual fuzzing (§7), the
interactive command layer (§7), coordinated disclosure (§13), authorized
external-target mode (§9), and Claude Code plugin/skill integration (§17).
Cosmo reuses Claude Code's auth/session/tool-use; it does not fork it.
"""
from .config import Config, load_config
from .engine import run_review
from .findings import Finding, Report

__version__ = "0.1.0"
__all__ = ["Config", "load_config", "run_review", "Finding", "Report", "__version__"]
