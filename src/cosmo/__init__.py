"""cosmo — Claude-Code-based security review tool.

MVP scope: build steps 1–6 of cosmo-architecture.md (core engine + Claude
default provider, config + trust tiers, diff resolver, output adapters + gate,
waiver/baseline, static pre-filter). Sandbox (§6), fuzzing (§7), and
external-target mode (§9) are deliberately out of scope and not wired in.
"""
from .config import Config, load_config
from .engine import run_review
from .findings import Finding, Report

__version__ = "0.1.0"
__all__ = ["Config", "load_config", "run_review", "Finding", "Report", "__version__"]
