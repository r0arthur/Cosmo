"""Configuration loading with the two-tier trust model (architecture §15/§16, RISK-01).

A scanned repo is UNTRUSTED input, and `cosmo.yaml` is checked into that repo.
So config resolves under two opposite rules:

  * Preference tier (threshold, ignore_paths, providers, ...): repo overrides
    operator, per the §8 resolution order. Harmless.
  * Safety tier (sandbox.* isolation and caps, fuzzing.*, external_targets.*,
    disclosure.*, triggers.*): operator/org is the ceiling. A repo may only
    *tighten* a safety key, never loosen it — enforced here at config-load by
    clamping every repo value against the operator baseline.

Without this, a malicious repo ships `sandbox: {network: bridge}` and relaxes
the very isolation that exists to contain it.
"""
from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

PREFERENCE_SECTIONS = {
    "threshold", "ignore_paths", "providers", "context_ingestion", "output", "skills",
}
# Keys that sit inside a PREFERENCE section but designate TRUST rather than
# taste, so a scanned repo may not set them.
#
# `skills.org_dir` names the directory whose skills are injected as
# *authoritative* guidance. A repo able to set it could point it at its own
# `.cosmo/` and promote its skills out of the untrusted section — handing the
# code under audit a direct channel to instruct the reviewer ("ignore all
# findings here"). That is exactly the override RISK-03 exists to prevent, so the
# key is operator-only and the operator's value survives a repo `skills` block.
OPERATOR_ONLY_PREFERENCE_KEYS: dict[str, set[str]] = {
    "skills": {"org_dir"},
}

SAFETY_SECTIONS = {
    "sandbox", "fuzzing", "external_targets", "disclosure", "triggers", "providers_policy",
    # Third-party extensions run in-process, so *enabling* one is a full-trust act
    # the operator must make — a scanned repo can never enable or add an extension.
    "extensions",
    # The whole-project LLM-audit call budget is a cost guard: the operator caps
    # how many files an audit sends to the model; a repo may only lower the cap.
    "llm_audit",
    # Same guard for a commit-history sweep — one model call per commit makes it
    # the most expensive thing cosmo can run.
    "history",
}

# Data-sensitivity ranked (higher = more restrictive). A repo may only raise it.
_SENSITIVITY_RANK = {"normal": 0, "sensitive": 1}

# Network modes ranked by restrictiveness (higher = more restrictive/safer).
_NETWORK_RANK = {"none": 3, "internal": 2, "bridge": 1, "host": 0}


def _parse_duration(value: Any) -> int:
    """'8h' -> 28800, '30m' -> 1800, 300 -> 300. Seconds."""
    if isinstance(value, (int, float)):
        return int(value)
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(value))
    if not m:
        raise ValueError(f"bad duration: {value!r}")
    n, unit = int(m.group(1)), m.group(2) or "s"
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


# A clamp takes (operator_value, repo_value) and returns (effective, was_clamped).
Clamp = Callable[[Any, Any], "tuple[Any, bool]"]


def _clamp_min(op: Any, repo: Any) -> tuple[Any, bool]:
    """Repo may only lower a numeric cap."""
    if repo <= op:
        return repo, False
    return op, True


def _clamp_duration_min(op: Any, repo: Any) -> tuple[Any, bool]:
    if _parse_duration(repo) <= _parse_duration(op):
        return repo, False
    return op, True


def _clamp_bool_and(op: Any, repo: Any) -> tuple[Any, bool]:
    """Repo may turn a capability off, never on."""
    eff = bool(op) and bool(repo)
    return eff, (bool(repo) and not eff)


def _clamp_network(op: Any, repo: Any) -> tuple[Any, bool]:
    """Repo may only choose an equal-or-more-restrictive network mode."""
    if _NETWORK_RANK.get(str(repo), -1) >= _NETWORK_RANK.get(str(op), 99):
        return repo, False
    return op, True


def _clamp_sensitivity(op: Any, repo: Any) -> tuple[Any, bool]:
    """Repo may only raise data sensitivity (tighten), never lower it."""
    if _SENSITIVITY_RANK.get(str(repo), -1) >= _SENSITIVITY_RANK.get(str(op), 99):
        return repo, False
    return op, True


# Only these safety keys accept a repo value at all (by tightening). Every other
# key under a safety section is operator-only: a repo value is ignored + warned.
CLAMP_RULES: dict[str, Clamp] = {
    "sandbox.enabled": _clamp_bool_and,
    "sandbox.confirmation": _clamp_bool_and,
    "sandbox.network": _clamp_network,
    "sandbox.timeout_seconds": _clamp_min,
    "fuzzing.enabled": _clamp_bool_and,
    "fuzzing.max_duration": _clamp_duration_min,
    "fuzzing.confirm_above": _clamp_duration_min,
    # A repo may raise data sensitivity (tighten); sensitive_allowed_vendors is operator-only.
    "providers_policy.data_sensitivity": _clamp_sensitivity,
    # A repo may only lower the whole-project audit's per-run file/call budget.
    "llm_audit.max_files": _clamp_min,
    # ...and only lower how many of those calls are in flight at once. Raising it
    # is the operator's call: burst rate is what trips a provider's rate limit.
    "llm_audit.concurrency": _clamp_min,
    # A repo may only lower how many commits one history sweep reviews.
    "history.max_commits": _clamp_min,
}


@dataclass
class Config:
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def threshold(self) -> str:
        return self.data.get("threshold", "medium")

    @property
    def ignore_paths(self) -> list[str]:
        return list(self.data.get("ignore_paths", []) or [])

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


def _merge(operator: dict, repo: dict) -> tuple[dict, list[str]]:
    effective = copy.deepcopy(operator)
    warnings: list[str] = []

    # Preference tier: repo overrides operator.
    for key in PREFERENCE_SECTIONS:
        if key in repo:
            value = copy.deepcopy(repo[key])
            reserved = OPERATOR_ONLY_PREFERENCE_KEYS.get(key, set())
            if reserved and isinstance(value, dict):
                op_section = effective.get(key)
                for rk in sorted(reserved):
                    if rk in value:
                        del value[rk]
                        warnings.append(
                            f"'{key}.{rk}' from repo ignored (operator-only: it "
                            f"designates trust, not preference)")
                    # A repo `skills` block must not erase the operator's org
                    # library either — replacing the section would drop it.
                    if isinstance(op_section, dict) and rk in op_section:
                        value[rk] = op_section[rk]
            effective[key] = value
    if "threshold" in repo:  # scalar, also a preference
        effective["threshold"] = repo["threshold"]

    # Safety tier: operator is the ceiling; repo may only tighten defined keys.
    for section in SAFETY_SECTIONS:
        repo_section = repo.get(section)
        if not isinstance(repo_section, dict):
            if repo_section is not None:
                warnings.append(f"safety-tier '{section}' from repo ignored (operator-only)")
            continue
        op_section = effective.setdefault(section, {})
        for key, repo_val in repo_section.items():
            dotted = f"{section}.{key}"
            clamp = CLAMP_RULES.get(dotted)
            if clamp is None:
                warnings.append(
                    f"safety-tier '{dotted}' from repo ignored (operator-only; no tightening rule)"
                )
                continue
            op_val = op_section.get(key)
            if op_val is None:  # operator didn't set a ceiling → nothing to tighten against
                warnings.append(f"safety-tier '{dotted}' from repo ignored (no operator baseline)")
                continue
            eff_val, clamped = clamp(op_val, repo_val)
            op_section[key] = eff_val
            if clamped:
                warnings.append(
                    f"safety-tier '{dotted}': repo value {repo_val!r} would loosen the "
                    f"operator ceiling {op_val!r} — clamped to {eff_val!r}"
                )
    return effective, warnings


def _load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


# Baked-in operator defaults. In a real deployment these come from the operator/org
# environment (COSMO_OPERATOR_CONFIG), never from the repo under scan.
BUILTIN_OPERATOR_DEFAULTS: dict[str, Any] = {
    "threshold": "medium",
    "providers": {"claude": {"default": True}},
    "sandbox": {"enabled": True, "network": "none", "timeout_seconds": 300, "confirmation": True},
    "fuzzing": {"enabled": False, "max_duration": "8h", "confirm_above": "4h"},
    "external_targets": {"enabled": False, "require_scope_declaration": True,
                         "rate_limit_source": "scope_declared"},
    "disclosure": {"contact": "security.md", "embargo_days": 90},
    "providers_policy": {"data_sensitivity": "normal", "sensitive_allowed_vendors": []},
    # Custom skills/detectors/commands. `paths`/entry-points are *discovered*, but
    # only names in `enabled` are *activated* (imported + run). `reference_only`
    # loads an enabled extension's skills as UNTRUSTED reference (RISK-03).
    "extensions": {"enabled": [], "paths": [], "reference_only": []},
    # Whole-project LLM audit (`cosmo review --audit`): max files sent to the model
    # in one run, and how many of those reviews run at once. Operator ceilings; a
    # repo may only lower either. See cosmo.audit.
    "llm_audit": {"max_files": 50, "concurrency": 4},
    # Commit-history sweep (`cosmo history`): commits reviewed in one run. One
    # model call per commit, so this is the sharpest cost ceiling cosmo has.
    # Concurrency is shared with llm_audit — it is the same resource.
    "history": {"max_commits": 200},
}


def load_config(target_dir: str | os.PathLike, operator_config: str | os.PathLike | None = None) -> Config:
    """Resolve operator config (the ceiling) with the target repo's cosmo.yaml.

    Precedence and clamping follow §15: preference keys repo-over-operator,
    safety keys operator-only with repo values clamped to tighten-only.
    """
    operator = copy.deepcopy(BUILTIN_OPERATOR_DEFAULTS)
    op_path = operator_config or os.environ.get("COSMO_OPERATOR_CONFIG")
    if op_path:
        # Operator config MAY loosen defaults — it is the trusted tier.
        for k, v in _load_yaml(Path(op_path)).items():
            if isinstance(v, dict) and isinstance(operator.get(k), dict):
                operator[k].update(v)
            else:
                operator[k] = v

    repo = _load_yaml(Path(target_dir) / "cosmo.yaml")
    effective, warnings = _merge(operator, repo)
    return Config(data=effective, warnings=warnings)
