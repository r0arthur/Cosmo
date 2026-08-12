"""RISK-01 — a scanned repo's cosmo.yaml can only TIGHTEN safety-tier settings."""
import textwrap

from cosmo.config import load_config


def _write(tmp_path, body: str):
    (tmp_path / "cosmo.yaml").write_text(textwrap.dedent(body))
    return tmp_path


def test_repo_cannot_loosen_sandbox_network(tmp_path):
    # Operator baseline is network: none. Repo tries to open it to bridge.
    _write(tmp_path, """
        sandbox:
          network: bridge
    """)
    cfg = load_config(tmp_path)
    assert cfg.get("sandbox.network") == "none"          # clamped, not loosened
    assert any("network" in w for w in cfg.warnings)


def test_repo_cannot_raise_timeout(tmp_path):
    _write(tmp_path, """
        sandbox:
          timeout_seconds: 999999
    """)
    cfg = load_config(tmp_path)
    assert cfg.get("sandbox.timeout_seconds") == 300     # operator ceiling holds


def test_repo_can_tighten_timeout(tmp_path):
    _write(tmp_path, """
        sandbox:
          timeout_seconds: 60
    """)
    cfg = load_config(tmp_path)
    assert cfg.get("sandbox.timeout_seconds") == 60      # lowering is allowed


def test_repo_cannot_raise_fuzzing_cap(tmp_path):
    _write(tmp_path, """
        fuzzing:
          max_duration: "500h"
    """)
    cfg = load_config(tmp_path)
    assert cfg.get("fuzzing.max_duration") == "8h"       # clamped to operator ceiling


def test_repo_cannot_enable_fuzzing_operator_disabled(tmp_path):
    _write(tmp_path, """
        fuzzing:
          enabled: true
    """)
    cfg = load_config(tmp_path)
    assert cfg.get("fuzzing.enabled") is False           # bool_and: operator False wins


def test_repo_external_targets_ignored(tmp_path):
    _write(tmp_path, """
        external_targets:
          require_scope_declaration: false
    """)
    cfg = load_config(tmp_path)
    assert cfg.get("external_targets.require_scope_declaration") is True  # operator-only


def test_preference_tier_repo_overrides(tmp_path):
    _write(tmp_path, """
        threshold: critical
    """)
    cfg = load_config(tmp_path)
    assert cfg.threshold == "critical"                   # preference: repo wins
