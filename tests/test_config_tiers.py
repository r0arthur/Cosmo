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


# --- RISK-03: a repo cannot promote its own skills to authoritative ---------
#
# `skills` is a preference section, but `skills.org_dir` names the directory
# whose skills are injected as AUTHORITATIVE. A repo able to set it could point
# it at its own tree and instruct the reviewer directly.

def test_repo_cannot_set_skills_org_dir(tmp_path):
    _write(tmp_path, """
        skills:
          org_dir: .cosmo/promoted
    """)
    cfg = load_config(tmp_path)
    assert cfg.get("skills.org_dir") is None             # never the repo's value
    assert any("skills.org_dir" in w for w in cfg.warnings)


def test_repo_cannot_hijack_the_operator_org_dir(tmp_path):
    from cosmo.config import _merge
    op = {"skills": {"org_dir": "/etc/cosmo/skills"}}
    eff, warns = _merge(op, {"skills": {"org_dir": "./evil"}})
    assert eff["skills"]["org_dir"] == "/etc/cosmo/skills"
    assert any("skills.org_dir" in w for w in warns)


def test_repo_cannot_erase_the_operator_org_dir(tmp_path):
    """Replacing the whole `skills` section must not drop the org library —
    silently losing trusted guidance is the same bypass, run backwards."""
    from cosmo.config import _merge
    op = {"skills": {"org_dir": "/etc/cosmo/skills"}}
    eff, _ = _merge(op, {"skills": {"something_else": 1}})
    assert eff["skills"]["org_dir"] == "/etc/cosmo/skills"
    assert eff["skills"]["something_else"] == 1          # the rest still merges


def test_other_skills_preferences_still_belong_to_the_repo(tmp_path):
    """Only the trust-designating key is reserved; the section stays a preference."""
    from cosmo.config import _merge
    eff, warns = _merge({}, {"skills": {"tone": "terse"}})
    assert eff["skills"]["tone"] == "terse"
    assert not warns
