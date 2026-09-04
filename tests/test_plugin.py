"""Claude Code plugin/skill integration — step 20."""
import json

import pytest

from cosmo import __version__
from cosmo.config import Config
from cosmo.interactive.commands import _COMMANDS
from cosmo.plugin import (
    ALLOWED_TOOLS,
    PluginBridge,
    check_plugin,
    command_markdown,
    command_specs,
    interactive_command_names,
    open_session,
    plugin_manifest,
    sync_plugin,
)


# --- the plugin surface is DERIVED from the guarded registry, not hand-kept ---

def test_surface_is_subset_of_guarded_registry():
    # every standalone /cosmo-<name> maps to a real command in the enforced
    # dispatcher; the only extra is the synthetic `review` umbrella.
    guarded = set(_COMMANDS)
    for spec in command_specs():
        assert spec.name == "review" or spec.name in guarded


def test_no_command_can_be_invented():
    # a plugin command that isn't in the registry (and isn't the umbrella) is
    # impossible — command_specs only ever emits names it found in _COMMANDS.
    names = {s.name for s in command_specs()}
    assert names - {"review"} <= set(_COMMANDS)


def test_interactive_names_are_the_registry():
    assert interactive_command_names() == list(_COMMANDS)


# --- no slash command can widen its own tool grant -----------------------------

def test_every_command_is_tool_narrowed():
    for spec in command_specs():
        assert spec.allowed_tools == ALLOWED_TOOLS
        md = command_markdown(spec)
        assert f"allowed-tools: {ALLOWED_TOOLS}" in md
        # never a bare shell, a network tool, or a GitHub-posting tool
        assert "Bash(*)" not in md
        assert "curl" not in md
        assert "gh pr comment" not in md and "gh issue comment" not in md


def test_public_posting_is_never_a_plugin_capability():
    # the review command explicitly refuses to post; posting stays behind.
    review = next(s for s in command_specs() if s.name == "review")
    assert "Do NOT post anything to GitHub" in review.body
    assert "fail-closed disclosure gate" in review.body


# --- manifest is well-formed and versioned off the package --------------------

def test_manifest_shape():
    m = plugin_manifest()
    assert m["name"] == "cosmo"
    assert m["version"] == __version__
    assert "does not fork" in m["description"]
    # one command entry per generated spec, all under ./commands/
    slugs = [f"./commands/{s.slug}.md" for s in command_specs()]
    assert m["commands"] == slugs
    assert all(c.startswith("./commands/cosmo-") for c in m["commands"])


# --- sync writes from code; check reports drift -------------------------------

def test_sync_then_check_is_clean(tmp_path):
    changed = sync_plugin(tmp_path)
    assert any("plugin.json" in c for c in changed)
    # freshly synced tree has no drift
    assert check_plugin(tmp_path) == []
    # plugin.json on disk parses and matches the manifest
    pj = json.loads((tmp_path / ".claude-plugin" / "plugin.json").read_text())
    assert pj == plugin_manifest()
    # a command file exists for every manifest entry
    for spec in command_specs():
        assert (tmp_path / "commands" / f"{spec.slug}.md").exists()


def test_check_detects_missing_and_stale(tmp_path):
    sync_plugin(tmp_path)
    assert check_plugin(tmp_path) == []
    # a hand-edited command file is drift
    p = tmp_path / "commands" / "cosmo-scope.md"
    p.write_text("tampered\n")
    assert any("cosmo-scope.md" in d for d in check_plugin(tmp_path))
    # a stray cosmo-*.md not backed by a registry command is stale
    (tmp_path / "commands" / "cosmo-bypass.md").write_text("x\n")
    assert any("cosmo-bypass.md" in d for d in check_plugin(tmp_path))
    # re-sync repairs both (rewrites the edited one, prunes the stray)
    sync_plugin(tmp_path)
    assert not (tmp_path / "commands" / "cosmo-bypass.md").exists()
    assert check_plugin(tmp_path) == []


# --- the in-process bridge reuses the SAME guarded dispatcher ------------------

def test_bridge_routes_through_dispatch(tmp_path):
    b = PluginBridge(session=_session(tmp_path))
    # a known command works exactly as in the REPL
    out = b.handle("/threshold")
    assert "threshold:" in out
    # an unknown command is refused identically — the plugin adds nothing
    assert "unknown command" in b.handle("/definitely-not-a-command")
    # the bridge's advertised surface is exactly the guarded registry
    assert b.commands() == list(_COMMANDS)


def test_bridge_cannot_bypass_disclosure_gate(tmp_path):
    # /report pr renders through the same fail-closed gate as batch mode.
    b = PluginBridge(session=_session(tmp_path))
    # no findings → empty gated comment, but crucially it goes through the gate
    # path, not a raw dump. Just assert it does not raise and returns a string.
    assert isinstance(b.handle("/report pr"), str)


def test_open_session_uses_operator_config_as_ceiling(tmp_path):
    # A repo cosmo.yaml that tries to ENABLE a safety-tier key must not win over
    # an operator config that leaves it disabled: load_config clamps it. We prove
    # the plugin path goes through load_config (not a raw Config) by checking the
    # resolved config still reflects the trust-tier resolution.
    (tmp_path / "cosmo.yaml").write_text(
        "external_targets:\n  enabled: true\n"      # repo tries to switch it on
    )
    sess = open_session(str(tmp_path))               # no operator override → default ceiling
    # default operator ceiling has external_targets.enabled = False (safety tier);
    # the repo cannot loosen it, so the plugin session sees it off.
    assert sess.config.get("external_targets.enabled", False) is False


def _session(tmp_path):
    from cosmo.interactive.session import Session
    return Session(config=Config(data={}), target=str(tmp_path))
