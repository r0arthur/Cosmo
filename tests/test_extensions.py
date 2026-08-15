"""Custom extensions — plugins & skills for cosmo."""
import textwrap

import pytest

from cosmo.config import Config, load_config
from cosmo.extensions import (
    Extension,
    LoadedExtensions,
    discover,
    load_enabled,
    normalize_extension_findings,
)
from cosmo.findings import Finding
from cosmo.severity import Severity


# --- fixtures: a local extension dir + config wiring --------------------------

_EXT_SRC = textwrap.dedent('''
    from cosmo.extensions import Extension
    from cosmo.findings import Finding
    from cosmo.severity import Severity
    from cosmo.skills.loader import Skill

    RAN = []  # module-level marker: proves whether the module was imported

    def _detect(target, config):
        return [Finding(id="x1", title="ext finding", severity=Severity.HIGH,
                        source="whatever", file="a.py", line=3, category="CWE-1")]

    def _cmd(session, args):
        return "x-hello ran"

    COSMO_EXTENSION = Extension(
        name="demo", version="9.9", description="demo ext",
        skills=[Skill(name="demo-skill", description="d", applies_to=["**/*.py"],
                      instructions="look harder", origin="pending")],
        detectors={"d": _detect},
        commands={"hello": _cmd},
    )
''')

# An extension whose import has a side effect we can observe — to prove a
# DISABLED extension is never imported.
_SIDEEFFECT_SRC = textwrap.dedent('''
    from pathlib import Path
    Path(__file__).with_name("IMPORTED").write_text("yes")
    from cosmo.extensions import Extension
    COSMO_EXTENSION = Extension(name="sideeffect")
''')


def _write_ext(tmp_path, name, src):
    d = tmp_path / name
    d.mkdir()
    (d / "cosmo_extension.py").write_text(src)
    return d


def _cfg(paths, enabled=(), reference_only=()):
    return Config(data={"extensions": {
        "paths": [str(p) for p in paths],
        "enabled": list(enabled),
        "reference_only": list(reference_only),
    }})


# --- discovery ≠ activation (the load-bearing safety property) ----------------

def test_discovery_does_not_import(tmp_path):
    d = _write_ext(tmp_path, "sideeffect", _SIDEEFFECT_SRC)
    cfg = _cfg([d])                       # discovered, NOT enabled
    found = discover(cfg)
    assert [x.name for x in found] == ["sideeffect"]
    # discover() must not have executed the module's top-level code
    assert not (d / "IMPORTED").exists()


def test_disabled_extension_is_never_run(tmp_path):
    d = _write_ext(tmp_path, "sideeffect", _SIDEEFFECT_SRC)
    loaded = load_enabled(_cfg([d]))      # enabled list is empty
    assert loaded.active == []
    assert "sideeffect" in loaded.disabled
    assert not (d / "IMPORTED").exists()  # proven inert


def test_enabling_activates(tmp_path):
    d = _write_ext(tmp_path, "demo", _EXT_SRC)
    loaded = load_enabled(_cfg([d], enabled=["demo"]))
    assert [e.name for e in loaded.active] == ["demo"]
    assert loaded.disabled == []


# --- a scanned repo can NEVER enable an extension (config trust tier) ----------

def test_repo_cannot_enable_extension(tmp_path):
    # operator config leaves extensions.enabled empty; the scanned repo tries to
    # enable one via its own cosmo.yaml. The safety tier must ignore it.
    ext_dir = _write_ext(tmp_path, "demo", _EXT_SRC)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "cosmo.yaml").write_text(textwrap.dedent(f'''
        extensions:
          paths: ["{ext_dir}"]
          enabled: ["demo"]
    '''))
    cfg = load_config(str(repo))          # no operator override
    assert cfg.get("extensions.enabled", []) == []      # repo value clamped away
    assert any("extensions" in w for w in cfg.warnings)
    assert load_enabled(cfg).active == []               # so nothing activates


def test_operator_can_enable_extension(tmp_path):
    ext_dir = _write_ext(tmp_path, "demo", _EXT_SRC)
    repo = tmp_path / "repo"
    repo.mkdir()
    op = tmp_path / "operator.yaml"
    op.write_text(textwrap.dedent(f'''
        extensions:
          paths: ["{ext_dir}"]
          enabled: ["demo"]
    '''))
    cfg = load_config(str(repo), operator_config=str(op))
    assert cfg.get("extensions.enabled", []) == ["demo"]
    assert [e.name for e in load_enabled(cfg).active] == ["demo"]


# --- custom commands can't impersonate a guarded builtin ----------------------

def test_extension_commands_are_namespaced(tmp_path):
    d = _write_ext(tmp_path, "demo", _EXT_SRC)
    loaded = load_enabled(_cfg([d], enabled=["demo"]))
    table = loaded.command_table()
    assert "x-hello" in table               # namespaced
    assert "hello" not in table             # never the bare name


def test_builtin_wins_over_extension_of_same_name(tmp_path):
    # An extension that tries to register a command named "report" still only
    # surfaces as /x-report; /report stays the guarded builtin.
    src = _EXT_SRC.replace('commands={"hello": _cmd}', 'commands={"report": _cmd}')
    d = _write_ext(tmp_path, "shadow", src)
    from cosmo.interactive import Session, dispatch
    from cosmo.interactive.commands import _COMMANDS
    s = Session(config=_cfg([d], enabled=["shadow"]), target=str(tmp_path))
    # /report resolves to the guarded builtin, not the extension handler
    out = dispatch(s, "/report")
    assert out != "x-hello ran" and "x-hello" not in out
    assert _COMMANDS["report"].__name__ == "_cmd_report"
    # the extension command is reachable only under its namespace
    assert dispatch(s, "/x-report") == "x-hello ran"


def test_dispatch_runs_extension_command(tmp_path):
    d = _write_ext(tmp_path, "demo", _EXT_SRC)
    from cosmo.interactive import Session, dispatch
    s = Session(config=_cfg([d], enabled=["demo"]), target=str(tmp_path))
    assert dispatch(s, "/x-hello") == "x-hello ran"
    assert "unknown command" in dispatch(s, "/x-nope")


# --- custom findings are forced through the shared shape ----------------------

def test_detector_output_normalized_and_stamped():
    good = [Finding(id="a", title="t", severity=Severity.LOW, source="raw",
                    file="f", line=1)]
    out = normalize_extension_findings("demo", good)
    assert out[0].source == "ext:demo"      # provenance re-stamped, un-spoofable


def test_detector_returning_non_finding_is_rejected():
    with pytest.raises(TypeError):
        normalize_extension_findings("demo", [{"not": "a finding"}])


def test_broken_extension_does_not_crash_load(tmp_path):
    d = _write_ext(tmp_path, "broken", "raise RuntimeError('boom')\n")
    loaded = load_enabled(_cfg([d], enabled=["broken"]))
    assert loaded.active == []
    assert "broken" in loaded.errors and "boom" in loaded.errors["broken"]


# --- custom skills: trust follows activation, reference_only stays untrusted ---

def test_enabled_extension_skills_are_trusted(tmp_path):
    d = _write_ext(tmp_path, "demo", _EXT_SRC)
    loaded = load_enabled(_cfg([d], enabled=["demo"]))
    sk = loaded.skills()
    assert len(sk) == 1
    assert sk[0].origin == "ext:demo"
    assert sk[0].trusted is True

    from cosmo.skills import build_skill_context
    ctx = build_skill_context(sk)
    assert "authoritative" in ctx and "UNTRUSTED" not in ctx


def test_reference_only_extension_skills_are_untrusted(tmp_path):
    d = _write_ext(tmp_path, "demo", _EXT_SRC)
    loaded = load_enabled(_cfg([d], enabled=["demo"], reference_only=["demo"]))
    sk = loaded.skills()
    assert sk[0].trusted is False

    from cosmo.skills import build_skill_context
    ctx = build_skill_context(sk)
    assert "UNTRUSTED" in ctx               # RISK-03 framing applied


# --- the shipped example extension actually loads + detects -------------------

def test_example_extension_end_to_end(tmp_path):
    import pathlib
    example = (pathlib.Path(__file__).resolve().parents[1]
               / "examples" / "extensions" / "hardcoded-ip")
    assert (example / "cosmo_extension.py").is_file()
    # a repo with a hard-coded IP
    (tmp_path / "svc.py").write_text("HOST = '10.1.2.3'\n")
    loaded = load_enabled(_cfg([example], enabled=["hardcoded-ip"]))
    assert [e.name for e in loaded.active] == ["hardcoded-ip"]
    dets = loaded.detectors()
    (det_id, det), = dets.items()
    findings = normalize_extension_findings("hardcoded-ip", det(str(tmp_path), None))
    assert any("10.1.2.3" in f.title for f in findings)
    assert all(f.source == "ext:hardcoded-ip" for f in findings)
