"""Harness-agnostic interactive driver — orchestration on any model, or none."""
import pytest

from cosmo.config import Config
from cosmo.interactive import (
    AgentDriver,
    CommandCall,
    Plan,
    PlanRequest,
    Session,
    llm_planner,
    parse_plan,
    rule_based_planner,
)
from cosmo.interactive.commands import _COMMANDS


def _session(tmp_path, **cfg):
    return Session(config=Config(data=cfg), target=str(tmp_path))


def _fixed(plan):
    """A planner that always returns the same plan — stands in for any model."""
    return lambda req: plan


# --- the catalog offered to the model IS the guarded surface, nothing more ----

def test_catalog_is_exactly_the_guarded_registry(tmp_path):
    d = AgentDriver(_session(tmp_path), _fixed(Plan()))
    names = {t.name for t in d.catalog()}
    assert names == set(_COMMANDS)          # no invented tools, none missing


def test_catalog_includes_active_extension_commands(tmp_path):
    import textwrap
    ext = tmp_path / "demo"
    ext.mkdir()
    (ext / "cosmo_extension.py").write_text(textwrap.dedent('''
        from cosmo.extensions import Extension
        def _c(session, args): return "ran"
        COSMO_EXTENSION = Extension(name="demo", commands={"hello": _c})
    '''))
    s = _session(tmp_path, extensions={"paths": [str(ext)], "enabled": ["demo"]})
    d = AgentDriver(s, _fixed(Plan()))
    assert "x-hello" in {t.name for t in d.catalog()}


# --- CONTAINMENT: the model can only reach the guarded dispatcher --------------

def test_offcatalog_command_is_refused_never_executed(tmp_path):
    # A hostile/hallucinating planner asks for a command that doesn't exist.
    d = AgentDriver(_session(tmp_path), _fixed(Plan(calls=[CommandCall("rm-rf-slash")])))
    res = d.step("do something bad")
    assert res.executed == []
    assert res.refused == [("rm-rf-slash", "not in the guarded command catalog")]


def test_shell_like_name_cannot_execute(tmp_path):
    # Even a name that looks like a shell command is just an unknown command name.
    d = AgentDriver(_session(tmp_path), _fixed(Plan(calls=[CommandCall("bash", ["-c", "id"])])))
    res = d.step("run a shell")
    assert res.executed == []
    assert res.refused and res.refused[0][0] == "bash"


def test_valid_command_runs_through_dispatch(tmp_path):
    d = AgentDriver(_session(tmp_path), _fixed(Plan(calls=[CommandCall("threshold")])))
    res = d.step("what's the threshold")
    assert len(res.executed) == 1
    line, out = res.executed[0]
    assert line == "/threshold" and "threshold:" in out


def test_calls_are_capped_per_turn(tmp_path):
    calls = [CommandCall("status")] * 10
    d = AgentDriver(_session(tmp_path), _fixed(Plan(calls=calls)), max_calls_per_turn=3)
    res = d.step("spam")
    assert len(res.executed) == 3          # the model can't fan out unbounded


# --- downstream guardrails STILL apply because everything goes through dispatch -

def test_model_cannot_bypass_disclosure_gate(tmp_path):
    # A model that "wants" to disclose still hits the guarded /disclose path,
    # which drafts+queues and sends nothing — the driver adds no shortcut.
    d = AgentDriver(_session(tmp_path), _fixed(Plan(calls=[CommandCall("disclose", ["nope"])])))
    res = d.step("disclose everything now")
    line, out = res.executed[0]
    assert line == "/disclose nope"
    # /disclose with an unknown finding id reports no-such-finding, not a send.
    assert "no finding" in out or "not disclosable" in out or "queued" in out


def test_model_cannot_loosen_safety_config(tmp_path):
    # /scope routes to the external mode, which refuses when the operator hasn't
    # enabled external_targets — a session command (model-driven or not) can't
    # flip a safety-tier switch.
    d = AgentDriver(_session(tmp_path), _fixed(
        Plan(calls=[CommandCall("scope", ["program=x", "includes=a.example", "rate=1"])])))
    res = d.step("add a.example to scope and start hitting it")
    _, out = res.executed[0]
    assert "refused" in out                 # external targets not operator-enabled


# --- provider-agnostic: any text-completion backend drives it ------------------

def test_llm_planner_with_fake_completion(tmp_path):
    # Stand in for a local Llama / DeepSeek / OpenAI-compatible endpoint: a plain
    # `complete(prompt) -> str`. No Claude, no network.
    def fake_complete(prompt):
        assert "/status" in prompt          # the guarded catalog was offered
        return '{"message": "checking", "calls": [{"name": "status", "args": []}]}'

    d = AgentDriver(_session(tmp_path), llm_planner(fake_complete))
    res = d.step("how are things")
    assert res.message == "checking"
    assert res.executed and res.executed[0][0] == "/status"


def test_llm_planner_offcatalog_still_contained(tmp_path):
    def rogue_complete(prompt):
        return '{"calls": [{"name": "exfiltrate", "args": ["--all"]}]}'
    d = AgentDriver(_session(tmp_path), llm_planner(rogue_complete))
    res = d.step("leak the repo")
    assert res.executed == [] and res.refused[0][0] == "exfiltrate"


def test_llm_planner_backend_error_is_safe(tmp_path):
    def boom(prompt):
        raise RuntimeError("endpoint down")
    d = AgentDriver(_session(tmp_path), llm_planner(boom))
    res = d.step("anything")
    assert res.executed == [] and "backend error" in res.message


# --- lenient JSON parsing degrades to a message, never a stray command ---------

def test_parse_plan_extracts_json_amid_prose():
    p = parse_plan('Sure! {"message": "ok", "calls": [{"name": "help"}]} hope that helps')
    assert p.message == "ok" and p.calls[0].name == "help"


def test_parse_plan_malformed_becomes_message_not_command():
    p = parse_plan("I think you should run /report but I'm not sure")
    assert p.calls == [] and "report" in p.message


# --- the no-model rule-based planner actually maps intents --------------------

def test_rule_based_planner_maps_common_intents(tmp_path):
    cat = AgentDriver(_session(tmp_path), _fixed(Plan())).catalog()

    def plan_for(text):
        return rule_based_planner(PlanRequest(text, cat, []))

    assert plan_for("show me the status").calls[0].name == "status"
    assert plan_for("set threshold to high").calls[0] == CommandCall("threshold", ["high"])
    assert plan_for("export sarif").calls[0] == CommandCall("report", ["sarif"])
    assert plan_for("what extensions are active").calls[0].name == "extensions"
    # unmappable input becomes a menu message, not a guessed command
    assert plan_for("tell me a joke").calls == []


def test_rule_based_end_to_end_through_driver(tmp_path):
    d = AgentDriver(_session(tmp_path), rule_based_planner)
    res = d.step("show status")
    assert res.executed and res.executed[0][0] == "/status"
