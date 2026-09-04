"""GitHub Action trigger adapter — step 14."""
import json

import pytest

from cosmo.config import Config
from cosmo.findings import ConfirmationStatus, Finding
from cosmo.severity import Severity
from cosmo.triggers import parse_pr_ref, run_github_action


def _repo(tmp_path):
    (tmp_path / "app.py").write_text("q = build_sql(user)\n")
    return str(tmp_path)


class _Provider:
    name = "claude"

    def __init__(self, findings):
        self._findings = findings

    def available(self):
        return True

    def review(self, diff, context, findings_so_far):
        return list(self._findings)


def _inject(monkeypatch, findings):
    import cosmo.engine as engine
    monkeypatch.setattr(engine, "resolve_primary", lambda cfg, cli_model=None: (_Provider(findings), []))


# --- PR ref parsing ---------------------------------------------------------

def test_parse_pr_ref():
    assert parse_pr_ref("owner/repo#123") == ("owner/repo", "123")
    with pytest.raises(ValueError):
        parse_pr_ref("not-a-ref")


# --- SARIF output + blocking ------------------------------------------------

def test_writes_sarif_and_blocks_by_default(tmp_path, monkeypatch):
    _inject(monkeypatch, [Finding(id="m0", title="SQLi", severity=Severity.HIGH,
                                  source="model:claude", file="app.py", line=1,
                                  category="CWE-89", security_sensitive=False)])
    sarif = tmp_path / "out.sarif"
    report, code = run_github_action(Config(data={}), _repo(tmp_path), sarif_path=str(sarif))
    assert code == 1 # ci blocks by default
    doc = json.loads(sarif.read_text())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-89"


def test_no_block_flag(tmp_path, monkeypatch):
    _inject(monkeypatch, [Finding(id="m0", title="SQLi", severity=Severity.HIGH,
                                  source="model:claude", file="app.py", line=1,
                                  security_sensitive=False)])
    report, code = run_github_action(Config(data={}), _repo(tmp_path), blocking_override=False)
    assert code == 0


def test_medium_threshold_filters_low(tmp_path, monkeypatch):
    _inject(monkeypatch, [Finding(id="m0", title="nit", severity=Severity.LOW,
                                  source="model:claude", file="app.py", line=1)])
    report, code = run_github_action(Config(data={}), _repo(tmp_path))
    assert report.findings == []                      # LOW below the medium floor
    assert code == 0


# --- the gate governs the posted comment (RISK-05) --------------------------

def test_posted_comment_is_gated(tmp_path, monkeypatch):
    findings = [
        Finding(id="ok", title="Public CSRF note", severity=Severity.MEDIUM,
                source="model:claude", file="a.py", line=1, security_sensitive=False,
                exploit_scenario="csrf detail"),
        Finding(id="secret", title="Hardcoded AWS key", severity=Severity.HIGH,
                source="static", file="b.py", line=2, security_sensitive=True,
                exploit_scenario="SECRET POC DETAIL"),
    ]
    _inject(monkeypatch, findings)
    posted = {}

    def fake_poster(pr_ref, body):
        posted["ref"] = pr_ref
        posted["body"] = body

    run_github_action(Config(data={}), _repo(tmp_path), pr_ref="o/r#7",
                      post=True, poster=fake_poster)

    body = posted["body"]
    assert posted["ref"] == "o/r#7"
    assert "Public CSRF note" in body                 # not-sensitive → posted with detail
    assert "Hardcoded AWS key" not in body            # sensitive → withheld
    assert "SECRET POC DETAIL" not in body            # ...and its PoC never leaks
    assert "withheld" in body                          # generic acknowledgment instead


def test_confirmed_high_withheld_from_post(tmp_path, monkeypatch):
    f = Finding(id="c", title="RCE", severity=Severity.CRITICAL, source="model:claude",
                file="a.py", line=1, security_sensitive=False,
                confirmation_status=ConfirmationStatus.CONFIRMED, exploit_scenario="rce poc")
    _inject(monkeypatch, [f])
    posted = {}
    run_github_action(Config(data={}), _repo(tmp_path), pr_ref="o/r#1",
                      post=True, poster=lambda ref, body: posted.update(body=body))
    assert "rce poc" not in posted["body"]            # confirmed+high → never public
