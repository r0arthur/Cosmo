"""Egress broker — the step-7 security boundary.

These tests are the point of the whole design: they assert that "no code path to
an arbitrary external target" actually holds.
"""
import json
import threading

import pytest

from cosmo.broker import (
    Decision,
    DisclosurePolicy,
    EgressBroker,
    EgressDenied,
    Mode,
    Scope,
)
from cosmo.broker.log import RequestLog


# --- mode gate --------------------------------------------------------------

def test_sandbox_cannot_reach_arbitrary_external():
    b = EgressBroker()
    b.sandbox_policy.internal_hosts = ["app.internal"]
    assert not b.authorize(Mode.SANDBOX, "https://evil.example.com/x")
    assert b.authorize(Mode.SANDBOX, "http://app.internal/health")


def test_sandbox_provisioning_window_gates_registry_access():
    b = EgressBroker()
    b.sandbox_policy.provisioning_allowlist = ["registry.npmjs.org", "*.pythonhosted.org"]
    # Window closed: registry is denied.
    assert not b.authorize(Mode.SANDBOX, "https://registry.npmjs.org/pkg")
    # Window open: registry allowed; arbitrary host still denied.
    b.open_provisioning_window()
    assert b.authorize(Mode.SANDBOX, "https://files.pythonhosted.org/x")
    assert not b.authorize(Mode.SANDBOX, "https://evil.example.com/x")
    b.close_provisioning_window()
    assert not b.authorize(Mode.SANDBOX, "https://registry.npmjs.org/pkg")


def test_external_requires_scope():
    b = EgressBroker()
    assert not b.authorize(Mode.EXTERNAL, "https://api.example.com/")
    b.declare_scope(Scope("prog", includes=["*.example.com"], rate_limit_per_sec=100))
    assert b.authorize(Mode.EXTERNAL, "https://api.example.com/")


# --- scope resolution -------------------------------------------------------

def test_exclusions_win_over_includes():
    b = EgressBroker()
    b.declare_scope(Scope("p", includes=["*.example.com"],
                          excludes=["secret.example.com"], rate_limit_per_sec=100))
    assert b.authorize(Mode.EXTERNAL, "https://api.example.com/")
    assert not b.authorize(Mode.EXTERNAL, "https://secret.example.com/")


def test_forbidden_metadata_address_denied_even_if_in_scope():
    b = EgressBroker()
    # A wildcard scope that would otherwise match an IP literal.
    b.declare_scope(Scope("p", includes=["*"], rate_limit_per_sec=100))
    assert not b.authorize(Mode.EXTERNAL, "http://169.254.169.254/latest/meta-data/")
    assert not b.authorize(Mode.EXTERNAL, "http://127.0.0.1:8080/")


def test_redirect_to_out_of_scope_is_refused_midchain():
    b = EgressBroker()
    b.declare_scope(Scope("p", includes=["in.example.com"], rate_limit_per_sec=100))

    def transport(url):
        if "in.example.com" in url:
            return 302, {"Location": "https://out.evil.com/pwn"}, b""
        return 200, {}, b"should-never-reach"

    with pytest.raises(EgressDenied) as ei:
        b.request(Mode.EXTERNAL, "https://in.example.com/start", transport=transport)
    assert "out of declared scope" in ei.value.decision.reason


# --- rate limit -------------------------------------------------------------

def test_global_rate_limit_exhausts():
    clock = {"t": 0.0}
    b = EgressBroker()
    b.declare_scope(Scope("p", includes=["*"], rate_limit_per_sec=1.0),
                    clock=lambda: clock["t"])  # capacity 1, no refill while clock frozen
    assert b.authorize(Mode.EXTERNAL, "https://a.test/")     # consumes the one token
    assert not b.authorize(Mode.EXTERNAL, "https://a.test/")  # bucket empty
    clock["t"] = 2.0                                          # 2s later → refilled
    assert b.authorize(Mode.EXTERNAL, "https://a.test/")


# --- disclosure -------------------------------------------------------------

def test_disclosure_endpoint_allowlist():
    b = EgressBroker()
    b.disclosure_policy = DisclosurePolicy(allowed_endpoints=["disclose.example.org"])
    assert b.authorize(Mode.DISCLOSURE, "https://disclose.example.org/report")
    assert not b.authorize(Mode.DISCLOSURE, "https://random.host/report")


# --- logging ----------------------------------------------------------------

def test_every_decision_is_logged():
    b = EgressBroker()
    b.authorize(Mode.SANDBOX, "https://evil.example.com/", tool="ffuf")
    b.declare_scope(Scope("p", includes=["*"], rate_limit_per_sec=100))
    b.authorize(Mode.EXTERNAL, "https://a.test/", tool="httpx")
    assert len(b.log.records) == 2
    assert b.log.records[0].tool == "ffuf" and b.log.records[0].allowed is False
    assert b.log.records[1].tool == "httpx" and b.log.records[1].allowed is True


def test_log_survives_concurrent_records(tmp_path):
    """One broker serves every concurrent model call — a whole-project audit
    reviews several files at once — so two threads can land in `record`
    together. Every JSONL line must still be a whole, parseable record.
    """
    log = RequestLog(path=tmp_path / "egress.jsonl")
    # A long reason makes an interleaved write likely if the sink is unguarded.
    decision = Decision(True, "allowed: " + "x" * 400, Mode.PROVIDER,
                        "https://api.anthropic.com/v1/messages", "api.anthropic.com")
    workers, per_worker = 8, 100
    start = threading.Barrier(workers)

    def _spam():
        start.wait(timeout=10)
        for _ in range(per_worker):
            log.record(decision, "model:claude")

    threads = [threading.Thread(target=_spam) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    expected = workers * per_worker
    assert len(log.records) == expected                   # no lost in-memory records
    lines = (tmp_path / "egress.jsonl").read_text().splitlines()
    assert len(lines) == expected                         # no lost or split lines
    for line in lines:
        json.loads(line)                                  # raises if a write interleaved
