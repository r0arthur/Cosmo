"""Coordinated disclosure workflow — step 18 (architecture §13)."""
import pytest

from cosmo.broker import EgressBroker, EgressDenied, Mode
from cosmo.broker.scope import DisclosurePolicy
from cosmo.disclose import (
    ApprovalRequired,
    DisclosureContact,
    HumanApproval,
    NotEligible,
    advance_status,
    draft_report,
    find_contact,
    is_disclosable,
    parse_security_md,
    queue_disclosure,
    send_disclosure,
)
from cosmo.disclose.workflow import QUEUED, REPORTED
from cosmo.findings import ConfirmationStatus, Finding
from cosmo.severity import Severity
from cosmo.store import TrendStore


def _confirmed(fp="fp-1", sev=Severity.HIGH):
    return Finding(id="f1", title="RCE in parser", severity=sev, source="fuzz",
                   file="a.py", line=3, category="CWE-94", fingerprint=fp,
                   confirmation_status=ConfirmationStatus.CONFIRMED,
                   exploit_scenario="POST /x with payload → shell")


def _store(tmp_path):
    return TrendStore(tmp_path / ".cosmo" / "trends.db")


def _broker(endpoints):
    b = EgressBroker()
    b.disclosure_policy = DisclosurePolicy(allowed_endpoints=list(endpoints))
    return b


# --- eligibility: confirmed + high + unpatched only -------------------------

def test_eligibility_requires_confirmed_high_unwaived():
    assert is_disclosable(_confirmed())
    assert not is_disclosable(_confirmed(sev=Severity.MEDIUM))     # too low
    unconf = _confirmed()
    unconf.confirmation_status = ConfirmationStatus.UNCONFIRMED
    assert not is_disclosable(unconf)                              # not reproduced
    waived = _confirmed()
    waived.waived = True
    assert not is_disclosable(waived)


# --- SECURITY.md parsing is untrusted candidate only ------------------------

def test_parse_security_md():
    c = parse_security_md("Report issues to security@example.com or https://acme.example/report")
    assert c.email == "security@example.com"
    assert c.url == "https://acme.example/report"
    assert c.trusted is False                     # a repo file is never trusted
    assert c.target == "https://acme.example/report"


def test_find_contact_locations(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "SECURITY.md").write_text("mailto:sec@proj.example")
    c = find_contact(tmp_path)
    assert c.email == "sec@proj.example"
    assert c.target == "mailto:sec@proj.example"


# --- queue drafts but sends nothing -----------------------------------------

def test_queue_drafts_and_enqueues_without_sending(tmp_path):
    store = _store(tmp_path)
    contact = DisclosureContact(url="https://hackerone.com/acme")
    draft = queue_disclosure(store, "t", _confirmed(), contact)
    assert "RCE in parser" in draft.title
    assert draft.cve == "pending"                 # never self-assigned
    assert draft.approved is False
    q = store.disclosure_queue("t")
    assert len(q) == 1 and q[0]["disclosure_status"] == QUEUED   # queued, not reported


def test_queue_refuses_ineligible(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(NotEligible):
        queue_disclosure(store, "t", _confirmed(sev=Severity.LOW),
                         DisclosureContact(url="https://x.example"))


def test_queue_refuses_without_contact(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(NotEligible):
        queue_disclosure(store, "t", _confirmed(), DisclosureContact())  # no target


# --- the hard property: nothing sent without explicit human approval --------

def test_send_refused_without_approval(tmp_path):
    store = _store(tmp_path)
    contact = DisclosureContact(url="https://hackerone.com/acme")
    draft = queue_disclosure(store, "t", _confirmed(), contact)
    broker = _broker(["hackerone.com"])
    sent = []

    def transport(url):
        sent.append(url)
        return 200, {}, b""

    with pytest.raises(ApprovalRequired):
        send_disclosure(draft, approval=None, broker=broker, transport=transport)
    # approval for a *different* finding must not authorize this one
    with pytest.raises(ApprovalRequired):
        send_disclosure(draft, approval=HumanApproval("other-id", "alice"),
                        broker=broker, transport=transport)
    assert sent == []                             # transport never touched
    assert store.disclosure_queue("t")[0]["disclosure_status"] == QUEUED


def test_send_with_approval_goes_through_broker(tmp_path):
    store = _store(tmp_path)
    contact = DisclosureContact(url="https://hackerone.com/acme")
    draft = queue_disclosure(store, "t", _confirmed(), contact)
    broker = _broker(["hackerone.com"])
    sent = []

    def transport(url):
        sent.append(url)
        return 200, {}, b""

    status, endpoint = send_disclosure(
        draft, approval=HumanApproval("f1", "alice"), broker=broker,
        store=store, target="t", transport=transport)
    assert status == 200
    assert sent == ["https://hackerone.com/acme"]
    assert draft.approved is True
    assert store.disclosure_queue("t")[0]["disclosure_status"] == REPORTED


def test_send_refused_when_endpoint_not_operator_configured(tmp_path):
    # SECURITY.md names an arbitrary host; even with approval the broker refuses
    # because it is not an operator-configured disclosure endpoint.
    store = _store(tmp_path)
    contact = DisclosureContact(url="https://evil.attacker.example/collect")
    draft = queue_disclosure(store, "t", _confirmed(), contact)
    broker = _broker(["hackerone.com"])          # attacker host not allowed
    sent = []

    with pytest.raises(EgressDenied):
        send_disclosure(draft, approval=HumanApproval("f1", "alice"),
                        broker=broker, transport=lambda u: sent.append(u))
    assert sent == []
    assert store.disclosure_queue("t")[0]["disclosure_status"] == QUEUED   # not advanced


# --- lifecycle advance ------------------------------------------------------

def test_advance_status(tmp_path):
    store = _store(tmp_path)
    queue_disclosure(store, "t", _confirmed(), DisclosureContact(url="https://h1.example"))
    advance_status(store, "t", "fp-1", "acknowledged")
    assert store.disclosure_queue("t")[0]["disclosure_status"] == "acknowledged"
    with pytest.raises(ValueError):
        advance_status(store, "t", "fp-1", "bogus")


# --- /disclose from the interactive layer queues, sends nothing -------------

def test_interactive_disclose_queues(tmp_path):
    from cosmo.config import Config
    from cosmo.interactive import Session, dispatch
    (tmp_path / "SECURITY.md").write_text("security@proj.example")
    s = Session(config=Config(data={}), target=str(tmp_path), findings=[_confirmed()])
    out = dispatch(s, "/disclose f1")
    assert "queued disclosure" in out
    assert "nothing sent" in out


def test_interactive_disclose_rejects_ineligible(tmp_path):
    from cosmo.config import Config
    from cosmo.interactive import Session, dispatch
    (tmp_path / "SECURITY.md").write_text("security@proj.example")
    low = _confirmed(sev=Severity.LOW)
    s = Session(config=Config(data={}), target=str(tmp_path), findings=[low])
    assert "not disclosable" in dispatch(s, "/disclose f1")
