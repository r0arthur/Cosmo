"""RISK-05 — the public-comment gate fails closed."""
from cosmo.findings import ConfirmationStatus, Finding
from cosmo.output.gate import PublicDecision, public_gate
from cosmo.severity import Severity


def _f(**kw) -> Finding:
    base = dict(id="x", title="t", severity=Severity.HIGH, source="model:claude", file="a.py", line=1)
    base.update(kw)
    return Finding(**base)


def test_unknown_sensitivity_high_is_withheld():
    # security_sensitive defaults to None (unknown) → must not be posted publicly.
    assert public_gate(_f(severity=Severity.HIGH)) is PublicDecision.WITHHOLD


def test_explicit_not_sensitive_posts_full():
    assert public_gate(_f(security_sensitive=False)) is PublicDecision.POST_FULL


def test_confirmed_high_is_withheld_even_if_marked_not_sensitive_when_confirmed():
    # Confirmed + exploitable + high → routed to disclosure regardless.
    f = _f(security_sensitive=True, confirmation_status=ConfirmationStatus.CONFIRMED,
           severity=Severity.CRITICAL)
    assert public_gate(f) is PublicDecision.WITHHOLD


def test_sensitive_but_unconfirmed_gets_ack_only():
    f = _f(security_sensitive=True, severity=Severity.HIGH)
    assert public_gate(f) is PublicDecision.ACKNOWLEDGE_ONLY


def test_unknown_low_sev_gets_ack_only():
    assert public_gate(_f(severity=Severity.LOW)) is PublicDecision.ACKNOWLEDGE_ONLY
