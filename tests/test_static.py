"""Static pre-filter — mapping tool output into the Finding shape.

Hermetic: feeds the mapper the JSON shapes semgrep actually returns, without
invoking semgrep.
"""
from cosmo.static.prefilter import _semgrep_remediation


def test_prose_guidance_is_used_verbatim():
    meta = {"fix": "Use a parameterized query."}
    assert _semgrep_remediation(meta, {}) == "Use a parameterized query."


def test_autofix_is_labelled_as_a_replacement():
    """`extra.fix` is the text semgrep would substitute, not advice.

    The rule for `subprocess(..., shell=True)` returns the bare string "False",
    which rendered unlabelled reads as "fix: False" — worse than saying nothing.
    """
    assert _semgrep_remediation({}, {"fix": "False"}) == "replace with `False`"


def test_prose_wins_over_autofix():
    out = _semgrep_remediation({"fix": "Pass a list, not a string."},
                               {"fix": "False"})
    assert out == "Pass a list, not a string."


def test_no_fix_of_either_kind_yields_nothing():
    # The renderer only prints a fix line when this is truthy, so "" hides it.
    assert _semgrep_remediation({}, {}) == ""
    assert _semgrep_remediation({"fix": None}, {"fix": None}) == ""
    assert _semgrep_remediation({"fix": "   "}, {"fix": ""}) == ""


def test_non_string_fix_is_ignored():
    """Guards the shape, not just the value: a bool or dict must not be
    stringified into remediation advice."""
    assert _semgrep_remediation({"fix": True}, {}) == ""
    assert _semgrep_remediation({}, {"fix": {"replacement": "x"}}) == ""
