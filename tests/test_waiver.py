"""RISK-07 — the waiver fingerprint is content-based, stable across line shifts."""
from cosmo.diff.resolver import parse_unified_diff, Diff
from cosmo.findings import Finding
from cosmo.severity import Severity
from cosmo.waiver import fingerprint


def _diff_with(start: int) -> tuple[Diff, int]:
    """Same sink and same immediate neighbors, placed at a different absolute line.

    This is the real 'line shift' case: unrelated edits elsewhere in the file
    moved the whole block down, so the sink's absolute line number changed while
    its content and surroundings did not.
    """
    lines = ["ctx_a()", "ctx_b()", "query = db.execute(user_input)", "ctx_c()", "ctx_d()"]
    body = "".join(f"+{l}\n" for l in lines)
    raw = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n+++ b/app.py\n"
        f"@@ -0,0 +{start},{len(lines)} @@\n" + body
    )
    files = parse_unified_diff(raw)
    diff = Diff(source="local", target=".", files=files, raw=raw)
    return diff, start + 2  # sink is the 3rd added line


def _finding(line: int) -> Finding:
    return Finding(id="s0", title="SQL injection", severity=Severity.HIGH,
                   source="static", file="app.py", line=line, category="CWE-89")


def test_fingerprint_stable_when_line_shifts():
    diff_a, line_a = _diff_with(start=10)
    diff_b, line_b = _diff_with(start=42)   # whole block moved down 32 lines
    assert line_a != line_b                 # the sink's absolute line moved
    fp_a = fingerprint(_finding(line_a), diff_a)
    fp_b = fingerprint(_finding(line_b), diff_b)
    assert fp_a == fp_b                      # ...but the content fingerprint didn't


def test_fingerprint_changes_when_sink_changes():
    diff, line = _diff_with(start=10)
    fp = fingerprint(_finding(line), diff)
    # Mutate the sink text in the diff and re-fingerprint.
    sink_idx = 2  # 3rd added line
    diff.files[0].hunks[0].added[sink_idx] = (line, "os.system(user_input)")
    fp2 = fingerprint(_finding(line), diff)
    assert fp != fp2
