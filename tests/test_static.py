"""Static pre-filter — mapping tool output into the Finding shape.

Hermetic: feeds each mapper the shape its scanner actually returns — captured
from a real run of semgrep, opengrep, gitleaks, trufflehog, bandit, trivy and
find-sec-bugs — and stubs the subprocess call, so none of the binaries is
required to run these.
"""
import json
import subprocess
from pathlib import Path

import pytest

from cosmo.findings import ConfirmationStatus
from cosmo.severity import Severity
from cosmo.static import runners as prefilter
from cosmo.static.runners import _run_gitleaks, _semgrep_remediation


def _leak(rule="github-pat", file="config.py", line=1):
    return {"RuleID": rule, "File": file, "StartLine": line,
            "Description": "a token"}


def _stub_gitleaks(monkeypatch, rows_by_mode):
    """Stand in for the gitleaks binary, writing the report it would write.

    `rows_by_mode` maps "tree"/"history" to the rows that pass should return.
    Records each argv so the test can assert how gitleaks was invoked.
    """
    calls = []

    def fake_sh(cmd, ev=None, timeout=None):
        calls.append(cmd)
        mode = "tree" if "--no-git" in cmd else "history"
        rows = rows_by_mode.get(mode)
        if isinstance(rows, Exception):      # simulate a timeout / crash
            raise rows
        path = Path(cmd[cmd.index("--report-path") + 1])
        if rows is not None:                 # None = ran but wrote no report
            path.write_text(json.dumps(rows))
        return ""

    monkeypatch.setattr(prefilter, "_sh", fake_sh)
    return calls


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


# --- gitleaks: the working tree must be scanned, not just history -----------

def test_non_git_target_is_scanned_on_disk(monkeypatch, tmp_path):
    """`gitleaks detect` alone walks commits. On a directory with no history it
    scanned nothing, exited 0, and cosmo reported no findings over a plaintext
    key — so the filesystem pass is the one that must always run."""
    calls = _stub_gitleaks(monkeypatch, {"tree": [_leak()]})
    found = _run_gitleaks(str(tmp_path))
    assert len(calls) == 1 and "--no-git" in calls[0]     # no .git → tree only
    assert [f.title for f in found] == ["Secret leaked: github-pat"]


def test_git_target_is_scanned_both_ways(monkeypatch, tmp_path):
    """A secret uncommitted in the tree and one deleted but still in history are
    different failures; neither pass alone catches both."""
    (tmp_path / ".git").mkdir()
    calls = _stub_gitleaks(monkeypatch, {
        "tree": [_leak(file="uncommitted.py")],
        "history": [_leak(file="deleted.py")],
    })
    found = _run_gitleaks(str(tmp_path))
    assert len(calls) == 2
    assert "--no-git" in calls[0] and "--no-git" not in calls[1]
    assert {f.file for f in found} == {"uncommitted.py", "deleted.py"}


def test_a_secret_in_both_passes_is_reported_once(monkeypatch, tmp_path):
    """The passes overlap on anything committed and still on disk."""
    (tmp_path / ".git").mkdir()
    _stub_gitleaks(monkeypatch, {"tree": [_leak()], "history": [_leak()]})
    assert len(_run_gitleaks(str(tmp_path))) == 1


def test_a_failed_scan_is_raised_not_reported_as_clean(monkeypatch, tmp_path):
    """gitleaks exits 1 on leaks found, so the exit code cannot distinguish
    success from failure — a missing report is the signal that it did not run.
    Swallowing that would present an empty result as a clean scan."""
    _stub_gitleaks(monkeypatch, {"tree": None})
    with pytest.raises(RuntimeError, match="no report"):
        _run_gitleaks(str(tmp_path))


def test_leaks_are_marked_security_sensitive(monkeypatch, tmp_path):
    """A live credential must reach the public-comment gate as withholdable."""
    _stub_gitleaks(monkeypatch, {"tree": [_leak()]})
    f = _run_gitleaks(str(tmp_path))[0]
    assert f.security_sensitive is True
    assert f.category == "CWE-798"


def test_report_file_is_cleaned_up(monkeypatch, tmp_path):
    _stub_gitleaks(monkeypatch, {"tree": [_leak()]})
    _run_gitleaks(str(tmp_path))
    assert not list(tmp_path.glob(".cosmo-gitleaks*"))


def test_history_timeout_keeps_tree_results_and_reports_the_shortfall(
        monkeypatch, tmp_path):
    """The history pass walks every commit, and on a partial clone each blob is
    a network fetch — it can run for minutes. Timing out must not discard the
    tree findings, nor pass tree-only coverage off as a full scan.
    """
    (tmp_path / ".git").mkdir()
    _stub_gitleaks(monkeypatch, {
        "tree": [_leak(file="live.py")],
        "history": subprocess.TimeoutExpired(cmd="gitleaks", timeout=60),
    })
    skipped: list[str] = []
    found = _run_gitleaks(str(tmp_path), None, skipped)

    assert [f.file for f in found] == ["live.py"]     # tree results survive
    assert any("history pass timed out" in s for s in skipped)
    assert not list(tmp_path.glob(".cosmo-gitleaks*"))   # still cleaned up


def test_a_timeout_does_not_sink_the_stage(monkeypatch, tmp_path):
    """A partial result is not a failed one — the caller records `skipped`
    itself, so nothing should propagate out of the runner."""
    (tmp_path / ".git").mkdir()
    _stub_gitleaks(monkeypatch, {
        "tree": [],
        "history": subprocess.TimeoutExpired(cmd="gitleaks", timeout=60),
    })
    assert _run_gitleaks(str(tmp_path), None, []) == []   # no exception


# --- evidence has to be triageable ------------------------------------------

def test_semgrep_evidence_is_built_from_fields_that_actually_carry_data():
    """`extra.lines` — the matched source — reads "requires login" on the OSS
    engine, so evidence built on it would print that string instead of code."""
    from cosmo.static.runners import _semgrep_evidence

    meta = {
        "cwe": ["CWE-502: Deserialization of Untrusted Data"],
        "owasp": ["A08:2021 - Software and Data Integrity Failures"],
        "confidence": "MEDIUM", "impact": "HIGH", "likelihood": "MEDIUM",
        "shortlink": "https://sg.run/NwQy",
        "references": ["https://blog.trailofbits.com/never-a-dill-moment/"],
    }
    out = _semgrep_evidence("trailofbits.python.pickles-in-pytorch", meta)
    assert "trailofbits.python.pickles-in-pytorch" in out
    assert "confidence=MEDIUM" in out and "impact=HIGH" in out
    assert "CWE-502: Deserialization of Untrusted Data" in out
    assert "https://sg.run/NwQy" in out
    assert "requires login" not in out


def test_semgrep_evidence_survives_a_bare_rule():
    from cosmo.static.runners import _semgrep_evidence
    assert _semgrep_evidence("some.rule", {}) == "semgrep rule: some.rule"


def test_a_secret_is_never_copied_into_the_evidence():
    """A report is a file that gets attached to tickets. Copying the credential
    into it mints a second live copy of the thing the finding says to rotate."""
    from cosmo.static.runners import _gitleaks_evidence

    secret = "phc_aBzNGHzlOy2C8n1BBDtH7d4qQsIw9d8T0unVlnKfdxB"
    out = _gitleaks_evidence({
        "RuleID": "generic-api-key", "Description": "Generic API Key",
        "Match": f"KEY = '{secret}'", "Secret": secret, "Entropy": "5.01"})
    assert secret not in out
    assert "phc_aB" in out          # ...but enough to recognise a PostHog key
    assert "generic-api-key" in out
    assert "5.01" in out


def test_a_short_secret_is_redacted_wholesale():
    from cosmo.static.runners import _gitleaks_evidence
    out = _gitleaks_evidence({"RuleID": "r", "Secret": "abc123", "Match": "k=abc123"})
    assert "abc123" not in out
    assert "redacted" in out


def test_commit_provenance_reaches_the_evidence():
    from cosmo.static.runners import _gitleaks_evidence
    out = _gitleaks_evidence({
        "RuleID": "jwt", "Secret": "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaa.bbbb",
        "Commit": "9f1c2d3e4b5a6789", "Author": "Test Dev",
        "Date": "2023-04-01T10:00:00Z"})
    assert "9f1c2d3e4b5a" in out
    assert "Test Dev" in out
    assert "2023-04-01" in out


def test_overlapping_passes_keep_the_row_that_knows_the_commit(monkeypatch, tmp_path):
    """The tree pass runs first and reports no commit. Dropping the later
    duplicate would throw away when the secret entered the repo."""
    from cosmo.static import runners as prefilter

    (tmp_path / ".git").mkdir()
    tree_row = {"RuleID": "jwt", "File": "a.py", "StartLine": "3",
                "Secret": "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaa.bbbb", "Commit": ""}
    hist_row = dict(tree_row, Commit="abc123def456")

    calls = []

    def fake_scan(root, mode_args, tag, ev=None, timeout=None):
        calls.append(tag)
        return [tree_row] if tag == "tree" else [hist_row]

    monkeypatch.setattr(prefilter, "_gitleaks_scan", fake_scan)
    out = prefilter._run_gitleaks(str(tmp_path))
    assert calls == ["tree", "history"]
    assert len(out) == 1                       # still deduped
    assert "abc123def456" in out[0].evidence   # ...to the richer row


# --- bandit ------------------------------------------------------------------

def _bandit_json(**over):
    row = {"filename": "/repo/app.py", "line_number": 12, "test_id": "B602",
           "test_name": "subprocess_popen_with_shell_equals_true",
           "issue_text": "subprocess call with shell=True identified.",
           "issue_severity": "HIGH", "issue_confidence": "HIGH",
           "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/..."},
           "more_info": "https://bandit.readthedocs.io/b602",
           "code": "12 subprocess.run(cmd, shell=True)\n"}
    row.update(over)
    return json.dumps({"errors": [], "generated_at": "", "metrics": {},
                       "results": [row]})


def test_bandit_rows_become_findings(monkeypatch):
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: _bandit_json())
    f = runners._run_bandit("/repo")[0]
    assert f.severity is Severity.HIGH
    assert f.file == "/repo/app.py" and f.line == 12
    assert f.category == "CWE-78"
    assert f.confidence == 0.8                    # bandit's HIGH confidence
    assert "B602" in f.evidence
    assert "https://bandit.readthedocs.io/b602" in f.evidence


def test_bandit_severity_and_confidence_are_kept_apart(monkeypatch):
    """A HIGH-severity LOW-confidence hit is the classic false positive; folding
    confidence into severity would hide exactly that."""
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh",
                        lambda *a, **k: _bandit_json(issue_confidence="LOW"))
    f = runners._run_bandit("/repo")[0]
    assert f.severity is Severity.HIGH
    assert f.confidence == 0.4


def test_bandit_hardcoded_password_is_not_copied_into_the_title(monkeypatch):
    """Bandit puts the value straight into its message, which would carry the
    credential into the finding title, the terminal and the report."""
    from cosmo.static import runners
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: _bandit_json(
        test_id="B105", issue_text=f"Possible hardcoded password: '{secret}'",
        code=f"12 PASSWORD = '{secret}'\n"))
    f = runners._run_bandit("/repo")[0]
    assert secret not in f.title
    assert secret not in f.evidence           # nor in the code snippet
    assert "wJalrX" in f.title                # still recognisable


def test_bandit_keeps_the_code_snippet_for_ordinary_findings(monkeypatch):
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: _bandit_json())
    assert "shell=True" in runners._run_bandit("/repo")[0].evidence


def test_bandit_unparseable_files_are_reported_as_lost_coverage(monkeypatch):
    from cosmo.static import runners
    payload = json.dumps({"errors": [{"filename": "x.py", "reason": "syntax"}],
                          "results": []})
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: payload)
    skipped = []
    runners._run_bandit("/repo", None, skipped)
    assert any("could not be parsed" in s for s in skipped)


# --- trivy -------------------------------------------------------------------

_TRIVY = {
    "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
         "Packages": [{"Name": "PyYAML", "Identifier": {"UID": "u1"},
                       "Locations": [{"StartLine": 2}]}],
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2019-20477", "PkgName": "PyYAML",
              "PkgIdentifier": {"UID": "u1"}, "InstalledVersion": "5.1",
              "FixedVersion": "5.2", "Severity": "CRITICAL",
              "CweIDs": ["CWE-502"], "Title": "command execution in FullLoader",
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-20477",
              "Description": "long text"}]},
        {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
         "Misconfigurations": [
             {"ID": "DS-0002", "Title": "Image user should not be 'root'",
              "Severity": "HIGH", "Message": "Last USER should not be root",
              "Resolution": "Add 'USER <non root>'", "Type": "Dockerfile",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ds-0002",
              "CauseMetadata": {"StartLine": 3}}]},
    ]
}


def test_trivy_vulnerability_becomes_a_finding_at_the_manifest_line(monkeypatch):
    """A vulnerability row names its package but carries no location; the line
    lives on the sibling Packages entry, joined by UID. Without that join every
    CVE reports line 0 and no editor can jump to it."""
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: json.dumps(_TRIVY))
    vuln = next(f for f in runners._run_trivy("/repo") if "CVE" in f.title)
    assert vuln.severity is Severity.CRITICAL
    assert vuln.file == "/repo/requirements.txt"
    assert vuln.line == 2
    assert vuln.category == "CWE-502"
    assert "5.1 → 5.2" in vuln.remediation


def test_trivy_says_so_when_there_is_no_fix(monkeypatch):
    from cosmo.static import runners
    data = json.loads(json.dumps(_TRIVY))
    del data["Results"][0]["Vulnerabilities"][0]["FixedVersion"]
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: json.dumps(data))
    vuln = next(f for f in runners._run_trivy("/repo") if "CVE" in f.title)
    assert "No fixed version" in vuln.remediation


def test_trivy_misconfiguration_carries_its_resolution(monkeypatch):
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: json.dumps(_TRIVY))
    m = next(f for f in runners._run_trivy("/repo") if "root" in f.title)
    assert m.severity is Severity.HIGH
    assert m.file == "/repo/Dockerfile" and m.line == 3
    assert "USER <non root>" in m.remediation


def test_trivy_unknown_severity_lands_below_any_floor(monkeypatch):
    from cosmo.static import runners
    data = json.loads(json.dumps(_TRIVY))
    data["Results"][0]["Vulnerabilities"][0]["Severity"] = "UNKNOWN"
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: json.dumps(data))
    vuln = next(f for f in runners._run_trivy("/repo") if "CVE" in f.title)
    assert vuln.severity is Severity.INFO


def test_trivy_empty_output_is_an_error_not_a_clean_scan(monkeypatch):
    """Trivy fetches a vulnerability DB on first use. A cold offline run must
    not read as 'no CVEs'."""
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: "")
    with pytest.raises(RuntimeError, match="did not complete"):
        runners._run_trivy("/repo")


# --- opengrep ----------------------------------------------------------------

_SEMGREP_LIKE = {"results": [{
    "check_id": "python.lang.security.audit.subprocess-shell-true",
    "path": "/repo/app.py", "start": {"line": 3},
    "extra": {"message": "Found subprocess with shell=True", "severity": "ERROR",
              "lines": "    return subprocess.check_output(cmd, shell=True)",
              "metadata": {"cwe": ["CWE-78: OS Command Injection"],
                           "confidence": "MEDIUM", "impact": "LOW",
                           "likelihood": "HIGH", "shortlink": "https://sg.run/J92w"}}}]}


def test_opengrep_uses_the_semgrep_mapper(monkeypatch):
    """opengrep is a semgrep fork and emits the same schema, so one mapper
    serves both — but the finding must say which tool actually ran."""
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: json.dumps(_SEMGREP_LIKE))
    f = runners._run_opengrep("/repo")[0]
    assert f.id.startswith("static-opengrep-")
    assert f.severity is Severity.HIGH        # semgrep ERROR
    assert f.file == "/repo/app.py" and f.line == 3
    assert "opengrep rule:" in f.evidence
    assert "semgrep rule:" not in f.evidence


def test_opengrep_keeps_the_matched_source(monkeypatch):
    """This is opengrep's practical edge over the OSS semgrep engine, which
    returns the string 'requires login' in that field."""
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: json.dumps(_SEMGREP_LIKE))
    assert "shell=True" in runners._run_opengrep("/repo")[0].evidence


def test_the_requires_login_placeholder_is_never_shown_as_code(monkeypatch):
    """semgrep OSS puts that literal string in `extra.lines`. Printed as
    'matched:' it would look like the code under review."""
    from cosmo.static import runners
    data = json.loads(json.dumps(_SEMGREP_LIKE))
    data["results"][0]["extra"]["lines"] = "requires login"
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: json.dumps(data))
    assert "matched:" not in runners._run_semgrep("/repo")[0].evidence


# --- trufflehog --------------------------------------------------------------

def _th_line(**over):
    row = {"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/conf.py",
                                                     "line": 4}}},
           "DetectorName": "SendGrid", "DetectorDescription": "SendGrid API key",
           "DecoderName": "PLAIN", "Verified": False,
           "Raw": "SG.aB3dE5fG7hI9jK1lM3nO5p.qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7",
           "Redacted": ""}
    row.update(over)
    return json.dumps(row)


def test_trufflehog_rows_become_findings(monkeypatch):
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: _th_line())
    f = runners._run_trufflehog("/repo")[0]
    assert f.file == "/repo/conf.py" and f.line == 4
    assert f.severity is Severity.HIGH
    assert f.category == "CWE-798"
    assert f.security_sensitive is True
    assert "SendGrid" in f.title


def test_a_verified_secret_outranks_a_pattern_match(monkeypatch):
    """Verification means trufflehog authenticated the credential against its
    provider. That is a reproduced finding, not a guess."""
    from cosmo.static import runners
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: _th_line(Verified=True))
    f = runners._run_trufflehog("/repo")[0]
    assert f.severity is Severity.CRITICAL
    assert f.confirmation_status is ConfirmationStatus.CONFIRMED
    assert f.confidence > 0.95
    assert "VERIFIED" in f.evidence


def test_trufflehog_never_copies_the_raw_secret(monkeypatch):
    from cosmo.static import runners
    secret = "SG.aB3dE5fG7hI9jK1lM3nO5p.qR7sT9uV1wX3yZ5aB7cD9eF1gH3iJ5kL7"
    monkeypatch.setattr(runners, "_sh", lambda *a, **k: _th_line())
    f = runners._run_trufflehog("/repo")[0]
    assert secret not in f.evidence and secret not in f.title


def test_trufflehog_log_lines_are_not_findings(monkeypatch):
    """Its own progress records are JSON too; only rows with a detector count."""
    from cosmo.static import runners
    noise = json.dumps({"level": "info-0", "msg": "running source"})
    monkeypatch.setattr(runners, "_sh",
                        lambda *a, **k: noise + "\n" + _th_line() + "\nnot json\n")
    assert len(runners._run_trufflehog("/repo")) == 1


def test_verification_is_off_unless_the_operator_asks(monkeypatch):
    """Verification sends candidate credentials to third parties, outside the
    egress broker. Default-on would exfiltrate the repo's secrets to check them."""
    from cosmo.static import runners
    seen = {}
    monkeypatch.setattr(runners, "_sh",
                        lambda argv, *a, **k: seen.setdefault("argv", argv) and "")
    runners._run_trufflehog("/repo")
    assert "--no-verification" in seen["argv"]

    seen.clear()
    runners._run_trufflehog("/repo", verify=True)
    assert "--no-verification" not in seen["argv"]


def test_a_repo_cannot_turn_verification_on(tmp_path):
    from cosmo.config import load_config
    (tmp_path / "cosmo.yaml").write_text("static:\n  trufflehog_verify: true\n")
    cfg = load_config(str(tmp_path))
    assert cfg.get("static.trufflehog_verify", False) is False
    assert any("trufflehog_verify" in w for w in cfg.warnings)


# --- find-sec-bugs -----------------------------------------------------------

_FSB_SARIF = {"runs": [{
    "tool": {"driver": {"name": "SpotBugs", "rules": [
        {"id": "SQL_INJECTION_JDBC",
         "shortDescription": {"text": "Potential JDBC Injection."},
         "helpUri": "https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC",
         "relationships": [{"target": {"id": "89",
                                       "toolComponent": {"name": "CWE"}}}]}]}},
    "results": [{
        "ruleId": "SQL_INJECTION_JDBC", "level": "warning",
        "message": {"text": "Potential JDBC Injection",
                    "arguments": ["java/sql/Statement.executeQuery"]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "Vuln.java"},
            "region": {"startLine": 5}},
            "logicalLocations": [{"fullyQualifiedName": "Vuln.lookup(Connection, String)"}]}]}]}]}


def _built_java_repo(tmp_path):
    (tmp_path / "target" / "classes").mkdir(parents=True)
    src = tmp_path / "src" / "main" / "java"
    src.mkdir(parents=True)
    (src / "Vuln.java").write_text("public class Vuln {}\n")
    return tmp_path


def test_findsecbugs_maps_sarif_results(monkeypatch, tmp_path):
    from cosmo.static import runners
    repo = _built_java_repo(tmp_path)

    def fake_sh(argv, ev=None, timeout=None):
        out = argv[argv.index("-output") + 1]
        Path(out).write_text(json.dumps(_FSB_SARIF))
        return ""

    monkeypatch.setattr(runners, "_sh", fake_sh)
    f = runners._run_findsecbugs(str(repo))[0]
    assert f.severity is Severity.MEDIUM              # SARIF `warning`
    assert f.category == "CWE-89"                     # from the taxonomy relationship
    assert f.line == 5
    assert "SQL_INJECTION_JDBC" in f.evidence
    assert "Vuln.lookup" in f.evidence


def test_findsecbugs_resolves_the_bare_source_filename(monkeypatch, tmp_path):
    """SpotBugs reports `Vuln.java` — the path is not in the bytecode. Left as
    is, no editor opens it and no waiver fingerprint anchors to it."""
    from cosmo.static import runners
    repo = _built_java_repo(tmp_path)

    def fake_sh(argv, ev=None, timeout=None):
        Path(argv[argv.index("-output") + 1]).write_text(json.dumps(_FSB_SARIF))
        return ""

    monkeypatch.setattr(runners, "_sh", fake_sh)
    f = runners._run_findsecbugs(str(repo))[0]
    assert f.file.endswith("src/main/java/Vuln.java")


def test_java_source_with_no_build_is_reported_as_lost_coverage(tmp_path):
    """find-sec-bugs reads bytecode. Java in the tree and no classes means the
    one tool that understands it did not look — which is not the same as clean."""
    from cosmo.static import runners
    (tmp_path / "A.java").write_text("public class A {}\n")
    skipped = []
    assert runners._run_findsecbugs(str(tmp_path), None, skipped) == []
    note = next(s for s in skipped if "find-sec-bugs" in s)
    assert "no compiled classes" in note
    assert "mvn" in note                      # tells you how to fix it


def test_a_repo_with_no_java_says_nothing(tmp_path):
    """Nothing was missed, so there is nothing to report."""
    from cosmo.static import runners
    (tmp_path / "app.py").write_text("x = 1\n")
    skipped = []
    assert runners._run_findsecbugs(str(tmp_path), None, skipped) == []
    assert skipped == []


def test_findsecbugs_finds_a_jar_when_there_is_no_class_dir(tmp_path):
    from cosmo.static import runners
    (tmp_path / "A.java").write_text("public class A {}\n")
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "app.jar").write_bytes(b"PK\x03\x04")
    assert runners._bytecode_roots(tmp_path) == [str(tmp_path / "target" / "app.jar")]


# --- interrupting a scan ----------------------------------------------------

def test_a_running_scanner_is_tracked_and_released():
    """`terminate_running_scanners` can only reach what `_sh` registered."""
    from cosmo.static import runners

    assert runners._sh(["true"]) == ""
    assert not runners._running, "a finished scanner stayed in the registry"


def test_terminate_signals_the_whole_process_group(monkeypatch):
    """`proc.terminate()` reaches only the direct child. semgrep's launcher
    spawns semgrep-core, which survived Ctrl-C and outlived cosmo."""
    import signal as _signal

    from cosmo.static import runners

    signalled = []

    class _Proc:
        pid = 4242

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(runners.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(runners.os, "killpg",
                        lambda pgid, sig: signalled.append((pgid, sig)))
    monkeypatch.setattr(runners, "_running", {_Proc()})
    assert runners.terminate_running_scanners(grace=0.01) == 1
    assert signalled == [(4242, _signal.SIGTERM)]


def test_a_scanner_ignoring_sigterm_is_killed(monkeypatch):
    """A scanner that will not stop would keep the pool waiting forever."""
    import signal as _signal

    from cosmo.static import runners

    signalled = []

    class _Stubborn:
        pid = 99

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("scanner", timeout or 0)

    monkeypatch.setattr(runners.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(runners.os, "killpg",
                        lambda pgid, sig: signalled.append(sig))
    monkeypatch.setattr(runners, "_running", {_Stubborn()})
    runners.terminate_running_scanners(grace=0.01)
    assert signalled == [_signal.SIGTERM, _signal.SIGKILL]


def test_a_timed_out_scanner_is_not_left_running():
    """communicate() leaves the child alive on timeout; the scan would finish
    with an orphan still working."""
    from cosmo.static import runners

    with pytest.raises(subprocess.TimeoutExpired) as exc:
        runners._sh(["sleep", "10"], timeout=0.3)
    assert exc.value.timeout == 0.3
    assert not runners._running
