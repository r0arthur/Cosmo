"""SARIF 2.1.0 renderer (architecture §12) — CI-consumable structured output.

Local artifact for CI tooling; the public-comment gate does not apply.
"""
from __future__ import annotations

import json

from ..findings import Report
from ..severity import Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(report: Report) -> str:
    results = []
    rules: dict[str, dict] = {}
    for f in report.findings:
        if f.waived:
            continue
        rule_id = f.category or f.source
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "properties": {
                    "severity": str(f.severity),
                    "confidence": f.confidence,
                    "source": f.source,
                    "confirmation_status": f.confirmation_status.value,
                    "fingerprint": f.fingerprint,
                },
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "cosmo", "version": "0.1.0", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
