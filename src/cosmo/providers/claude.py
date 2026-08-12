"""Claude — the built-in default provider (architecture §8).

Hardcoded default and fallback. If the `anthropic` SDK isn't installed or no API
key is set, `available()` is False and the engine records a skipped stage rather
than silently dropping the LLM review (§8: never silently skip review).
"""
from __future__ import annotations

import json
import os

from ..diff import Diff
from ..findings import ConfirmationStatus, Finding
from ..severity import Severity

_MODEL = "claude-opus-4-8"  # default review model; see claude-api skill for current ids

_SYSTEM = (
    "You are a security code reviewer. Review ONLY the added lines in the diff. "
    "Report high-signal security issues (injection, authz, SSRF, secrets, unsafe "
    "deserialization, path traversal, etc.). Do not flag style or pre-existing code. "
    "Respond with a JSON array; each item: "
    '{"title","severity"(critical|high|medium|low|info),"file","line",'
    '"category"(CWE id if known),"exploit_scenario","remediation",'
    '"security_sensitive"(true|false),"confidence"(0..1)}. '
    "Return [] if nothing qualifies."
)


class ClaudeProvider:
    name = "claude"

    def __init__(self, model: str = _MODEL):
        self.model = model

    def available(self) -> bool:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
            return True
        except ImportError:
            return False

    def review(self, diff: Diff, context: str, findings_so_far: list[Finding]) -> list[Finding]:
        import anthropic

        client = anthropic.Anthropic()
        prompt = self._build_prompt(diff, context, findings_so_far)
        resp = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return self._parse(text)

    def _build_prompt(self, diff: Diff, context: str, findings_so_far: list[Finding]) -> str:
        already = ", ".join(f"{f.file}:{f.line} {f.title}" for f in findings_so_far)
        parts = [f"# Diff for {diff.target}", diff.raw or self._synth_raw(diff)]
        if context:
            parts += ["\n# Static pre-filter already flagged (do not re-derive):", context]
        if already:
            parts += ["\n# Findings so far:", already]
        return "\n".join(parts)

    @staticmethod
    def _synth_raw(diff: Diff) -> str:
        out = []
        for f in diff.files:
            out.append(f"--- {f.path}")
            for h in f.hunks:
                for ln, txt in h.added:
                    out.append(f"+{ln}: {txt}")
        return "\n".join(out)

    def _parse(self, text: str) -> list[Finding]:
        text = text.strip()
        start, end = text.find("["), text.rfind("]")
        if start == -1 or end == -1:
            return []
        try:
            rows = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []
        for i, r in enumerate(rows):
            out.append(
                Finding(
                    id=f"model-claude-{i}",
                    title=str(r.get("title", "Unnamed model finding")),
                    severity=Severity.parse(r.get("severity", "medium")),
                    source="model:claude",
                    file=str(r.get("file", "")),
                    line=int(r.get("line", 0) or 0),
                    confidence=float(r.get("confidence", 0.5) or 0.5),
                    confirmation_status=ConfirmationStatus.UNCONFIRMED,
                    category=r.get("category"),
                    exploit_scenario=str(r.get("exploit_scenario", "")),
                    remediation=str(r.get("remediation", "")),
                    security_sensitive=r.get("security_sensitive"),  # may be None → gate fails closed
                )
            )
        return out


def get_default_provider() -> ClaudeProvider:
    return ClaudeProvider()
