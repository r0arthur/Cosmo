"""Claude — the built-in default provider (architecture §8).

Hardcoded default and fallback. If the `anthropic` SDK isn't installed or no API
key is set, `available()` is False and the engine records a skipped stage rather
than silently dropping the LLM review (§8: never silently skip review).
"""
from __future__ import annotations

import os

from ..diff import Diff
from ..findings import Finding
from .base import CROSS_CHECK, PRIMARY_REVIEW
from .parse import REVIEW_SYSTEM_PROMPT, build_review_prompt, parse_findings_json

_MODEL = "claude-opus-4-8"  # default review model; see claude-api skill for current ids


class ClaudeProvider:
    name = "claude"
    vendor = "anthropic"
    exports_source = True   # hosted; the diff is sent to Anthropic
    roles = {PRIMARY_REVIEW, CROSS_CHECK}

    _ENDPOINT = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: str = _MODEL, *, broker=None):
        self.model = model
        self.broker = broker

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
        from .egress import guard_provider_egress

        guard_provider_egress(self.broker, self._ENDPOINT, "model:claude")
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=REVIEW_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_review_prompt(diff, context, findings_so_far)}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return parse_findings_json(text, source="model:claude")

    def complete(self, prompt: str, *, max_tokens: int = 1024) -> str:
        import anthropic
        from .egress import guard_provider_egress

        guard_provider_egress(self.broker, self._ENDPOINT, "model:claude")
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")


def get_default_provider() -> ClaudeProvider:
    return ClaudeProvider()
