"""Claude via the Claude Code CLI (architecture §8 + §17).

An alternative to the API-key `ClaudeProvider`: instead of calling the Anthropic
Messages API with an `ANTHROPIC_API_KEY`, this shells out to the installed
`claude` binary (Claude Code) in headless/print mode (`claude -p`). That runs the
review on the user's Claude Code **subscription** — no separate API key, no API
billing — which is the §17 "reuse Claude Code's auth/session, don't fork it"
posture applied to the reviewer role itself.

Data-governance note (§8): `exports_source = True`. Shelling to `claude` still
sends the diff to Anthropic — it's the same vendor, just a different auth/billing
path — so the §8 sensitivity gate treats it exactly like the hosted API provider.

Egress note (§9a): calls go through the `claude` CLI, which does its own
networking, so cosmo's PROVIDER-mode egress broker does **not** wrap them. This
is inherent to reusing an external harness; the `broker` attribute is accepted
for interface parity but is not a chokepoint for this backend.
"""
from __future__ import annotations

import shutil
import subprocess

from ..diff import Diff
from ..findings import Finding
from .base import CROSS_CHECK, PRIMARY_REVIEW
from .parse import REVIEW_SYSTEM_PROMPT, build_review_prompt, parse_findings_json

_BIN = "claude"


class ClaudeCLIProvider:
    name = "claude-cli"
    vendor = "anthropic"
    exports_source = True   # the diff still goes to Anthropic, via the CLI/subscription
    roles = {PRIMARY_REVIEW, CROSS_CHECK}

    def __init__(self, model: str | None = None, *, timeout: int = 300, broker=None):
        self.model = model            # None → the CLI's configured default model
        self.timeout = timeout
        self.broker = broker          # accepted for parity; see module docstring

    def available(self) -> bool:
        return shutil.which(_BIN) is not None

    def _run_cli(self, prompt: str) -> str:
        # Prompt goes on stdin (not argv) so a large diff can't hit ARG_MAX.
        cmd = [_BIN, "-p", "--output-format", "text"]
        if self.model:
            cmd += ["--model", self.model]
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=self.timeout
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"claude CLI exited {proc.returncode}: {proc.stderr.strip()[:300]}"
            )
        return proc.stdout

    def review(self, diff: Diff, context: str, findings_so_far: list[Finding]) -> list[Finding]:
        # The CLI has no separate system-prompt channel here, so the review
        # instructions are prepended to the user prompt.
        prompt = (
            REVIEW_SYSTEM_PROMPT
            + "\n\n"
            + build_review_prompt(diff, context, findings_so_far)
        )
        return parse_findings_json(self._run_cli(prompt), source="model:claude-cli")

    def complete(self, prompt: str, *, max_tokens: int = 1024) -> str:
        # max_tokens isn't a CLI knob; accepted for the ModelProvider contract.
        return self._run_cli(prompt).strip()
