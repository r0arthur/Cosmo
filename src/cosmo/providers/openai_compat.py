"""OpenAI-compatible providers (architecture §8).

Codex (OpenAI), DeepSeek, and local Llama (Ollama/vLLM) all speak the
OpenAI-style chat-completions API, so one implementation covers all three —
parameterized by endpoint, model, key, vendor, and data-export posture. Uses
stdlib HTTP (no extra dependency); the transport is injectable for testing.
"""
from __future__ import annotations

import json
import os
from typing import Callable

from ..diff import Diff
from ..findings import Finding
from .base import CROSS_CHECK, PRIMARY_REVIEW
from .parse import REVIEW_SYSTEM_PROMPT, build_review_prompt, parse_findings_json

# transport(url, headers, json_body) -> response dict
Transport = Callable[[str, dict, dict], dict]


class OpenAICompatProvider:
    def __init__(
        self,
        name: str,
        vendor: str,
        endpoint: str,
        model: str,
        *,
        key_env: str | None,
        exports_source: bool,
        roles: set[str],
        transport: Transport | None = None,
    ):
        self.name = name
        self.vendor = vendor
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.key_env = key_env
        self.exports_source = exports_source
        self.roles = roles
        self._transport = transport or _urllib_transport

    def available(self) -> bool:
        # Hosted providers need a key; a local endpoint (no key_env) is assumed reachable.
        if self.key_env is None:
            return True
        return bool(os.environ.get(self.key_env))

    def review(self, diff: Diff, context: str, findings_so_far: list[Finding]) -> list[Finding]:
        headers = {"Content-Type": "application/json"}
        if self.key_env:
            headers["Authorization"] = f"Bearer {os.environ.get(self.key_env, '')}"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
                {"role": "user", "content": build_review_prompt(diff, context, findings_so_far)},
            ],
            "temperature": 0,
        }
        resp = self._transport(f"{self.endpoint}/chat/completions", headers, body)
        text = resp["choices"][0]["message"]["content"]
        return parse_findings_json(text, source=f"model:{self.name}")

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.key_env:
            headers["Authorization"] = f"Bearer {os.environ.get(self.key_env, '')}"
        return headers

    def complete(self, prompt: str, *, max_tokens: int = 1024) -> str:
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        resp = self._transport(f"{self.endpoint}/chat/completions", self._headers(), body)
        return resp["choices"][0]["message"]["content"]


def _urllib_transport(url: str, headers: dict, json_body: dict) -> dict:  # pragma: no cover - network
    import urllib.request

    req = urllib.request.Request(
        url, data=json.dumps(json_body).encode(), headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


# --- built-in alternate definitions (architecture §8, §16) ------------------

def codex_provider(**kw) -> OpenAICompatProvider:
    return OpenAICompatProvider(
        "codex", "openai", "https://api.openai.com/v1", "gpt-4o",
        key_env="OPENAI_API_KEY", exports_source=True,
        roles={PRIMARY_REVIEW, CROSS_CHECK}, **kw,
    )


def deepseek_provider(**kw) -> OpenAICompatProvider:
    return OpenAICompatProvider(
        "deepseek", "deepseek", "https://api.deepseek.com/v1", "deepseek-chat",
        key_env="DEEPSEEK_API_KEY", exports_source=True,
        roles={PRIMARY_REVIEW, CROSS_CHECK}, **kw,
    )


def llama_provider(endpoint: str = "http://localhost:11434/v1", **kw) -> OpenAICompatProvider:
    # Local (Ollama/vLLM). Never leaves the box → eligible even for sensitive repos.
    # Declares only cross_check by default: a smaller local model isn't assumed
    # interchangeable as the primary reviewer (§8).
    return OpenAICompatProvider(
        "llama", "local", endpoint, "llama3.1",
        key_env=None, exports_source=False, roles={CROSS_CHECK}, **kw,
    )
