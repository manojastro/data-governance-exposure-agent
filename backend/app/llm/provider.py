"""LLM provider abstraction.

The deterministic engines compute every conclusion; the LLM layer ONLY turns
supplied facts into reasoning narratives. The MockLLMProvider is fully
deterministic (identical inputs -> byte-identical output) and never invents
facts: it formats exactly the dict handed to it.

OpenAICompatibleProvider posts to any /chat/completions endpoint via httpx and
degrades to mock-style output on failure so investigations never block on an
external service. API keys are never logged.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)


class LLMError(RuntimeError):
    pass


class LLMProvider(Protocol):
    mode: str

    def summarize_stage(self, agent: str, facts: dict[str, Any]) -> dict[str, Any]:
        """Return {'mode', 'narrative', 'model'} built from facts only."""
        ...


def _fmt(v: Any) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, default=str, sort_keys=True)
    return str(v)


class MockLLMProvider:
    """Deterministic, facts-only narrative provider. mode='mock'."""

    mode = "mock"
    model = "mock-deterministic"

    def summarize_stage(self, agent: str, facts: dict[str, Any]) -> dict[str, Any]:
        lines = [f"[mock] {agent} stage summary:"]
        for key in sorted(facts.keys()):
            lines.append(f"- {key}: {_fmt(facts[key])}")
        narrative = "\n".join(lines) + (
            f"\nConclusion is computed by the deterministic {agent} engine; this "
            "narrative restates supplied facts only.")
        return {"mode": self.mode, "narrative": narrative, "model": self.model}


class OpenAICompatibleProvider:
    """Any OpenAI-compatible /chat/completions endpoint. mode='openai-compatible'.

    On transport/API failure, falls back to deterministic mock narration so
    that governance workflows remain available (flagged mode='mock-fallback').
    """

    mode = "openai-compatible"

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout_s: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key          # never logged
        self.model = model or "gpt-4o-mini"
        self.timeout_s = timeout_s
        self._fallback = MockLLMProvider()

    def summarize_stage(self, agent: str, facts: dict[str, Any]) -> dict[str, Any]:
        system = (
            "You are the narrator inside a data-access-governance platform. "
            "You receive JSON FACTS produced by deterministic engines. Restate "
            "and connect ONLY those facts into a short reasoning summary. "
            "Never add numbers, names or conclusions not present in the facts."
        )
        user = json.dumps({"agent": agent, "facts": facts}, default=str, sort_keys=True)
        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                resp = client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json={"model": self.model,
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user}],
                          "temperature": 0},
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
            return {"mode": self.mode, "narrative": content, "model": self.model}
        except Exception as exc:  # noqa: BLE001 - degrade gracefully
            logger.warning("LLM call failed (%s); using deterministic fallback.", type(exc).__name__)
            out = self._fallback.summarize_stage(agent, facts)
            out["mode"] = "mock-fallback"
            return out


def get_provider(settings=None) -> LLMProvider:
    from app.config import get_settings

    s = settings or get_settings()
    if s.LLM_MODE == "openai-compatible" and s.LLM_BASE_URL:
        return OpenAICompatibleProvider(s.LLM_BASE_URL, s.LLM_API_KEY, s.LLM_MODEL)
    return MockLLMProvider()
