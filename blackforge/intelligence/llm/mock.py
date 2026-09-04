from __future__ import annotations

from typing import Any

from blackforge.intelligence.llm.base import LLMProvider, LLMRequest, LLMResponse


class MockLLMProvider(LLMProvider):
    """Deterministic mock LLM for testing. No network calls."""

    def __init__(self, model: str = "mock-model") -> None:
        self._model = model

    def generate(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            content=f"[mock response to: {request.prompt[:80]}]",
            model=self._model,
            provider="mock",
            usage={"prompt_tokens": 0, "completion_tokens": 0},
            raw={"mock": True},
        )

    def health_check(self) -> bool:
        return True

    def metadata(self) -> dict[str, Any]:
        return {"provider": "mock", "model": self._model}
