from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class LLMRequest(BaseModel):
    prompt: str
    system_prompt: str | None = None
    temperature: float = 0.7
    max_tokens: int = 2048
    response_format: dict | None = None
    tools: list[dict] | None = None


class LLMResponse(BaseModel):
    content: str | None = None
    tool_calls: list[dict] | None = None
    finish_reason: str = "stop"
    usage: dict = Field(default_factory=dict)
    model: str = ""
    provider: str = ""
    raw: dict = Field(default_factory=dict)

    @classmethod
    def default(cls) -> LLMResponse:
        return cls(content="", model="mock", provider="mock")


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        ...

    def structured_generate(
        self, request: LLMRequest, schema: dict | None = None
    ) -> LLMResponse:
        return self.generate(request)

    def tool_call(
        self, request: LLMRequest, tools: list[dict] | None = None
    ) -> LLMResponse:
        request.tools = tools
        return self.generate(request)

    def health_check(self) -> bool:
        return True

    def metadata(self) -> dict[str, Any]:
        return {"provider": "unknown", "model": "unknown"}
