from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class Message(BaseModel):
    """A single message in a conversation context."""

    role: str  # system, user, assistant, tool
    content: str
    name: str | None = None
    tool_calls: list["ToolCall"] | None = None
    tool_call_id: str | None = None


class LLMRequest(BaseModel):
    prompt: str
    system_prompt: str | None = None
    messages: list[Message] | None = None
    temperature: float = 0.7
    max_tokens: int = 2048
    context: dict[str, Any] = Field(default_factory=dict)
    response_format: dict | None = None
    tools: list[dict] | None = None


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ToolCall(BaseModel):
    """Internal normalized tool-call representation, independent of any model."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "arguments": self.arguments, "id": self.id}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolCall:
        return cls(
            name=str(data.get("name", "")),
            arguments=data.get("arguments", {}),
            id=data.get("id"),
        )


class LLMResponse(BaseModel):
    content: str | None = None
    tool_calls: list[ToolCall] | None = None
    finish_reason: str = "stop"
    usage: Usage = Field(default_factory=Usage)
    model: str = ""
    provider: str = ""
    stdout: str | None = None
    elapsed_seconds: float | None = None
    retry_count: int = 0
    error: str | None = None
    raw: dict = Field(default_factory=dict)

    @classmethod
    def default(cls) -> LLMResponse:
        return cls(content="", model="mock", provider="mock")


class LLMProvider(ABC):
    """Provider-agnostic interface for language model inference.

    The rest of Blackforge depends only on this interface. Concrete providers
    (mock, Ollama, HuggingFace, OpenAI-compatible) implement it.
    """

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

    def close(self) -> None:
        """Release provider resources. No-op by default."""
        return None


# Resolve forward references
Message.model_rebuild()