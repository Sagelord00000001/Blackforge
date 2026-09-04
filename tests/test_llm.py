from blackforge.intelligence.llm.base import LLMRequest, LLMResponse
from blackforge.intelligence.llm.mock import MockLLMProvider


class TestMockLLMProvider:
    def test_generate(self) -> None:
        provider = MockLLMProvider()
        resp = provider.generate(LLMRequest(prompt="hello"))
        assert resp.content is not None
        assert "mock" in resp.provider

    def test_health_check(self) -> None:
        provider = MockLLMProvider()
        assert provider.health_check() is True

    def test_metadata(self) -> None:
        provider = MockLLMProvider(model="test-model")
        meta = provider.metadata()
        assert meta["provider"] == "mock"
        assert meta["model"] == "test-model"

    def test_structured_generate(self) -> None:
        provider = MockLLMProvider()
        resp = provider.structured_generate(
            LLMRequest(prompt="structured"), schema={"type": "object"}
        )
        assert resp.content is not None

    def test_tool_call(self) -> None:
        provider = MockLLMProvider()
        resp = provider.tool_call(
            LLMRequest(prompt="tools"), tools=[{"name": "test"}]
        )
        assert resp.content is not None


class TestLLMResponse:
    def test_default(self) -> None:
        resp = LLMResponse.default()
        assert resp.provider == "mock"
        assert resp.model == "mock"
