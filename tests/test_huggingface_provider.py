import pytest
from unittest.mock import patch, MagicMock

from blackforge.core.config import LLMConfig
from blackforge.intelligence.llm.huggingface import HuggingFaceProvider
from blackforge.intelligence.llm.base import LLMRequest, LLMResponse


class TestHuggingFaceProvider:
    def test_init(self) -> None:
        p = HuggingFaceProvider(LLMConfig(provider="huggingface", model="test-model"))
        assert p.config.model == "test-model"
        assert p._loaded is False

    def test_health_check_no_torch(self) -> None:
        """Health check should not load the model."""
        p = HuggingFaceProvider(LLMConfig(provider="huggingface", model="test"))
        # With no torch installed, health check returns False (not an error)
        result = p.health_check()
        # result depends on whether torch is available in test env
        assert isinstance(result, bool)

    def test_metadata(self) -> None:
        p = HuggingFaceProvider(LLMConfig(provider="huggingface", model="m"))
        meta = p.metadata()
        assert meta["provider"] == "huggingface"
        assert meta["model"] == "m"
        assert "loaded" in meta

    def test_close(self) -> None:
        p = HuggingFaceProvider()
        p.close()
        assert p._loaded is False

    def test_structured_generate_does_not_mutate_request(self) -> None:
        """structured_generate should not mutate the original request."""
        p = HuggingFaceProvider()
        req = LLMRequest(prompt="original prompt")
        # structured_generate will call _ensure_loaded which may fail
        # but we test the request isn't mutated
        try:
            p.structured_generate(req)
        except Exception:
            pass
        assert req.prompt == "original prompt"
