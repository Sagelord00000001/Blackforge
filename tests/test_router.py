import pytest
from unittest.mock import patch, MagicMock

from blackforge.core.types import TaskCategory
from blackforge.intelligence.llm.base import LLMRequest, LLMResponse
from blackforge.intelligence.llm.mock import MockLLMProvider
from blackforge.intelligence.routing.router import ModelRouter, RoutingRule


class TestModelRouter:
    def test_default_routing(self) -> None:
        default = MockLLMProvider("default")
        router = ModelRouter(default_provider=default)
        resp = router.route(TaskCategory.ANALYSIS, LLMRequest(prompt="test"))
        assert resp.provider == "mock"

    def test_custom_rule_routing(self) -> None:
        default = MockLLMProvider("default")
        specialized = MockLLMProvider("specialized")
        router = ModelRouter(default_provider=default)
        router.register_provider("specialized", specialized)
        router.add_rule(
            RoutingRule(category=TaskCategory.ANALYSIS, provider_name="specialized", priority=10)
        )
        resp = router.route(TaskCategory.ANALYSIS, LLMRequest(prompt="test"))
        assert resp.model == "specialized"

    def test_rule_priority(self) -> None:
        default = MockLLMProvider("default")
        low = MockLLMProvider("low")
        high = MockLLMProvider("high")
        router = ModelRouter(default_provider=default)
        router.register_provider("low", low)
        router.register_provider("high", high)
        router.add_rule(RoutingRule(category=TaskCategory.ANALYSIS, provider_name="low", priority=1))
        router.add_rule(RoutingRule(category=TaskCategory.ANALYSIS, provider_name="high", priority=10))
        resp = router.route(TaskCategory.ANALYSIS, LLMRequest(prompt="test"))
        assert resp.model == "high"

    def test_health_check(self) -> None:
        default = MockLLMProvider("default")
        router = ModelRouter(default_provider=default)
        results = router.health_check()
        assert results["default"] is True


class TestModelRouterFallback:
    def test_fallback_on_primary_failure(self) -> None:
        class FailProvider(MockLLMProvider):
            def generate(self, request: LLMRequest) -> LLMResponse:
                raise RuntimeError("primary failure")

        primary = FailProvider()
        fallback = MockLLMProvider("fallback_model")
        router = ModelRouter(default_provider=primary)
        router.set_fallback(fallback)
        resp = router.route(TaskCategory.ANALYSIS, LLMRequest(prompt="test"))
        assert resp.model == "fallback_model"
        assert resp.provider == "mock"

    def test_no_fallback_raises_original(self) -> None:
        class FailProvider(MockLLMProvider):
            def generate(self, request: LLMRequest) -> LLMResponse:
                raise RuntimeError("boom")

        primary = FailProvider()
        router = ModelRouter(default_provider=primary)
        with pytest.raises(RuntimeError, match="boom"):
            router.route(TaskCategory.ANALYSIS, LLMRequest(prompt="test"))

    def test_fallback_also_fails_raises_original(self) -> None:
        class FailProvider(MockLLMProvider):
            def generate(self, request: LLMRequest) -> LLMResponse:
                raise RuntimeError("all fail")

        primary = FailProvider()
        fallback = FailProvider()
        router = ModelRouter(default_provider=primary)
        router.set_fallback(fallback)
        with pytest.raises(RuntimeError, match="all fail"):
            router.route(TaskCategory.ANALYSIS, LLMRequest(prompt="test"))
