from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from blackforge.core.logging import get_logger
from blackforge.core.types import TaskCategory
from blackforge.intelligence.llm.base import LLMProvider, LLMRequest, LLMResponse

log = get_logger("intelligence.router")


class RoutingRule(BaseModel):
    category: TaskCategory
    provider_name: str
    model: str | None = None
    priority: int = 0


class ModelRouter:
    def __init__(self, default_provider: LLMProvider) -> None:
        self._default_provider = default_provider
        self._rules: list[RoutingRule] = []
        self._providers: dict[str, LLMProvider] = {}

    def register_provider(self, name: str, provider: LLMProvider) -> None:
        self._providers[name] = provider
        log.info("provider_registered", name=name)

    def add_rule(self, rule: RoutingRule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def route(
        self, category: TaskCategory, request: LLMRequest
    ) -> LLMResponse:
        provider = self._resolve_provider(category)
        log.debug("routing_request", category=category.value, provider=provider.metadata().get("provider"))
        return provider.generate(request)

    def _resolve_provider(self, category: TaskCategory) -> LLMProvider:
        for rule in self._rules:
            if rule.category == category and rule.provider_name in self._providers:
                return self._providers[rule.provider_name]
        return self._default_provider

    def health_check(self) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for name, provider in self._providers.items():
            results[name] = provider.health_check()
        results["default"] = self._default_provider.health_check()
        return results
