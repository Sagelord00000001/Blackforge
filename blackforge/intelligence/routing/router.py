from __future__ import annotations

from pydantic import BaseModel

from blackforge.core.logging import get_logger
from blackforge.core.types import TaskCategory
from blackforge.intelligence.llm.base import LLMProvider, LLMRequest, LLMResponse

log = get_logger("intelligence.router")


class RoutingRule(BaseModel):
    category: TaskCategory
    provider_name: str
    priority: int = 0


class ModelRouter:
    def __init__(self, default_provider: LLMProvider) -> None:
        self._default_provider = default_provider
        self._rules: list[RoutingRule] = []
        self._providers: dict[str, LLMProvider] = {}
        self._fallback_providers: list[LLMProvider] = []

    def register_provider(self, name: str, provider: LLMProvider) -> None:
        self._providers[name] = provider
        log.info("provider_registered", name=name)

    def set_fallback(self, *providers: LLMProvider) -> None:
        self._fallback_providers = list(providers)

    def add_rule(self, rule: RoutingRule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def route(self, category: TaskCategory, request: LLMRequest) -> LLMResponse:
        provider = self._resolve_provider(category)
        try:
            return provider.generate(request)
        except Exception as exc:
            log.warning(
                "primary_provider_failed",
                category=category.value,
                provider=provider.metadata().get("provider", "?"),
                error=str(exc)[:200],
            )
            return self._fallback(category, request, exc)

    def _resolve_provider(self, category: TaskCategory) -> LLMProvider:
        for rule in self._rules:
            if rule.category == category and rule.provider_name in self._providers:
                return self._providers[rule.provider_name]
        return self._default_provider

    def _fallback(
        self,
        category: TaskCategory,
        request: LLMRequest,
        original_error: Exception,
    ) -> LLMResponse:
        if not self._fallback_providers:
            raise original_error

        for fb in self._fallback_providers:
            try:
                log.info(
                    "fallback_provider_attempt",
                    category=category.value,
                    fallback_provider=fb.metadata().get("provider", "?"),
                )
                return fb.generate(request)
            except Exception as fb_exc:
                log.warning(
                    "fallback_provider_failed",
                    fallback_provider=fb.metadata().get("provider", "?"),
                    error=str(fb_exc)[:200],
                )
                continue

        raise original_error

    def health_check(self) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for name, provider in self._providers.items():
            results[name] = provider.health_check()
        results["default"] = self._default_provider.health_check()
        for i, fb in enumerate(self._fallback_providers):
            results[f"fallback_{i}"] = fb.health_check()
        return results
