from __future__ import annotations

from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.config import BlackforgeConfig, load_config
from blackforge.core.errors import ConfigurationError
from blackforge.core.logging import get_logger, setup_logging
from blackforge.evidence.store import EvidenceStore
from blackforge.intelligence.llm.mock import MockLLMProvider
from blackforge.intelligence.routing.router import ModelRouter
from blackforge.memory.manager import MemoryManager
from blackforge.memory.repository import InMemoryRepository, SQLiteMemoryRepository
from blackforge.mission.manager import MissionManager

if TYPE_CHECKING:
    from blackforge.intelligence.llm.base import LLMProvider
    from blackforge.memory.base import MemoryBackend

log = get_logger("runtime.bootstrap")


def _resolve_memory(
    config: BlackforgeConfig,
    backend: MemoryBackend | None = None,
) -> MemoryManager:
    """Resolve the memory facade from configuration.

    An explicitly provided backend is wrapped in a :class:`MemoryManager`.
    Otherwise the ``memory.backend`` setting selects SQLite (persistent) or
    an in-memory repository (testing/discardable).
    """
    if isinstance(backend, MemoryManager):
        return backend
    if backend is not None:
        return MemoryManager(repository=backend)
    if config.memory.backend == "in_memory":
        return MemoryManager(repository=InMemoryRepository())
    return MemoryManager(repository=SQLiteMemoryRepository(config.memory.db_path))


def _resolve_provider(config: BlackforgeConfig) -> LLMProvider:
    """Resolve LLMProvider from configuration.

    Providers:
      - 'mock': MockLLMProvider (default, always works)
      - 'ollama': OllamaProvider (requires Ollama server)
      - 'huggingface' / 'hf': HuggingFaceProvider (requires torch+transformers)
    """
    provider_name = config.llm.provider.lower()

    if provider_name in ("mock", "testing"):
        return MockLLMProvider(model=config.llm.model)

    if provider_name == "ollama":
        from blackforge.intelligence.llm.ollama import OllamaProvider

        return OllamaProvider(config=config.llm)

    if provider_name in ("huggingface", "hf", "transformers"):
        from blackforge.intelligence.llm.huggingface import HuggingFaceProvider

        return HuggingFaceProvider(config=config.llm)

    log.warning("unknown_provider_falling_back_to_mock", provider=provider_name)
    return MockLLMProvider(model=config.llm.model)


class BlackforgeApp:
    def __init__(
        self,
        config: BlackforgeConfig | None = None,
        memory_backend: MemoryBackend | None = None,
        llm_provider: LLMProvider | None = None,
    ) -> None:
        self.config = config or load_config()
        setup_logging(self.config.log_level, self.config.app_name)

        log.info("blackforge_initializing", environment=self.config.environment)

        self.mission_manager = MissionManager()
        self.capability_registry = CapabilityRegistry()
        self.evidence_store = EvidenceStore()
        self.authorization = AuthorizationBoundary(mode=self.config.authorization.mode)

        self.memory: MemoryManager = _resolve_memory(self.config, memory_backend)
        self.llm: LLMProvider = llm_provider or _resolve_provider(self.config)
        self.model_router = ModelRouter(default_provider=self.llm)

        self.capability_registry.register_defaults()

        log.info(
            "blackforge_initialized",
            environment=self.config.environment,
            provider=self.llm.metadata().get("provider", "?"),
            model=self.llm.metadata().get("model", "?"),
            capabilities=self.capability_registry.list_capabilities(),
        )

    def verify(self) -> dict[str, bool]:
        return {
            "config_loaded": self.config is not None,
            "logging_initialized": True,
            "mission_manager_ready": self.mission_manager is not None,
            "capability_registry_ready": len(self.capability_registry.list_capabilities()) > 0,
            "memory_ready": self.memory.health_check(),
            "llm_ready": self.llm.health_check(),
            "authorization_ready": self.authorization is not None,
            "evidence_store_ready": self.evidence_store is not None,
            "model_router_ready": self.model_router is not None,
        }

    def healthy(self) -> bool:
        checks = self.verify()
        return all(checks.values())


def bootstrap(
    config_path: str | None = None,
    memory_backend: MemoryBackend | None = None,
    llm_provider: LLMProvider | None = None,
) -> BlackforgeApp:
    try:
        config = load_config(config_path) if config_path else load_config()
    except Exception as exc:
        raise ConfigurationError(f"Failed to load configuration: {exc}") from exc

    app = BlackforgeApp(
        config=config,
        memory_backend=memory_backend,
        llm_provider=llm_provider,
    )

    if not app.healthy():
        failed = {k: v for k, v in app.verify().items() if not v}
        raise ConfigurationError(f"Bootstrap verification failed: {failed}")

    log.info("bootstrap_complete")
    return app
