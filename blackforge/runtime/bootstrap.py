from __future__ import annotations

from blackforge.authorization import AuthorizationBoundary
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.config import BlackforgeConfig, load_config
from blackforge.core.errors import ConfigurationError
from blackforge.core.logging import get_logger, setup_logging
from blackforge.evidence.store import EvidenceStore
from blackforge.intelligence.llm.base import LLMProvider
from blackforge.intelligence.llm.mock import MockLLMProvider
from blackforge.intelligence.routing.router import ModelRouter
from blackforge.memory.base import MemoryBackend
from blackforge.memory.models import InMemoryBackend
from blackforge.mission.manager import MissionManager

log = get_logger("runtime.bootstrap")


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

        self.memory: MemoryBackend = memory_backend or InMemoryBackend()
        self.llm: LLMProvider = llm_provider or MockLLMProvider()
        self.model_router = ModelRouter(default_provider=self.llm)

        self.capability_registry.register_defaults()

        log.info(
            "blackforge_initialized",
            environment=self.config.environment,
            capabilities=self.capability_registry.list_capabilities(),
        )

    def verify(self) -> dict[str, bool]:
        return {
            "config_loaded": self.config is not None,
            "logging_initialized": True,
            "mission_manager_ready": self.mission_manager is not None,
            "capability_registry_ready": len(self.capability_registry.list_capabilities()) > 0,
            "memory_ready": self.memory is not None,
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
