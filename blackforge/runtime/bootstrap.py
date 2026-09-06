from __future__ import annotations

from typing import TYPE_CHECKING

from blackforge.auth.engine import AuthEngine
from blackforge.authorization import AuthorizationBoundary
from blackforge.business_logic.engine import BusinessLogicEngine
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.cloud.engine import CloudEngine
from blackforge.container.engine import ContainerEngine
from blackforge.core.config import BlackforgeConfig, load_config
from blackforge.core.errors import ConfigurationError
from blackforge.core.logging import get_logger, setup_logging
from blackforge.evidence.bridge import EvidenceMemoryBridge
from blackforge.evidence.repository import (
    EvidenceRepository,
    InMemoryEvidenceRepository,
    SQLiteEvidenceRepository,
)
from blackforge.evidence.store import EvidenceStore
from blackforge.identity.engine import IdentityEngine
from blackforge.intelligence.llm.mock import MockLLMProvider
from blackforge.intelligence.routing.router import ModelRouter
from blackforge.memory.manager import MemoryManager
from blackforge.memory.repository import InMemoryRepository, SQLiteMemoryRepository
from blackforge.mission.manager import MissionManager
from blackforge.network.engine import NetworkEngine
from blackforge.recon.engine import ReconEngine
from blackforge.webapi.engine import WebApiEngine
from blackforge.world_model.repository import (
    InMemoryWorldRepository,
    SQLiteWorldRepository,
)
from blackforge.world_model.store import WorldModelStore

if TYPE_CHECKING:
    from blackforge.intelligence.llm.base import LLMProvider
    from blackforge.memory.base import MemoryBackend
    from blackforge.world_model.repository import WorldRepository

log = get_logger("runtime.bootstrap")


def _resolve_evidence(
    config: BlackforgeConfig,
    backend: EvidenceRepository | None = None,
) -> EvidenceStore:
    """Resolve the evidence controller from configuration.

    An explicitly provided repository is wrapped in an :class:`EvidenceStore`.
    Otherwise ``evidence.backend`` selects SQLite (persistent) or an
    in-memory repository (testing/discardable).
    """
    if isinstance(backend, EvidenceStore):
        return backend
    if backend is not None:
        return EvidenceStore(repository=backend)
    if config.evidence.backend == "in_memory":
        return EvidenceStore(repository=InMemoryEvidenceRepository())
    return EvidenceStore(repository=SQLiteEvidenceRepository(config.evidence.db_path))


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


def _resolve_world_model(
    config: BlackforgeConfig,
    backend: WorldRepository | None = None,
) -> WorldModelStore:
    """Resolve the world model facade from configuration.

    An explicitly provided repository is wrapped in a :class:`WorldModelStore`.
    Otherwise ``world_model.backend`` selects SQLite (persistent) or an
    in-memory repository (testing/discardable).
    """
    if isinstance(backend, WorldModelStore):
        return backend
    if backend is not None:
        return WorldModelStore(repository=backend)
    if config.world_model.backend == "in_memory":
        return WorldModelStore(
            repository=InMemoryWorldRepository(),
        )
    return WorldModelStore(
        repository=SQLiteWorldRepository(config.world_model.db_path),
    )


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
        evidence_backend: EvidenceRepository | None = None,
        llm_provider: LLMProvider | None = None,
        world_model_backend: WorldRepository | None = None,
    ) -> None:
        self.config = config or load_config()
        setup_logging(self.config.log_level, self.config.app_name)

        log.info("blackforge_initializing", environment=self.config.environment)

        self.mission_manager = MissionManager()
        self.capability_registry = CapabilityRegistry()
        self.evidence_store: EvidenceStore = _resolve_evidence(
            self.config, evidence_backend
        )
        self.authorization = AuthorizationBoundary(mode=self.config.authorization.mode)

        self.memory: MemoryManager = _resolve_memory(self.config, memory_backend)
        self.evidence_bridge = EvidenceMemoryBridge(self.evidence_store, self.memory)
        self.world_model: WorldModelStore = _resolve_world_model(
            self.config, world_model_backend
        )
        self.recon_engine = ReconEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
        self.webapi_engine = WebApiEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
        self.auth_engine = AuthEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
        self.business_logic_engine = BusinessLogicEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
        self.network_engine = NetworkEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
        self.identity_engine = IdentityEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
        self.cloud_engine = CloudEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
        self.container_engine = ContainerEngine(
            capability_registry=self.capability_registry,
            evidence_store=self.evidence_store,
            world_model=self.world_model,
            memory_bridge=self.evidence_bridge,
            authorization=self.authorization,
        )
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
            "evidence_store_ready": self.evidence_store.health_check(),
            "evidence_memory_link_ready": (
                self.evidence_store.health_check() and self.memory.health_check()
            ),
            "world_model_ready": self.world_model.health_check(),
            "recon_ready": (
                self.recon_engine is not None
                and len(self.recon_engine.capabilities) == 6
            ),
            "webapi_ready": (
                self.webapi_engine is not None
                and len(self.webapi_engine.capabilities) == 10
            ),
            "auth_ready": (
                self.auth_engine is not None
                and len(self.auth_engine.capabilities) == 11
            ),
            "business_logic_ready": (
                self.business_logic_engine is not None
                and len(self.business_logic_engine.capabilities) == 11
            ),
            "network_ready": (
                self.network_engine is not None
                and len(self.network_engine.capabilities) == 11
            ),
            "identity_ready": (
                self.identity_engine is not None
                and len(self.identity_engine.capabilities) == 11
            ),
            "cloud_ready": (
                self.cloud_engine is not None
                and len(self.cloud_engine.capabilities) == 20
            ),
            "container_ready": (
                self.container_engine is not None
                and len(self.container_engine.capabilities) == 14
            ),
            "model_router_ready": self.model_router is not None,
        }

    def healthy(self) -> bool:
        checks = self.verify()
        return all(checks.values())


def bootstrap(
    config_path: str | None = None,
    memory_backend: MemoryBackend | None = None,
    evidence_backend: EvidenceRepository | None = None,
    llm_provider: LLMProvider | None = None,
    world_model_backend: WorldRepository | None = None,
) -> BlackforgeApp:
    try:
        config = load_config(config_path) if config_path else load_config()
    except Exception as exc:
        raise ConfigurationError(f"Failed to load configuration: {exc}") from exc

    app = BlackforgeApp(
        config=config,
        memory_backend=memory_backend,
        evidence_backend=evidence_backend,
        llm_provider=llm_provider,
        world_model_backend=world_model_backend,
    )

    if not app.healthy():
        failed = {k: v for k, v in app.verify().items() if not v}
        raise ConfigurationError(f"Bootstrap verification failed: {failed}")

    log.info("bootstrap_complete")
    return app
