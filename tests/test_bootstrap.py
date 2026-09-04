from blackforge.core.config import BlackforgeConfig
from blackforge.intelligence.llm.mock import MockLLMProvider
from blackforge.memory.models import InMemoryBackend
from blackforge.runtime.bootstrap import BlackforgeApp, bootstrap


class TestBootstrap:
    def test_blackforge_app_init(self) -> None:
        app = BlackforgeApp()
        assert app.config is not None
        assert app.mission_manager is not None
        assert app.capability_registry is not None
        assert app.evidence_store is not None
        assert app.authorization is not None
        assert app.memory is not None
        assert app.llm is not None
        assert app.model_router is not None

    def test_verify_all_healthy(self) -> None:
        app = BlackforgeApp()
        status = app.verify()
        assert all(status.values())

    def test_healthy(self) -> None:
        app = BlackforgeApp()
        assert app.healthy() is True

    def test_with_custom_backends(self) -> None:
        memory = InMemoryBackend()
        llm = MockLLMProvider("custom")
        app = BlackforgeApp(memory_backend=memory, llm_provider=llm)
        assert app.memory is memory
        assert app.llm is llm
        assert app.healthy()

    def test_bootstrap_function(self) -> None:
        app = bootstrap()
        assert app.healthy()
        checks = app.verify()
        assert checks["config_loaded"]
        assert checks["logging_initialized"]
        assert checks["mission_manager_ready"]
        assert checks["capability_registry_ready"]
        assert checks["memory_ready"]
        assert checks["llm_ready"]
        assert checks["authorization_ready"]
        assert checks["evidence_store_ready"]
        assert checks["model_router_ready"]

    def test_mission_creation_through_app(self) -> None:
        app = bootstrap()
        m = app.mission_manager.create("App Test Mission")
        assert m.name == "App Test Mission"

    def test_capability_execution_through_app(self) -> None:
        app = bootstrap()
        cap = app.capability_registry.get("mock_discovery")
        result = cap.execute("example.com")
        assert result.success is True

    def test_provider_resolves_to_mock(self) -> None:
        app = bootstrap()
        assert app.config.llm.provider == "mock"
        assert isinstance(app.llm, MockLLMProvider)
