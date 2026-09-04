import pytest

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.mock import MockDiscoveryCapability
from blackforge.capabilities.models import CapabilityMeta
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import CapabilityError
from blackforge.core.types import RiskLevel, TargetType


class TestMockCapability:
    def test_meta(self) -> None:
        cap = MockDiscoveryCapability()
        meta = cap.meta()
        assert meta.name == "mock_discovery"
        assert meta.version == "1.0.0"
        assert meta.risk_level == RiskLevel.INFORMATIONAL

    def test_execute(self) -> None:
        cap = MockDiscoveryCapability()
        result = cap.execute("example.com")
        assert result.success is True
        assert "example.com" in str(result.output)


class TestCapabilityRegistry:
    def test_register_and_get(self) -> None:
        registry = CapabilityRegistry()
        cap = MockDiscoveryCapability()
        registry.register(cap)
        assert registry.has("mock_discovery")
        retrieved = registry.get("mock_discovery")
        assert retrieved.meta().name == "mock_discovery"

    def test_duplicate_registration(self) -> None:
        registry = CapabilityRegistry()
        cap = MockDiscoveryCapability()
        registry.register(cap)
        with pytest.raises(CapabilityError, match="already registered"):
            registry.register(cap)

    def test_get_nonexistent(self) -> None:
        registry = CapabilityRegistry()
        with pytest.raises(CapabilityError, match="not found"):
            registry.get("nonexistent")

    def test_list_capabilities(self) -> None:
        registry = CapabilityRegistry()
        registry.register(MockDiscoveryCapability())
        names = registry.list_capabilities()
        assert "mock_discovery" in names

    def test_list_meta(self) -> None:
        registry = CapabilityRegistry()
        registry.register(MockDiscoveryCapability())
        metas = registry.list_meta()
        assert len(metas) == 1
        assert isinstance(metas[0], CapabilityMeta)

    def test_register_defaults(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        assert registry.has("mock_discovery")
        assert len(registry.list_capabilities()) == 1
