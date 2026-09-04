from __future__ import annotations

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.mock import MockDiscoveryCapability
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.errors import CapabilityError
from blackforge.core.logging import get_logger

log = get_logger("capabilities.registry")


class CapabilityRegistry:
    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}

    def register(self, capability: Capability) -> None:
        meta = capability.meta()
        if meta.name in self._capabilities:
            log.warning("capability_duplicate", name=meta.name)
            raise CapabilityError(f"Capability already registered: {meta.name}")
        self._capabilities[meta.name] = capability
        log.info("capability_registered", name=meta.name, version=meta.version)

    def get(self, name: str) -> Capability:
        cap = self._capabilities.get(name)
        if not cap:
            raise CapabilityError(f"Capability not found: {name}")
        return cap

    def has(self, name: str) -> bool:
        return name in self._capabilities

    def list_capabilities(self) -> list[str]:
        return list(self._capabilities.keys())

    def list_meta(self) -> list[CapabilityMeta]:
        return [cap.meta() for cap in self._capabilities.values()]

    def register_defaults(self) -> None:
        self.register(MockDiscoveryCapability())
