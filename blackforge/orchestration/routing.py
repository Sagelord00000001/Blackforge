"""Typed capability routing for the mission orchestration layer.

The router maps a registered capability id to:

* the engine that owns it (recon, webapi, auth, ...),
* the engine's *typed* request model,
* the engine's default observation mode,

and builds fully typed request objects. It never executes anything; the
orchestrator calls :meth:`~blackforge.orchestration.routing.CapabilityRouter.
adapter_for` and the engine ``run(...)`` only after every gate has passed.

The router is also the single source of truth for the mission-aware
capability view the Development Console renders.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from blackforge.core.types import MissionID, SessionID, TargetType
from blackforge.orchestration.models import AdapterMode, CapabilityView, CapabilityViewRow

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from blackforge.capabilities.interface import CapabilityMeta
    from blackforge.scope.models import TargetScope


@dataclass(frozen=True)
class EngineBinding:
    """Ownership of a capability id prefix and how to build its request."""

    prefix: str
    engine_attr: str
    request_module: str
    request_class: str
    mode_attr: str = "mode"

    def score(self, capability_id: str) -> int:
        if capability_id.startswith(self.prefix):
            return len(self.prefix)
        return -1

    def request_type(self) -> type:
        from importlib import import_module

        module = import_module(f"blackforge.{self.request_module}.models")
        return getattr(module, self.request_class)


_ENGINE_BINDINGS: list[EngineBinding] = [
    EngineBinding("recon.", "recon_engine", "recon", "ReconRequest"),
    EngineBinding("webapi.", "webapi_engine", "webapi", "WebApiRequest"),
    EngineBinding("auth.", "auth_engine", "auth", "AuthRequest"),
    EngineBinding(
        "business_logic.",
        "business_logic_engine",
        "business_logic",
        "BusinessLogicRequest",
    ),
    EngineBinding("network.", "network_engine", "network", "NetworkRequest"),
    EngineBinding("identity.", "identity_engine", "identity", "IdentityRequest"),
    EngineBinding("cloud.", "cloud_engine", "cloud", "CloudRequest"),
    EngineBinding("container.", "container_engine", "container", "ContainerRequest"),
    EngineBinding(
        "source_runtime.",
        "source_runtime_engine",
        "source_runtime",
        "SourceRuntimeRequest",
    ),
]


def _engine_prefix(capability_id: str) -> str | None:
    return next(
        (
            binding.prefix
            for binding in _ENGINE_BINDINGS
            if capability_id.startswith(binding.prefix)
        ),
        None,
    )


class CapabilityRouter:
    """Resolves capability ids to engines, requests and adapters."""

    def __init__(
        self,
        registry: Any,
        engines: dict[str, Any],
        real_adapters: Any | None = None,
    ) -> None:
        self._registry = registry
        self._engines = engines
        self._real_adapters = real_adapters

    # ------------------------------------------------------------------
    # Registry access
    # ------------------------------------------------------------------
    def list_registered(self) -> list[str]:
        return [meta.id for meta in self._registry.list_meta()]

    def meta(self, capability_id: str) -> CapabilityMeta:
        meta = self._registry.get(capability_id)
        if meta is None:
            raise KeyError(f"unknown capability: {capability_id}")
        return meta

    def meta_of(
        self, capability_id: str, *, raise_on_missing: bool = False
    ) -> CapabilityMeta | None:
        """Fetch metadata for a capability id (``None`` when not registered)."""
        try:
            capability = self._registry.get(capability_id)
        except Exception:
            if raise_on_missing:
                raise KeyError(f"unknown capability: {capability_id}") from None
            return None
        return capability.meta()

    def engine_for(self, capability_id: str) -> Any:
        prefix = _engine_prefix(capability_id)
        if prefix is None:
            return None
        binding = next(b for b in _ENGINE_BINDINGS if b.prefix == prefix)
        return self._engines.get(binding.engine_attr)

    def binding_for(self, capability_id: str) -> EngineBinding | None:
        prefix = _engine_prefix(capability_id)
        if prefix is None:
            return None
        return next(b for b in _ENGINE_BINDINGS if b.prefix == prefix)

    # ------------------------------------------------------------------
    # Typed request construction
    # ------------------------------------------------------------------
    def build_request(
        self,
        capability_id: str,
        mission_id: MissionID,
        scope: TargetScope,
        session_id: SessionID | None = None,
        **overrides: object,
    ) -> Any:
        """Build the correctly typed request object for a capability.

        The request's mode is left to the engine's typed default (the
        engine's standard bounded observation mode); unknown capabilities
        raise ``KeyError``, which the orchestrator treats as a blocked step
        (fail closed) rather than executing anything.
        """
        binding = self.binding_for(capability_id)
        if binding is None:
            raise KeyError(f"no engine binding for capability: {capability_id}")
        kwargs: dict[str, object] = {
            "mission_id": mission_id,
            "scope": scope,
            "session_id": session_id,
        }
        kwargs.update(overrides)
        return binding.request_type()(**kwargs)

    def default_mode_for(self, capability_id: str) -> str:
        """Engine-default observation mode for a capability id."""
        binding = self.binding_for(capability_id)
        if binding is None:
            return "unknown"
        field = binding.request_type().model_fields.get("mode")
        default = getattr(field, "default", None) if field else None
        return getattr(default, "value", default.value if hasattr(default, "value") else "") or ""

    # ------------------------------------------------------------------
    # Adaptivity
    # ------------------------------------------------------------------
    def real_controlled(self) -> list[str]:
        if self._real_adapters is None:
            return []
        return self._real_adapters.installed_capability_ids()

    def adapter_for(self, capability_id: str) -> Any | None:
        if self._real_adapters is None:
            return None
        return self._real_adapters.get(capability_id)

    def adapter_mode_for(self, capability_id: str) -> AdapterMode:
        if self.adapter_for(capability_id) is not None:
            return AdapterMode.REAL_CONTROLLED
        return AdapterMode.MOCK_ONLY

    # ------------------------------------------------------------------
    # Mission-aware view
    # ------------------------------------------------------------------
    def applicable(self, target_type: TargetType | list[TargetType]) -> list[str]:
        accepts = [target_type] if isinstance(target_type, TargetType) else list(target_type)
        out: list[str] = []
        for meta in self._registry.list_meta():
            overlap = set(meta.supported_target_types) & set(accepts)
            if overlap:
                out.append(meta.id)
        return out

    def view(
        self,
        mission_id: MissionID,
        scope: TargetScope,
        seed_target_type: TargetType | list[TargetType],
        executed: dict[tuple[str, str], int] | None = None,
    ) -> CapabilityView:
        """Build the console capability table for a mission."""
        executed = executed or {}
        rows: list[CapabilityViewRow] = []
        registered = 0
        count_auth = 0
        for meta in self._registry.list_meta():
            supported = meta.supported_target_types or []
            if not supported:
                continue
            registered += 1
            applicable = any(
                target_type in supported for target_type in (
                    seed_target_type if isinstance(seed_target_type, list) else [seed_target_type]
                )
            )
            authorized = scope.is_capability_allowed(meta.id)
            mode = self.adapter_mode_for(meta.id)
            executed_count = executed.get((meta.id, ""), 0)
            rows.append(
                CapabilityViewRow(
                    capability=meta.id,
                    name=meta.name,
                    category=str(meta.id).split(".", 1)[0],
                    mode=self.default_mode_for(meta.id),
                    risk_level=meta.risk_level,
                    target_types=list(supported),
                    adapter=mode,
                    applicable=applicable,
                    authorized=authorized,
                    executed_count=executed_count,
                )
            )
            if authorized and applicable:
                count_auth += 1
        real_count = sum(1 for row in rows if row.adapter == AdapterMode.REAL_CONTROLLED)
        return CapabilityView(
            registered=registered,
            applicable=sum(1 for row in rows if row.applicable),
            authorized=count_auth,
            real_controlled=real_count,
            rows=rows,
        )


def registry_capability_ids(registry: Any) -> set[str]:
    return {meta.id for meta in registry.list_meta()}


__all__ = [
    "CapabilityRouter",
    "EngineBinding",
    "registry_capability_ids",
]
