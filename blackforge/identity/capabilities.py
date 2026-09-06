from __future__ import annotations

from pydantic import Field

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType
from blackforge.identity.models import IdentityMode, IdentityObservationKind
from blackforge.identity.normalization import (
    IdentityToolAdapter,
    adapter_for_tool,
)
from blackforge.identity.transport import MockIdentityTransport

IDENTITY_CAPABILITY_IDS = [
    "identity.directory_discovery",
    "identity.identity_inventory",
    "identity.group_inventory",
    "identity.role_inventory",
    "identity.permission_inventory",
    "identity.resource_inventory",
    "identity.membership_observation",
    "identity.role_assignment_observation",
    "identity.permission_assignment_observation",
    "identity.relationship_analysis",
    "identity.metadata_observation",
]

_DIRECTORY_LEVEL_TOOLS = frozenset(
    {
        "discover_directories",
        "inventory_identities",
        "inventory_groups",
        "inventory_roles",
        "inventory_permissions",
        "inventory_resources",
    }
)

_IDENTITY_LEVEL_TOOLS = frozenset(
    {
        "observe_membership",
        "observe_role_assignment",
        "observe_permission_assignment",
        "analyze_relationships",
        "observe_metadata",
    }
)


class IdentityCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for identity capabilities."""

    category: str = "identity"
    mode: IdentityMode = IdentityMode.PASSIVE
    produces: list[IdentityObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    supported_target_types: list[TargetType],
    produces: list[IdentityObservationKind],
    *,
    version: str = "1.0.0",
) -> IdentityCapabilityMeta:
    return IdentityCapabilityMeta(
        id=CapabilityID(capability_id),
        name=capability_id,
        description=description,
        version=version,
        risk_level=RiskLevel.LOW,
        authorization_required=True,
        supported_target_types=supported_target_types,
        input_schema={
            "target": {"type": "string"},
            "params": {"type": "object"},
        },
        output_schema={"observations": {"type": "array"}},
        evidence_types_produced=["artifact", "observation"],
        mode=IdentityMode.PASSIVE,
        produces=produces,
    )


def build_identity_meta() -> list[IdentityCapabilityMeta]:
    """Metadata for all eleven identity & directory capabilities."""
    directory_level = [TargetType.DIRECTORY, TargetType.ASSET, TargetType.DOMAIN]
    identity_level = [
        TargetType.IDENTITY,
        TargetType.DIRECTORY,
        TargetType.ASSET,
        TargetType.DOMAIN,
    ]
    return [
        _meta(
            "identity.directory_discovery",
            "Discover directory services within the authorized environment.",
            directory_level,
            [IdentityObservationKind.DIRECTORY],
        ),
        _meta(
            "identity.identity_inventory",
            "Inventory identities and their directory attributes.",
            directory_level,
            [IdentityObservationKind.IDENTITY],
        ),
        _meta(
            "identity.group_inventory",
            "Inventory directory security groups.",
            directory_level,
            [IdentityObservationKind.GROUP],
        ),
        _meta(
            "identity.role_inventory",
            "Inventory directory roles and their privilege levels.",
            directory_level,
            [IdentityObservationKind.ROLE],
        ),
        _meta(
            "identity.permission_inventory",
            "Inventory permissions that roles can be assigned.",
            directory_level,
            [IdentityObservationKind.PERMISSION],
        ),
        _meta(
            "identity.resource_inventory",
            "Inventory resources that permissions apply to.",
            directory_level,
            [IdentityObservationKind.RESOURCE],
        ),
        _meta(
            "identity.membership_observation",
            "Observe the directory groups an identity belongs to.",
            identity_level,
            [IdentityObservationKind.MEMBERSHIP],
        ),
        _meta(
            "identity.role_assignment_observation",
            "Observe the roles assigned to an identity.",
            identity_level,
            [IdentityObservationKind.ROLE_ASSIGNMENT],
        ),
        _meta(
            "identity.permission_assignment_observation",
            "Observe the permissions granted through an identity's roles.",
            identity_level,
            [IdentityObservationKind.PERMISSION_ASSIGNMENT],
        ),
        _meta(
            "identity.relationship_analysis",
            "Analyze identity, group, role, permission, and resource relationships.",
            identity_level,
            [IdentityObservationKind.RELATIONSHIP],
        ),
        _meta(
            "identity.metadata_observation",
            "Observe descriptive metadata about an identity.",
            identity_level,
            [IdentityObservationKind.METADATA],
        ),
    ]


class IdentityCapability(Capability):
    """A typed identity capability bound to a mock transport method.

    ``execute`` runs the deterministic mock transport through the
    normalization adapter and returns normalized observations. It performs no
    authorization itself — the :class:`IdentityEngine` enforces scope /
    authorization before any execution path reaches the mock.
    """

    def __init__(
        self,
        meta: IdentityCapabilityMeta,
        tool_method: str,
        adapter: IdentityToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._transport = MockIdentityTransport()

    def meta(self) -> IdentityCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> IdentityToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        params = params or {}
        mode_param = params.get("mode")
        mode = IdentityMode(mode_param) if mode_param else self._meta.mode
        method = self._tool_method
        identity = params.get("identity")
        if method in _IDENTITY_LEVEL_TOOLS:
            raw = getattr(self._transport, method)(
                target, mode=mode, identity=identity
            )
        else:
            raw = getattr(self._transport, method)(target, mode=mode)
        normalized = self._adapter.adapt(raw, context={"target": target, "mode": mode})
        return CapabilityResult(
            success=True,
            output=[o.model_dump() for o in normalized.observations],
            metadata={
                "tool": method,
                "mode": mode.value,
                "target_type": "identity" if method in _IDENTITY_LEVEL_TOOLS else "directory",
                "warnings": normalized.warnings,
                "error": normalized.error,
                "mock": True,
            },
        )


def build_identity_capabilities() -> list[IdentityCapability]:
    """Instantiate all eleven typed identity capabilities (mock-backed)."""
    metas = build_identity_meta()
    tool_methods = [
        "discover_directories",
        "inventory_identities",
        "inventory_groups",
        "inventory_roles",
        "inventory_permissions",
        "inventory_resources",
        "observe_membership",
        "observe_role_assignment",
        "observe_permission_assignment",
        "analyze_relationships",
        "observe_metadata",
    ]
    adapters = [adapter_for_tool(method) for method in tool_methods]
    return [
        IdentityCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            metas,
            tool_methods,
            adapters,
            strict=True,
        )
    ]


__all__ = [
    "IDENTITY_CAPABILITY_IDS",
    "IdentityCapability",
    "IdentityCapabilityMeta",
    "build_identity_capabilities",
    "build_identity_meta",
]
