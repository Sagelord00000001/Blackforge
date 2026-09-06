from __future__ import annotations

from pydantic import Field

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.container.models import ContainerMode, ContainerObservationKind
from blackforge.container.normalization import (
    ContainerToolAdapter,
    adapter_for_tool,
)
from blackforge.container.transport import MockContainerTransport
from blackforge.core.types import CapabilityID, RiskLevel, TargetType

CONTAINER_CAPABILITY_IDS = [
    "container.cluster_observation",
    "container.node_observation",
    "container.namespace_enumeration",
    "container.workload_observation",
    "container.pod_observation",
    "container.container_observation",
    "container.image_metadata_observation",
    "container.service_observation",
    "container.ingress_exposure_observation",
    "container.rbac_observation",
    "container.service_account_observation",
    "container.network_policy_observation",
    "container.security_context_observation",
    "container.resource_configuration_observation",
]


class ContainerCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for container security capabilities."""

    category: str = "container"
    mode: ContainerMode = ContainerMode.PASSIVE
    produces: list[ContainerObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    produces: list[ContainerObservationKind],
    *,
    version: str = "1.0.0",
) -> ContainerCapabilityMeta:
    return ContainerCapabilityMeta(
        id=CapabilityID(capability_id),
        name=capability_id,
        description=description,
        version=version,
        risk_level=RiskLevel.LOW,
        authorization_required=True,
        supported_target_types=[TargetType.ASSET, TargetType.CLOUD],
        input_schema={
            "target": {"type": "string"},
            "params": {"type": "object"},
        },
        output_schema={"observations": {"type": "array"}},
        evidence_types_produced=["artifact", "observation"],
        mode=ContainerMode.PASSIVE,
        produces=produces,
    )


def build_container_meta() -> list[ContainerCapabilityMeta]:
    """Metadata for all fourteen container / Kubernetes security capabilities."""
    return [
        _meta(
            "container.cluster_observation",
            "Observe a Kubernetes cluster and its descriptive top-level "
            "attributes (platform, version, node/namespace/workload counts).",
            [ContainerObservationKind.CLUSTER],
        ),
        _meta(
            "container.node_observation",
            "Observe cluster node records and their descriptive attributes.",
            [ContainerObservationKind.NODE],
        ),
        _meta(
            "container.namespace_enumeration",
            "Enumerate namespaces on an authorized cluster.",
            [ContainerObservationKind.NAMESPACE],
        ),
        _meta(
            "container.workload_observation",
            "Observe workloads (Deployments / StatefulSets / DaemonSets) and "
            "their descriptive scheduling and rollout attributes.",
            [
                ContainerObservationKind.WORKLOAD,
                ContainerObservationKind.DEPLOYMENT,
            ],
        ),
        _meta(
            "container.pod_observation",
            "Observe pods and their descriptive scheduling attributes.",
            [ContainerObservationKind.POD],
        ),
        _meta(
            "container.container_observation",
            "Observe container instances and their descriptive attributes.",
            [ContainerObservationKind.CONTAINER],
        ),
        _meta(
            "container.image_metadata_observation",
            "Observe image metadata and the registries that host them "
            "(never pulled content and never credentials).",
            [
                ContainerObservationKind.IMAGE,
                ContainerObservationKind.REGISTRY,
            ],
        ),
        _meta(
            "container.service_observation",
            "Observe Kubernetes Services and their descriptive routing metadata.",
            [ContainerObservationKind.SERVICE],
        ),
        _meta(
            "container.ingress_exposure_observation",
            "Observe Ingress objects exposing Services through named host rules.",
            [ContainerObservationKind.INGRESS],
        ),
        _meta(
            "container.rbac_observation",
            "Observe descriptive RBAC bindings (subject -> role -> permission).",
            [ContainerObservationKind.RBAC],
        ),
        _meta(
            "container.service_account_observation",
            "Observe ServiceAccounts and their reported attributes.",
            [ContainerObservationKind.SERVICE_ACCOUNT],
        ),
        _meta(
            "container.network_policy_observation",
            "Observe NetworkPolicies and their descriptive match/action rules.",
            [ContainerObservationKind.NETWORK_POLICY],
        ),
        _meta(
            "container.security_context_observation",
            "Observe security-context attributes for pods and containers from "
            "authoritative and correlated feeds.",
            [ContainerObservationKind.SECURITY_CONTEXT],
        ),
        _meta(
            "container.resource_configuration_observation",
            "Observe computed resource (limit/request) configuration and "
            "declared-vs-reported configuration discrepancies.",
            [
                ContainerObservationKind.RESOURCE_CONFIGURATION,
                ContainerObservationKind.CONFIGURATION_DISCREPANCY,
            ],
        ),
    ]


class ContainerCapability(Capability):
    """A typed container security capability bound to a mock transport method.

    ``execute`` runs the deterministic mock transport through the
    normalization adapter and returns normalized observations. It performs no
    authorization itself — the :class:`ContainerEngine` enforces scope /
    authorization before any execution path reaches the mock.
    """

    def __init__(
        self,
        meta: ContainerCapabilityMeta,
        tool_method: str,
        adapter: ContainerToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._transport = MockContainerTransport()

    def meta(self) -> ContainerCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> ContainerToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        params = params or {}
        mode_param = params.get("mode")
        mode = (
            ContainerMode(mode_param) if mode_param else self._meta.mode
        )
        method = self._tool_method
        raw = getattr(self._transport, method)(target, mode=mode)
        normalized = self._adapter.adapt(
            raw, context={"target": target, "mode": mode}
        )
        return CapabilityResult(
            success=True,
            output=[o.model_dump() for o in normalized.observations],
            metadata={
                "tool": method,
                "mode": mode.value,
                "capability": self.capability_id,
                "warnings": normalized.warnings,
                "error": normalized.error,
                "mock": True,
            },
        )


def build_container_capabilities() -> list[ContainerCapability]:
    """Instantiate all fourteen typed container capabilities (mock-backed)."""
    metas = build_container_meta()
    tool_methods = [
        "observe_clusters",
        "observe_nodes",
        "enumerate_namespaces",
        "observe_workloads",
        "observe_pods",
        "observe_containers",
        "observe_image_metadata",
        "observe_services",
        "observe_ingress",
        "observe_rbac",
        "observe_service_accounts",
        "observe_network_policies",
        "observe_security_contexts",
        "observe_resource_configuration",
    ]
    adapters = [adapter_for_tool(method) for method in tool_methods]
    return [
        ContainerCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            metas,
            tool_methods,
            adapters,
            strict=True,
        )
    ]


__all__ = [
    "CONTAINER_CAPABILITY_IDS",
    "ContainerCapability",
    "ContainerCapabilityMeta",
    "build_container_capabilities",
    "build_container_meta",
]
