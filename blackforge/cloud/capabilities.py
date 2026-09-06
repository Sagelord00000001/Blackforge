from __future__ import annotations

from pydantic import Field

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.cloud.models import CloudMode, CloudObservationKind
from blackforge.cloud.normalization import CloudToolAdapter, adapter_for_tool
from blackforge.cloud.transport import MockCloudTransport
from blackforge.core.types import CapabilityID, RiskLevel, TargetType

CLOUD_CAPABILITY_IDS = [
    "cloud.provider_discovery",
    "cloud.account_inventory",
    "cloud.project_inventory",
    "cloud.resource_inventory",
    "cloud.compute_observation",
    "cloud.storage_observation",
    "cloud.database_observation",
    "cloud.network_observation",
    "cloud.public_exposure_analysis",
    "cloud.security_configuration_observation",
    "cloud.secret_reference_observation",
    "cloud.iam_identity_observation",
    "cloud.iam_role_observation",
    "cloud.iam_permission_observation",
    "cloud.resource_relationship_analysis",
    "cloud.container_observation",
    "cloud.cluster_observation",
    "cloud.edge_architecture_observation",
    "cloud.origin_candidate_analysis",
    "cloud.transport_security_observation",
]


class CloudCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for cloud security capabilities."""

    category: str = "cloud"
    mode: CloudMode = CloudMode.PASSIVE
    produces: list[CloudObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    produces: list[CloudObservationKind],
    *,
    version: str = "1.0.0",
) -> CloudCapabilityMeta:
    return CloudCapabilityMeta(
        id=CapabilityID(capability_id),
        name=capability_id,
        description=description,
        version=version,
        risk_level=RiskLevel.LOW,
        authorization_required=True,
        supported_target_types=[TargetType.CLOUD],
        input_schema={
            "target": {"type": "string"},
            "params": {"type": "object"},
        },
        output_schema={"observations": {"type": "array"}},
        evidence_types_produced=["artifact", "observation"],
        mode=CloudMode.PASSIVE,
        produces=produces,
    )


def build_cloud_meta() -> list[CloudCapabilityMeta]:
    """Metadata for all twenty cloud security capabilities."""
    return [
        _meta(
            "cloud.provider_discovery",
            "Discover the modeled provider and its authorization container layout.",
            [CloudObservationKind.PROVIDER],
        ),
        _meta(
            "cloud.account_inventory",
            "Inventory accounts / subscriptions within the authorized provider.",
            [CloudObservationKind.ACCOUNT],
        ),
        _meta(
            "cloud.project_inventory",
            "Inventory projects associated with the authorized estate.",
            [CloudObservationKind.PROJECT],
        ),
        _meta(
            "cloud.resource_inventory",
            "Inventory typed cloud resources across the estate.",
            [CloudObservationKind.CLOUD_RESOURCE],
        ),
        _meta(
            "cloud.compute_observation",
            "Observe compute instances and their descriptive attributes.",
            [CloudObservationKind.COMPUTE],
        ),
        _meta(
            "cloud.storage_observation",
            "Observe storage resources and their descriptive attributes.",
            [CloudObservationKind.STORAGE],
        ),
        _meta(
            "cloud.database_observation",
            "Observe database services and their descriptive attributes.",
            [CloudObservationKind.DATABASE],
        ),
        _meta(
            "cloud.network_observation",
            "Observe virtual network primitives and provider-reported rules.",
            [CloudObservationKind.NETWORK],
        ),
        _meta(
            "cloud.public_exposure_analysis",
            "Derive public exposure hypotheses from provider-reported posture.",
            [CloudObservationKind.PUBLIC_EXPOSURE],
        ),
        _meta(
            "cloud.security_configuration_observation",
            "Observe security configuration attributes from authoritative "
            "and correlated feeds.",
            [CloudObservationKind.SECURITY_CONFIGURATION],
        ),
        _meta(
            "cloud.secret_reference_observation",
            "Observe references to managed secrets (never secret values).",
            [CloudObservationKind.SECRET_REFERENCE],
        ),
        _meta(
            "cloud.iam_identity_observation",
            "Observe IAM identities and their descriptive attributes.",
            [CloudObservationKind.IAM_IDENTITY],
        ),
        _meta(
            "cloud.iam_role_observation",
            "Observe IAM roles within the authorized estate.",
            [CloudObservationKind.IAM_ROLE],
        ),
        _meta(
            "cloud.iam_permission_observation",
            "Observe descriptive permission statements attached to the estate.",
            [CloudObservationKind.IAM_PERMISSION],
        ),
        _meta(
            "cloud.resource_relationship_analysis",
            "Resolve descriptive structural relationships between resources.",
            [CloudObservationKind.RESOURCE_RELATIONSHIP],
        ),
        _meta(
            "cloud.container_observation",
            "Observe container instances and their descriptive attributes.",
            [CloudObservationKind.CONTAINER],
        ),
        _meta(
            "cloud.cluster_observation",
            "Observe container orchestrator clusters and their attributes.",
            [CloudObservationKind.CLUSTER],
        ),
        _meta(
            "cloud.edge_architecture_observation",
            "Observe provider-fronted edge / proxy / CDN architecture in front "
            "of applications.",
            [CloudObservationKind.EDGE_ARCHITECTURE],
        ),
        _meta(
            "cloud.origin_candidate_analysis",
            "Correlate provider posture into origin candidate hypotheses. "
            "Candidates are never confirmed origins and never imply "
            "vulnerability or authorization, correlational analysis only.",
            [CloudObservationKind.ORIGIN_CANDIDATE],
        ),
        _meta(
            "cloud.transport_security_observation",
            "Observe TLS / transport security posture reported for endpoints.",
            [CloudObservationKind.TRANSPORT_SECURITY],
        ),
    ]


class CloudCapability(Capability):
    """A typed cloud security capability bound to a mock transport method.

    ``execute`` runs the deterministic mock transport through the
    normalization adapter and returns normalized observations. It performs no
    authorization itself — the :class:`CloudEngine` enforces scope /
    authorization before any execution path reaches the mock.
    """

    def __init__(
        self,
        meta: CloudCapabilityMeta,
        tool_method: str,
        adapter: CloudToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._transport = MockCloudTransport()

    def meta(self) -> CloudCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> CloudToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        params = params or {}
        mode_param = params.get("mode")
        mode = CloudMode(mode_param) if mode_param else self._meta.mode
        method = self._tool_method
        raw = getattr(self._transport, method)(target, mode=mode)
        normalized = self._adapter.adapt(raw, context={"target": target, "mode": mode})
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


def build_cloud_capabilities() -> list[CloudCapability]:
    """Instantiate all twenty typed cloud capabilities (mock-backed)."""
    metas = build_cloud_meta()
    tool_methods = [
        "discover_providers",
        "inventory_accounts",
        "inventory_projects",
        "inventory_resources",
        "observe_compute",
        "observe_storage",
        "observe_databases",
        "observe_networks",
        "analyze_public_exposure",
        "observe_security_configuration",
        "observe_secret_references",
        "observe_iam_identities",
        "observe_iam_roles",
        "observe_iam_permissions",
        "analyze_resource_relationships",
        "observe_containers",
        "observe_clusters",
        "observe_edge_architecture",
        "analyze_origin_candidates",
        "observe_transport_security",
    ]
    adapters = [adapter_for_tool(method) for method in tool_methods]
    return [
        CloudCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            metas,
            tool_methods,
            adapters,
            strict=True,
        )
    ]


__all__ = [
    "CLOUD_CAPABILITY_IDS",
    "CloudCapability",
    "CloudCapabilityMeta",
    "build_cloud_capabilities",
    "build_cloud_meta",
]
