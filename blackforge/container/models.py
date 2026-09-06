from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class ContainerMode(str, Enum):
    """How container / Kubernetes security observation operates.

    * ``PASSIVE`` — inference only: derived posture metadata (security
      context analysis, resource configuration, configuration discrepancy,
      exposure correlation). No cluster record is touched.
    * ``CONTROLLED`` — deterministic, bounded observation against the
      (authorized) mock cluster dataset: cluster/node/namespace enumeration,
      workload, pod, image, service, ingress, RBAC, service-account and
      network-policy observation. No real cluster API is ever queried and no
      mutation is ever issued.
    """

    PASSIVE = "passive"
    CONTROLLED = "controlled"


class ContainerStatus(str, Enum):
    """Failure-aware outcomes for a container capability execution.

    Every run terminates in one of these states; negative outcomes (unknown /
    unsupported cluster, unknown namespace, rate limited, malformed, timeout)
    are recorded as structured results rather than silent failures. Failure
    states never become findings.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    LIMITED = "limited"
    NO_EVIDENCE = "no_evidence"
    REQUEST_FAILED = "request_failed"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"
    OUT_OF_SCOPE = "out_of_scope"
    MALFORMED_RESPONSE = "malformed_response"
    TIMEOUT = "timeout"
    UNKNOWN_CLUSTER = "unknown_cluster"
    UNSUPPORTED_CLUSTER = "unsupported_cluster"
    FAILED = "failed"


class ContainerObservationKind(str, Enum):
    """Typed kinds of container / Kubernetes security observations."""

    CLUSTER = "cluster"
    NODE = "node"
    NAMESPACE = "namespace"
    WORKLOAD = "workload"
    DEPLOYMENT = "deployment"
    POD = "pod"
    CONTAINER = "container"
    IMAGE = "image"
    REGISTRY = "registry"
    SERVICE = "service"
    INGRESS = "ingress"
    RBAC = "rbac"
    SERVICE_ACCOUNT = "service_account"
    NETWORK_POLICY = "network_policy"
    SECURITY_CONTEXT = "security_context"
    RESOURCE_CONFIGURATION = "resource_configuration"
    CONFIGURATION_DISCREPANCY = "configuration_discrepancy"


class ClusterObservation(BaseModel):
    """A Kubernetes cluster observed on the authorized platform.

    ``api_accessible`` is a descriptive, source-tagged posture attribute —
    never an automatic finding and never used to derive exploitation paths.
    """

    kind: Literal["cluster"] = "cluster"
    cluster: str
    platform: str | None = None
    version: str | None = None
    node_count: int | None = None
    namespace_count: int | None = None
    workload_count: int | None = None
    api_accessible: bool | None = None
    note: str | None = None


class NodeObservation(BaseModel):
    kind: Literal["node"] = "node"
    cluster: str
    node: str
    role: str | None = None
    ip_address: str | None = None
    os_image: str | None = None
    container_runtime: str | None = None
    kubelet_version: str | None = None
    note: str | None = None


class NamespaceObservation(BaseModel):
    kind: Literal["namespace"] = "namespace"
    cluster: str
    namespace: str
    labels: dict | None = None
    pod_count: int | None = None
    note: str | None = None


class WorkloadObservation(BaseModel):
    """A workload abstraction (Deployment / StatefulSet / DaemonSet).

    ``replicas``/``strategy`` are descriptive attributes reported by the
    cluster metadata; observation never derives privilege or reachability
    semantics from them.
    """

    kind: Literal["workload"] = "workload"
    cluster: str
    namespace: str
    workload: str
    workload_kind: str | None = None
    replicas: int | None = None
    image: str | None = None
    strategy: str | None = None
    update_status: str | None = None
    note: str | None = None


class DeploymentObservation(BaseModel):
    """The controller object (Deployment) that manages an application.

    ``ready``/``available`` replica counts are descriptive cluster-reported
    state — never a health or vulnerability claim.
    """

    kind: Literal["deployment"] = "deployment"
    cluster: str
    namespace: str
    deployment: str
    workload: str | None = None
    replicas: int | None = None
    ready_replicas: int | None = None
    available_replicas: int | None = None
    strategy: str | None = None
    image: str | None = None
    note: str | None = None


class PodObservation(BaseModel):
    """A running pod and its descriptive scheduling attributes.

    ``phase`` is the reported pod lifecycle stage. ``service_account`` is a
    reference, never a credential; token material is redacted at the artifact
    boundary.
    """

    kind: Literal["pod"] = "pod"
    cluster: str
    namespace: str
    pod: str
    workload: str | None = None
    node: str | None = None
    phase: str | None = None
    pod_ip: str | None = None
    restarts: int | None = None
    service_account: str | None = None
    containers: list[str] = Field(default_factory=list)
    note: str | None = None


class ContainerInstanceObservation(BaseModel):
    """A container instance observed on a cluster.

    ``privileged`` is a descriptive reported attribute — never an automatic
    finding and never used to derive privilege-escalation semantics.
    """

    kind: Literal["container"] = "container"
    cluster: str
    namespace: str
    pod: str | None = None
    container: str
    image: str | None = None
    image_pull_policy: str | None = None
    command: list[str] = Field(default_factory=list)
    args: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    volume_mounts: list[str] = Field(default_factory=list)
    privileged: bool | None = None
    note: str | None = None


class ImageObservation(BaseModel):
    """Image metadata referenced by the estate (never pulled content)."""

    kind: Literal["image"] = "image"
    cluster: str
    namespace: str | None = None
    image: str
    registry: str | None = None
    tag: str | None = None
    digest: str | None = None
    pull_policy: str | None = None
    note: str | None = None


class RegistryObservation(BaseModel):
    """A container image registry referenced by the estate.

    ``secure`` is a descriptive attribute; registry credentials are redacted
    at the artifact boundary and never reach observations, evidence, or the
    world model.
    """

    kind: Literal["registry"] = "registry"
    cluster: str
    registry: str
    host: str | None = None
    image_count: int | None = None
    secure: bool | None = None
    note: str | None = None


class ServiceObservation(BaseModel):
    """A Kubernetes Service and its descriptive routing metadata.

    ``selector`` is descriptive; a Service observation never derives
    reachability or exposure semantics on its own.
    """

    kind: Literal["service"] = "service"
    cluster: str
    namespace: str
    service: str
    service_type: str | None = None
    cluster_ip: str | None = None
    ports: list[str] = Field(default_factory=list)
    selector: dict | None = None
    note: str | None = None


class IngressObservation(BaseModel):
    """An Ingress object exposing Services through named host rules.

    ``tls_enabled`` is a descriptive attribute — observing TLS absence is a
    posture note, never an automatic finding.
    """

    kind: Literal["ingress"] = "ingress"
    cluster: str
    namespace: str
    ingress: str
    host: str | None = None
    paths: list[str] = Field(default_factory=list)
    backend: str | None = None
    tls_enabled: bool | None = None
    note: str | None = None


class RbacObservation(BaseModel):
    """A descriptive RBAC binding (subject -> role -> permission).

    ``verbs``/``resources``/``api_group`` are reported rule attributes.
    Observation never derives privilege-escalation, move, or exploit
    semantics from a role binding.
    """

    kind: Literal["rbac"] = "rbac"
    cluster: str
    namespace: str
    subject: str
    subject_kind: str | None = None
    role: str
    role_kind: str | None = None
    permission: str | None = None
    verbs: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    api_group: str | None = None
    note: str | None = None


class ServiceAccountObservation(BaseModel):
    """A ServiceAccount and its reported attributes.

    ``automount_token`` is descriptive; ``image_pull_secrets`` references are
    never secret values. Token material in raw transport output is redacted.
    """

    kind: Literal["service_account"] = "service_account"
    cluster: str
    namespace: str
    service_account: str
    automount_token: bool | None = None
    secrets: list[str] = Field(default_factory=list)
    image_pull_secrets: list[str] = Field(default_factory=list)
    note: str | None = None


class NetworkPolicyObservation(BaseModel):
    """A NetworkPolicy and its descriptive match/action rules.

    ``policy_types`` are reported as ``Ingress``/``Egress``; rules are
    descriptive statements, never proof of reachability or isolation.
    """

    kind: Literal["network_policy"] = "network_policy"
    cluster: str
    namespace: str
    network_policy: str
    policy_types: list[str] = Field(default_factory=list)
    pod_selector: dict | None = None
    ingress_rules: list[dict] = Field(default_factory=list)
    egress_rules: list[dict] = Field(default_factory=list)
    note: str | None = None


class SecurityContextObservation(BaseModel):
    """A security-context attribute observed for a pod or container.

    ``source`` distinguishes authoritative cluster records (``cluster``) from
    correlated feeds (``image_metadata``). ``resolved`` is False (with a
    warning) when the referenced pod/container does not exist on the estate.
    Contradictory reports surface as assertions, never silent overwrites.
    """

    kind: Literal["security_context"] = "security_context"
    cluster: str
    namespace: str
    pod: str | None = None
    container: str | None = None
    allow_privilege_escalation: bool | None = None
    privileged: bool | None = None
    run_as_non_root: bool | None = None
    run_as_user: int | None = None
    read_only_root_filesystem: bool | None = None
    seccomp_profile: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    source: str = "cluster"
    resolved: bool = True
    missing_reference: str | None = None
    note: str | None = None


class ResourceConfigurationObservation(BaseModel):
    """Computed (limit/request) configuration for a workload container.

    ``recommendation_source`` records who reported the numbers. Attributes
    are descriptive; no capacity or inefficiency claim is derived.
    """

    kind: Literal["resource_configuration"] = "resource_configuration"
    cluster: str
    namespace: str
    workload: str
    container: str | None = None
    cpu_request: str | None = None
    memory_request: str | None = None
    cpu_limit: str | None = None
    memory_limit: str | None = None
    recommendation_source: str | None = None
    source: str = "cluster"
    resolved: bool = True
    missing_reference: str | None = None
    note: str | None = None


class ConfigurationDiscrepancyObservation(BaseModel):
    """A configuration discrepancy between declared and reported values.

    ``declared_value`` is what the workload spec declares;
    ``cluster_reported_value`` is what the cluster reports. ``severity`` is a
    descriptive label from the reporting source — never an automatic finding.
    """

    kind: Literal["configuration_discrepancy"] = "configuration_discrepancy"
    cluster: str
    namespace: str
    workload: str
    container: str | None = None
    item: str
    declared_value: str | None = None
    cluster_reported_value: str | None = None
    severity: str | None = None
    note: str | None = None


ContainerObservation = Annotated[
    ClusterObservation
    | NodeObservation
    | NamespaceObservation
    | WorkloadObservation
    | DeploymentObservation
    | PodObservation
    | ContainerInstanceObservation
    | ImageObservation
    | RegistryObservation
    | ServiceObservation
    | IngressObservation
    | RbacObservation
    | ServiceAccountObservation
    | NetworkPolicyObservation
    | SecurityContextObservation
    | ResourceConfigurationObservation
    | ConfigurationDiscrepancyObservation,
    Field(discriminator="kind"),
]


class ContainerRequest(BaseModel):
    """Authorized container / Kubernetes observation request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: ContainerMode = ContainerMode.CONTROLLED
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)


class ContainerResult(BaseModel):
    """Structured, deterministic outcome of a container execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: ContainerMode
    status: ContainerStatus = ContainerStatus.SUCCESS
    observations: list[ContainerObservation] = Field(default_factory=list)
    evidence_ids: list[EvidenceID] = Field(default_factory=list)
    raw_output: str | None = None
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0
    authorized: bool = True
    created_at: float = Field(default_factory=time.time)

    @property
    def observation_count(self) -> int:
        return len(self.observations)


__all__ = [
    "ClusterObservation",
    "ConfigurationDiscrepancyObservation",
    "ContainerInstanceObservation",
    "ContainerMode",
    "ContainerObservation",
    "ContainerObservationKind",
    "ContainerRequest",
    "ContainerResult",
    "ContainerStatus",
    "DeploymentObservation",
    "ImageObservation",
    "IngressObservation",
    "NamespaceObservation",
    "NetworkPolicyObservation",
    "NodeObservation",
    "PodObservation",
    "RbacObservation",
    "RegistryObservation",
    "ResourceConfigurationObservation",
    "SecurityContextObservation",
    "ServiceAccountObservation",
    "ServiceObservation",
    "WorkloadObservation",
]
