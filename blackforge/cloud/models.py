from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class CloudMode(str, Enum):
    """How cloud security observation operates on a provider estate.

    * ``PASSIVE`` — inference only: correlated posture metadata, derived
      exposure analysis, and descriptive resource relationships. No provider
      record is touched.
    * ``CONTROLLED`` — deterministic, bounded observation against the
      (authorized) mock provider dataset: provider/account/project discovery,
      typed resource inventory, and IAM/secret-reference observation. No real
      provider API is ever queried and no mutation is ever issued.
    """

    PASSIVE = "passive"
    CONTROLLED = "controlled"


class CloudStatus(str, Enum):
    """Failure-aware outcomes for a cloud capability execution.

    Every run terminates in one of these states; negative outcomes (unknown /
    unsupported provider, unknown account, rate limited, malformed, timeout)
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
    UNKNOWN_PROVIDER = "unknown_provider"
    UNSUPPORTED_PROVIDER = "unsupported_provider"
    FAILED = "failed"


class CloudProvider(str, Enum):
    """Modeled cloud providers.

    Only these providers carry authoritative mock fixture data. Any other
    prefix is an ``UNKNOWN`` provider and fails closed.
    """

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class CloudContainerType(str, Enum):
    """Top-level authorization container for a provider estate.

    Every cloud target resolves ``provider/container``; the container is an
    account (AWS), a subscription (Azure), or a project (GCP).
    """

    ACCOUNT = "account"
    SUBSCRIPTION = "subscription"
    PROJECT = "project"


class CloudObservationKind(str, Enum):
    """Typed kinds of cloud security observations."""

    PROVIDER = "provider"
    ACCOUNT = "account"
    PROJECT = "project"
    CLOUD_RESOURCE = "cloud_resource"
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    PUBLIC_EXPOSURE = "public_exposure"
    SECURITY_CONFIGURATION = "security_configuration"
    SECRET_REFERENCE = "secret_reference"
    IAM_IDENTITY = "iam_identity"
    IAM_ROLE = "iam_role"
    IAM_PERMISSION = "iam_permission"
    RESOURCE_RELATIONSHIP = "resource_relationship"
    CONTAINER = "container"
    CLUSTER = "cluster"
    EDGE_ARCHITECTURE = "edge_architecture"
    ORIGIN_CANDIDATE = "origin_candidate"
    TRANSPORT_SECURITY = "transport_security"


class CloudResourceType(str, Enum):
    """Typed kinds of cloud resources that can be observed.

    Mapped deterministically to world model entity types at materialization
    time; ``unknown`` collapses to the generic cloud resource entity.
    """

    ACCOUNT = "account"
    ORGANIZATION = "organization"
    PROJECT = "project"
    SUBSCRIPTION = "subscription"
    REGION = "region"
    COMPUTE_INSTANCE = "compute_instance"
    STORAGE_BUCKET = "storage_bucket"
    STORAGE_DISK = "storage_disk"
    DATABASE = "database"
    VIRTUAL_NETWORK = "virtual_network"
    SUBNET = "subnet"
    SECURITY_GROUP = "security_group"
    FIREWALL_RULE = "firewall_rule"
    LOAD_BALANCER = "load_balancer"
    CONTAINER = "container"
    CLUSTER = "cluster"
    SECRET = "secret"
    UNKNOWN = "unknown"


class ProviderObservation(BaseModel):
    kind: Literal["provider"] = "provider"
    provider: CloudProvider
    container_type: CloudContainerType | None = None
    accounts: int | None = None
    regions: list[str] = Field(default_factory=list)
    note: str | None = None


class AccountObservation(BaseModel):
    kind: Literal["account"] = "account"
    provider: CloudProvider
    account: str
    container_type: CloudContainerType | None = None
    account_id: str | None = None
    regions: list[str] = Field(default_factory=list)
    note: str | None = None


class ProjectObservation(BaseModel):
    kind: Literal["project"] = "project"
    provider: CloudProvider
    project: str
    account: str | None = None
    project_type: str | None = None
    note: str | None = None


class CloudResourceObservation(BaseModel):
    """A generic resource inventory record (container-level breadth pass)."""

    kind: Literal["cloud_resource"] = "cloud_resource"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    resource_type: CloudResourceType = CloudResourceType.UNKNOWN
    name: str
    note: str | None = None


class ComputeObservation(BaseModel):
    """A compute instance observed on the estate.

    ``public_endpoint`` is the *provider-reported* endpoint of the instance —
    descriptive state, never a vulnerability claim. ``tags`` are descriptive
    labels with credential-like values redacted at the artifact boundary.
    """

    kind: Literal["compute"] = "compute"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    name: str
    instance_type: str | None = None
    state: str | None = None
    public_endpoint: str | None = None
    private_endpoints: list[str] = Field(default_factory=list)
    tags: dict | None = None
    note: str | None = None


class StorageObservation(BaseModel):
    """A storage resource (object bucket / block disk / file share)."""

    kind: Literal["storage"] = "storage"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    name: str
    storage_type: str | None = None
    public_access: bool | None = None
    note: str | None = None


class DatabaseObservation(BaseModel):
    kind: Literal["database"] = "database"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    name: str
    engine: str | None = None
    public_access: bool | None = None
    note: str | None = None


class NetworkObservation(BaseModel):
    """A virtual network primitive (VPC/VNet, subnet, security group, firewall
    rule, or load balancer).

    ``ingress_allowed`` reflects a provider-reported rule (e.g. an inbound
    ``0.0.0.0/0`` authorization) — descriptive, never an automatic finding.
    """

    kind: Literal["network"] = "network"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    name: str
    network_type: str | None = None
    ingress_allowed: bool | None = None
    attached_cidrs: list[str] = Field(default_factory=list)
    note: str | None = None


class PublicExposureObservation(BaseModel):
    """A derived exposure analysis for a single typed resource.

    ``exposed`` is a *hypothesis* derived from the provider-reported public
    reachability posture; it is never an automatic vulnerability claim.
    """

    kind: Literal["public_exposure"] = "public_exposure"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    resource_type: CloudResourceType = CloudResourceType.UNKNOWN
    resource: str
    exposed: bool
    endpoint: str | None = None
    note: str | None = None


class SecurityConfigurationObservation(BaseModel):
    """A security configuration attribute observed for an entity.

    ``source`` distinguishes authoritative primary records (``provider``)
    from correlated feeds; ``resolved`` is False (with a warning) when the
    referenced value points at an object that does not exist on the estate.
    Contradictions between sources surface as assertions, never silent
    overwrites.
    """

    kind: Literal["security_configuration"] = "security_configuration"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    entity_type: str | None = None
    entity: str
    item: str
    value: str | None = None
    source: str | None = None
    resolved: bool = True
    missing_reference: str | None = None
    note: str | None = None


class SecretReferenceObservation(BaseModel):
    """A reference to a managed secret — never the secret value.

    Only the name, kind, and provider-reported reference (ARN / path) are
    carried. Any secret value present in raw transport output is redacted at
    the artifact boundary and never reaches observations, evidence, or the
    world model.
    """

    kind: Literal["secret_reference"] = "secret_reference"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    name: str
    secret_kind: str | None = None
    reference: str | None = None
    note: str | None = None


class IamIdentityObservation(BaseModel):
    """An identity principal observed on the estate.

    ``mfa_enabled`` is a descriptive provider-reported attribute — never an
    automatic finding and never inferred from names.
    """

    kind: Literal["iam_identity"] = "iam_identity"
    provider: CloudProvider
    account: str
    identity: str
    principal_type: str | None = None
    enabled: bool | None = None
    mfa_enabled: bool | None = None
    privileges: list[str] = Field(default_factory=list)
    note: str | None = None


class IamRoleObservation(BaseModel):
    kind: Literal["iam_role"] = "iam_role"
    provider: CloudProvider
    account: str
    role: str
    description: str | None = None
    note: str | None = None


class IamPermissionObservation(BaseModel):
    """A permission statement observed on the estate.

    ``effect``/``action`` are descriptive (``allow``/``deny``); observation
    never derives privilege-escalation semantics.
    """

    kind: Literal["iam_permission"] = "iam_permission"
    provider: CloudProvider
    account: str
    permission: str
    effect: str | None = None
    action: str | None = None
    note: str | None = None


class ResourceRelationshipObservation(BaseModel):
    """A derived, descriptive relationship resolved between cloud resources.

    ``relationship_type`` is restricted to the world model's structural edge
    vocabulary (contains / uses / depends_on / connects_to / applies_to /
    hosts / located_in / belongs_to / has_role / has_permission /
    associated_with). Offensive edges (LEADS_TO, ENABLES, CAN_COMPROMISE,
    EXPLOITS) are never produced.
    """

    kind: Literal["resource_relationship"] = "resource_relationship"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    relationship_type: str
    source_type: CloudResourceType = CloudResourceType.UNKNOWN
    source: str
    target_type: CloudResourceType = CloudResourceType.UNKNOWN
    target: str
    note: str | None = None


class ContainerObservation(BaseModel):
    """A container instance observed on the estate."""

    kind: Literal["container"] = "container"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    name: str
    image: str | None = None
    state: str | None = None
    exposed_ports: list[str] = Field(default_factory=list)
    cluster: str | None = None
    note: str | None = None


class ClusterObservation(BaseModel):
    """A container orchestrator cluster observed on the estate."""

    kind: Literal["cluster"] = "cluster"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    name: str
    version: str | None = None
    node_count: int | None = None
    note: str | None = None


class EdgeArchitectureObservation(BaseModel):
    """An edge / proxy / CDN front-end observed on the estate.

    Captures the ``DOMAIN -> EDGE -> ORIGIN`` boundary: an edge endpoint
    (CDN, proxy, WAF, load balancer) fronts one or more origin endpoints and
    protects named applications. ``directly_reachable_origin`` is a
    *derived* hypothesis (False when every origin is only reachable through
    the edge) — never a vulnerability claim and never used to auto-expand
    scope.

    Edge rows are descriptive: observing that an application sits behind an
    edge does not mean it is unreachable, and an unfronted public endpoint is
    a descriptive posture, not a finding.
    """

    kind: Literal["edge_architecture"] = "edge_architecture"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    edge: str
    edge_kind: str | None = None
    domain: str | None = None
    origin_endpoints: list[str] = Field(default_factory=list)
    protected_applications: list[str] = Field(default_factory=list)
    directly_reachable_origin: bool | None = None
    note: str | None = None


class OriginCandidateObservation(BaseModel):
    """A typed *candidate* origin for a public domain — never a claim.

    Each row records who reported the candidate address (``source_category``),
    which evidence supports it, and why it correlated. ``evidence_status``
    reflects the candidate's own verification stage (OBSERVED / INFERRED /
    HYPOTHESIZED / VALIDATED) and is deliberately independent of
    ``confidence_label``: a HIGH-confidence INFERRED candidate is still
    INFERRED, and ``validation_status`` stays ``unvalidated`` until an
    authorized process validates it. Origin candidates require explicit
    authorization before any validation/interaction is attempted.
    """

    kind: Literal["origin_candidate"] = "origin_candidate"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    domain: str
    candidate_address: str
    candidate_endpoint: str | None = None
    source_category: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    correlation_reasons: list[str] = Field(default_factory=list)
    confidence_label: str | None = None
    evidence_status: str = "hypothesized"
    validation_status: str = "unvalidated"
    authorization_requirements: list[str] = Field(default_factory=list)
    note: str | None = None


class TransportSecurityObservation(BaseModel):
    """Transport-layer (TLS) security posture observed for an endpoint.

    ``tls_enforced`` / ``tls_version`` / ``certificate_valid`` are
    descriptive, source-tagged attributes. Conflicting reports surface as
    contradictory assertions on the endpoint — never a silent overwrite and
    never an automatic finding.
    """

    kind: Literal["transport_security"] = "transport_security"
    provider: CloudProvider
    account: str | None = None
    project: str | None = None
    region: str | None = None
    endpoint: str
    tls_enforced: bool | None = None
    tls_version: str | None = None
    certificate_valid: bool | None = None
    source: str | None = None
    note: str | None = None


CloudObservation = Annotated[
    ProviderObservation
    | AccountObservation
    | ProjectObservation
    | CloudResourceObservation
    | ComputeObservation
    | StorageObservation
    | DatabaseObservation
    | NetworkObservation
    | PublicExposureObservation
    | SecurityConfigurationObservation
    | SecretReferenceObservation
    | IamIdentityObservation
    | IamRoleObservation
    | IamPermissionObservation
    | ResourceRelationshipObservation
    | ContainerObservation
    | ClusterObservation
    | EdgeArchitectureObservation
    | OriginCandidateObservation
    | TransportSecurityObservation,
    Field(discriminator="kind"),
]


class CloudRequest(BaseModel):
    """Authorized cloud security observation request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: CloudMode = CloudMode.CONTROLLED
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)


class CloudResult(BaseModel):
    """Structured, deterministic outcome of a cloud execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: CloudMode
    status: CloudStatus = CloudStatus.SUCCESS
    observations: list[CloudObservation] = Field(default_factory=list)
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
    "AccountObservation",
    "CloudContainerType",
    "CloudMode",
    "CloudObservation",
    "CloudObservationKind",
    "CloudProvider",
    "CloudRequest",
    "CloudResourceObservation",
    "CloudResourceType",
    "CloudResult",
    "CloudStatus",
    "ClusterObservation",
    "ComputeObservation",
    "ContainerObservation",
    "DatabaseObservation",
    "EdgeArchitectureObservation",
    "IamIdentityObservation",
    "IamPermissionObservation",
    "IamRoleObservation",
    "NetworkObservation",
    "OriginCandidateObservation",
    "ProjectObservation",
    "ProviderObservation",
    "PublicExposureObservation",
    "ResourceRelationshipObservation",
    "SecretReferenceObservation",
    "SecurityConfigurationObservation",
    "StorageObservation",
    "TransportSecurityObservation",
]
