from __future__ import annotations

import json

from blackforge.cloud.models import (
    AccountObservation,
    CloudMode,
    CloudObservation,
    CloudResourceObservation,
    ClusterObservation,
    ComputeObservation,
    ContainerObservation,
    DatabaseObservation,
    EdgeArchitectureObservation,
    IamIdentityObservation,
    IamPermissionObservation,
    IamRoleObservation,
    NetworkObservation,
    OriginCandidateObservation,
    ProjectObservation,
    ProviderObservation,
    PublicExposureObservation,
    ResourceRelationshipObservation,
    SecretReferenceObservation,
    SecurityConfigurationObservation,
    StorageObservation,
    TransportSecurityObservation,
)
from blackforge.cloud.redaction import redact_cloud_raw
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    ProvenanceType,
    SessionID,
)
from blackforge.evidence.models import Evidence, Provenance

_DIRECT_KIND_VALUES = frozenset(
    {
        "provider",
        "account",
        "project",
        "cloud_resource",
        "compute",
        "storage",
        "database",
        "network",
        "iam_identity",
        "iam_role",
        "iam_permission",
        "secret_reference",
        "cluster",
        "container",
    }
)
_DERIVED_KIND_VALUES = frozenset(
    {
        "public_exposure",
        "resource_relationship",
        "edge_architecture",
        "origin_candidate",
        "transport_security",
    }
)


def observation_confidence(
    observation: CloudObservation, mode: CloudMode
) -> Confidence:
    """Confidence policy for cloud observations.

    * Anything inferred without provider interaction (``PASSIVE``) is LOW.
    * Direct authoritative provider records (provider/account/project/
      resource inventories, IAM records, secret references) are HIGH.
    * Security configuration from the authoritative ``provider`` source is
      HIGH; correlated feeds are MEDIUM.
    * Derived exposure and relationship analysis is MEDIUM.
    * Edge architecture, origin-candidate correlation, and transport
      security are derived correlations — MEDIUM in CONTROLLED, LOW in
      PASSIVE. A HIGH-confidence origin candidate is still the lowest
      evidence stage until validated.
    """
    if mode == CloudMode.PASSIVE:
        return Confidence.LOW
    if observation.kind in _DIRECT_KIND_VALUES:
        return Confidence.HIGH
    if isinstance(observation, SecurityConfigurationObservation):
        return (
            Confidence.HIGH
            if observation.source == "provider"
            else Confidence.MEDIUM
        )
    if observation.kind in _DERIVED_KIND_VALUES:
        return Confidence.MEDIUM
    return Confidence.LOW


def observation_summary(observation: CloudObservation) -> str:
    """One-line human summary for a cloud observation."""
    if isinstance(observation, ProviderObservation):
        return (
            f"Provider {observation.provider.value} "
            f"container={observation.container_type} "
            f"accounts={observation.accounts}"
        )
    if isinstance(observation, AccountObservation):
        return (
            f"Account {observation.account} ({observation.provider.value}) "
            f"type={observation.container_type}"
        )
    if isinstance(observation, ProjectObservation):
        return (
            f"Project {observation.project} "
            f"type={observation.project_type}"
        )
    if isinstance(observation, CloudResourceObservation):
        return (
            f"Cloud resource {observation.name} "
            f"type={observation.resource_type.value} "
            f"in {observation.account or observation.project}"
        )
    if isinstance(observation, ComputeObservation):
        return (
            f"Compute {observation.name} type={observation.instance_type} "
            f"state={observation.state} in {observation.account or observation.project}"
        )
    if isinstance(observation, StorageObservation):
        return (
            f"Storage {observation.name} "
            f"type={observation.storage_type} "
            f"public={observation.public_access}"
        )
    if isinstance(observation, DatabaseObservation):
        return (
            f"Database {observation.name} "
            f"engine={observation.engine} "
            f"public={observation.public_access}"
        )
    if isinstance(observation, NetworkObservation):
        return (
            f"Network {observation.name} "
            f"type={observation.network_type} "
            f"ingress={observation.ingress_allowed}"
        )
    if isinstance(observation, PublicExposureObservation):
        return (
            f"Exposure {observation.resource} "
            f"exposed={observation.exposed} "
            f"endpoint={observation.endpoint or 'none'}"
        )
    if isinstance(observation, SecurityConfigurationObservation):
        return (
            f"Security config {observation.entity}.{observation.item}="
            f"{observation.value} via {observation.source}"
        )
    if isinstance(observation, SecretReferenceObservation):
        return (
            f"Secret reference {observation.name} "
            f"kind={observation.secret_kind}"
        )
    if isinstance(observation, IamIdentityObservation):
        return (
            f"IAM identity {observation.identity} "
            f"type={observation.principal_type} "
            f"mfa={observation.mfa_enabled}"
        )
    if isinstance(observation, IamRoleObservation):
        return f"IAM role {observation.role} in {observation.account}"
    if isinstance(observation, IamPermissionObservation):
        return (
            f"IAM permission {observation.permission} "
            f"effect={observation.effect}"
        )
    if isinstance(observation, ResourceRelationshipObservation):
        return (
            f"Relationship {observation.source} "
            f"-{observation.relationship_type}-"
            f"> {observation.target}"
        )
    if isinstance(observation, ContainerObservation):
        return (
            f"Container {observation.name} "
            f"image={observation.image} "
            f"cluster={observation.cluster}"
        )
    if isinstance(observation, ClusterObservation):
        return (
            f"Cluster {observation.name} "
            f"version={observation.version} "
            f"nodes={observation.node_count}"
        )
    if isinstance(observation, EdgeArchitectureObservation):
        return (
            f"Edge {observation.edge} "
            f"kind={observation.edge_kind} "
            f"for {observation.domain} "
            f"direct={observation.directly_reachable_origin}"
        )
    if isinstance(observation, OriginCandidateObservation):
        return (
            f"Origin candidate {observation.candidate_address} "
            f"for {observation.domain} "
            f"status={observation.evidence_status} "
            f"validated={observation.validation_status}"
        )
    if isinstance(observation, TransportSecurityObservation):
        return (
            f"Transport security {observation.endpoint} "
            f"tls={observation.tls_enforced} "
            f"via {observation.source}"
        )
    return f"Cloud observation {observation.kind}"


def observation_reference(observation: CloudObservation) -> str:
    """Default evidence reference for a cloud observation."""
    if isinstance(observation, ProviderObservation):
        return observation.provider.value
    if isinstance(observation, AccountObservation):
        return observation.account
    if isinstance(observation, ProjectObservation):
        return observation.project
    if isinstance(observation, CloudResourceObservation):
        return observation.name
    if isinstance(observation, ComputeObservation):
        return observation.name
    if isinstance(observation, StorageObservation):
        return observation.name
    if isinstance(observation, DatabaseObservation):
        return observation.name
    if isinstance(observation, NetworkObservation):
        return observation.name
    if isinstance(observation, PublicExposureObservation):
        return observation.resource
    if isinstance(observation, SecurityConfigurationObservation):
        return observation.entity
    if isinstance(observation, SecretReferenceObservation):
        return observation.name
    if isinstance(observation, IamIdentityObservation):
        return observation.identity
    if isinstance(observation, IamRoleObservation):
        return observation.role
    if isinstance(observation, IamPermissionObservation):
        return observation.permission
    if isinstance(observation, ResourceRelationshipObservation):
        return observation.source
    if isinstance(observation, ContainerObservation):
        return observation.name
    if isinstance(observation, ClusterObservation):
        return observation.name
    if isinstance(observation, EdgeArchitectureObservation):
        return observation.edge
    if isinstance(observation, OriginCandidateObservation):
        return observation.domain
    if isinstance(observation, TransportSecurityObservation):
        return observation.endpoint
    return "unknown"


def artifact_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    raw_output: str,
    *,
    session_id: SessionID | None = None,
    mode: CloudMode = CloudMode.CONTROLLED,
    summary: str | None = None,
) -> Evidence:
    """Raw mock output preserved as authoritative ARTIFACT evidence.

    Credential-like fields (access keys, connection strings, service
    secrets) are recursively redacted from the raw document before the
    payload is stored so no plaintext secret ever reaches the evidence
    ledger.
    """
    redacted_raw = redact_cloud_raw(raw_output)
    try:
        payload_doc = json.loads(redacted_raw)
    except (json.JSONDecodeError, TypeError):
        payload_doc = {"raw": redacted_raw}
    if isinstance(payload_doc, dict):
        payload_doc["mode"] = mode.value
        payload = json.dumps(payload_doc, sort_keys=True, default=str)
    else:
        payload = json.dumps(
            {"mode": mode.value, "raw": redacted_raw}, sort_keys=True
        )
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.ARTIFACT,
        status=EvidenceStatus.OBSERVED,
        confidence=Confidence.HIGH,
        raw_data=payload,
        summary=summary
        or f"{capability_id} raw output for {target} (mock cloud transport)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"cloud": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: CloudObservation,
    *,
    session_id: SessionID | None = None,
    mode: CloudMode = CloudMode.CONTROLLED,
) -> Evidence:
    """Typed OBSERVATION evidence derived from a normalized observation.

    The mode is embedded in the raw payload so a PASSIVE observation never
    dedups onto a CONTROLLED record (confidence is mode-derived); repeated
    runs in the same mode still coalesce.
    """
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.OBSERVATION,
        status=EvidenceStatus.OBSERVED,
        confidence=observation_confidence(observation, mode),
        raw_data=json.dumps(
            {"mode": mode.value, "observation": observation.model_dump()},
            sort_keys=True,
            default=str,
        ),
        summary=observation_summary(observation),
        reference=observation_reference(observation),
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={
            "cloud": True,
            "mode": mode.value,
            "kind": observation.kind,
        },
    )


def evidence_dedup_key_for(evidence: Evidence) -> str:
    """Idempotency key reused across runs so identical observations dedup."""
    from blackforge.evidence.repository import (
        compute_evidence_dedup_key,
        evidence_dedup_content,
    )

    return compute_evidence_dedup_key(
        evidence.mission_id,
        evidence.target,
        evidence.source_capability,
        evidence.evidence_type,
        evidence_dedup_content(evidence),
    )


def existing_evidence_id(
    evidence_store, evidence: Evidence
) -> EvidenceID | None:
    """Return the stored id when an equivalent record already exists."""
    existing = evidence_store.repository.get_by_dedup_key(
        evidence_dedup_key_for(evidence)
    )
    return existing.id if existing is not None else None


__all__ = [
    "artifact_evidence",
    "evidence_dedup_key_for",
    "existing_evidence_id",
    "observation_confidence",
    "observation_evidence",
    "observation_reference",
    "observation_summary",
]
