from __future__ import annotations

import json

from blackforge.container.models import (
    ClusterObservation,
    ConfigurationDiscrepancyObservation,
    ContainerInstanceObservation,
    ContainerMode,
    ContainerObservation,
    DeploymentObservation,
    ImageObservation,
    IngressObservation,
    NamespaceObservation,
    NetworkPolicyObservation,
    NodeObservation,
    PodObservation,
    RbacObservation,
    RegistryObservation,
    ResourceConfigurationObservation,
    SecurityContextObservation,
    ServiceAccountObservation,
    ServiceObservation,
    WorkloadObservation,
)
from blackforge.container.redaction import redact_container_raw
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

# Container observation kinds that are direct authoritative cluster records.
_DIRECT_KINDS = frozenset(
    {
        "cluster",
        "node",
        "namespace",
        "workload",
        "deployment",
        "pod",
        "container",
        "image",
        "registry",
        "service",
        "service_account",
    }
)

# Derived / correlational kinds — MEDIUM even in CONTROLLED mode.
_DERIVED_KINDS = frozenset(
    {
        "ingress",
        "rbac",
        "network_policy",
        "security_context",
        "resource_configuration",
        "configuration_discrepancy",
    }
)


def observation_confidence(
    observation: ContainerObservation, mode: ContainerMode
) -> Confidence:
    """Confidence policy for container observations.

    * Anything inferred without cluster interaction (``PASSIVE``) is LOW.
    * Direct authoritative cluster records (cluster/node/namespace/workload/
      deployment/pod/container/image/registry/service/service-account) are
      HIGH in CONTROLLED mode.
    * Derived / correlational kinds (ingress, RBAC, network policy, security
      context, resource configuration, configuration discrepancy) are MEDIUM
      in CONTROLLED mode.
    """
    if mode == ContainerMode.PASSIVE:
        return Confidence.LOW
    if observation.kind in _DIRECT_KINDS:
        return Confidence.HIGH
    if observation.kind in _DERIVED_KINDS:
        return Confidence.MEDIUM
    return Confidence.LOW


def observation_summary(observation: ContainerObservation) -> str:
    """One-line human summary for a container observation."""
    if isinstance(observation, ClusterObservation):
        return (
            f"Cluster {observation.cluster} platform={observation.platform} "
            f"version={observation.version} nodes={observation.node_count}"
        )
    if isinstance(observation, NodeObservation):
        return (
            f"Node {observation.node} on {observation.cluster} "
            f"role={observation.role}"
        )
    if isinstance(observation, NamespaceObservation):
        return f"Namespace {observation.namespace} on {observation.cluster}"
    if isinstance(observation, WorkloadObservation):
        return (
            f"Workload {observation.workload}/{observation.namespace} "
            f"kind={observation.workload_kind} replicas={observation.replicas}"
        )
    if isinstance(observation, DeploymentObservation):
        return (
            f"Deployment {observation.deployment}/{observation.namespace} "
            f"ready={observation.ready_replicas}/{observation.replicas}"
        )
    if isinstance(observation, PodObservation):
        return (
            f"Pod {observation.pod}/{observation.namespace} "
            f"phase={observation.phase} sa={observation.service_account}"
        )
    if isinstance(observation, ContainerInstanceObservation):
        return (
            f"Container {observation.container}/{observation.namespace} "
            f"image={observation.image} privileged={observation.privileged}"
        )
    if isinstance(observation, ImageObservation):
        return f"Image {observation.image} registry={observation.registry}"
    if isinstance(observation, RegistryObservation):
        return f"Registry {observation.registry} on {observation.cluster}"
    if isinstance(observation, ServiceObservation):
        return (
            f"Service {observation.service}/{observation.namespace} "
            f"type={observation.service_type}"
        )
    if isinstance(observation, IngressObservation):
        return (
            f"Ingress {observation.ingress}/{observation.namespace} "
            f"host={observation.host} tls={observation.tls_enabled}"
        )
    if isinstance(observation, RbacObservation):
        return (
            f"RBAC {observation.subject} -> {observation.role} "
            f"/{observation.namespace}"
        )
    if isinstance(observation, ServiceAccountObservation):
        return (
            f"ServiceAccount {observation.service_account}/{observation.namespace}"
        )
    if isinstance(observation, NetworkPolicyObservation):
        return (
            f"NetworkPolicy {observation.network_policy}/{observation.namespace} "
            f"types={observation.policy_types}"
        )
    if isinstance(observation, SecurityContextObservation):
        return (
            f"Security context {observation.container}/{observation.namespace} "
            f"privileged={observation.privileged} "
            f"root={observation.run_as_non_root}"
        )
    if isinstance(observation, ResourceConfigurationObservation):
        return (
            f"Resource config {observation.container}/{observation.namespace} "
            f"cpu={observation.cpu_request}"
        )
    if isinstance(observation, ConfigurationDiscrepancyObservation):
        return (
            f"Configuration discrepancy {observation.item} "
            f"for {observation.workload}/{observation.namespace}"
        )
    return f"Container observation {observation.kind}"


def observation_reference(observation: ContainerObservation) -> str:
    """Default evidence reference for a container observation."""
    if isinstance(observation, ClusterObservation):
        return observation.cluster
    if isinstance(observation, NodeObservation):
        return observation.node
    if isinstance(observation, NamespaceObservation):
        return observation.namespace
    if isinstance(observation, WorkloadObservation):
        return observation.workload
    if isinstance(observation, DeploymentObservation):
        return observation.deployment
    if isinstance(observation, PodObservation):
        return observation.pod
    if isinstance(observation, ContainerInstanceObservation):
        return observation.container
    if isinstance(observation, ImageObservation):
        return observation.image
    if isinstance(observation, RegistryObservation):
        return observation.registry
    if isinstance(observation, ServiceObservation):
        return observation.service
    if isinstance(observation, IngressObservation):
        return observation.ingress
    if isinstance(observation, RbacObservation):
        return observation.role
    if isinstance(observation, ServiceAccountObservation):
        return observation.service_account
    if isinstance(observation, NetworkPolicyObservation):
        return observation.network_policy
    if isinstance(observation, SecurityContextObservation):
        return observation.container or observation.pod or observation.namespace
    if isinstance(observation, ResourceConfigurationObservation):
        return observation.workload
    if isinstance(observation, ConfigurationDiscrepancyObservation):
        return observation.workload
    return "unknown"


def artifact_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    raw_output: str,
    *,
    session_id: SessionID | None = None,
    mode: ContainerMode = ContainerMode.CONTROLLED,
    summary: str | None = None,
) -> Evidence:
    """Raw mock output preserved as authoritative ARTIFACT evidence.

    Credential-like fields (registry tokens, service-account tokens,
    kubeconfig passwords, TLS private keys) are recursively redacted from the
    raw document before the payload is stored so no plaintext secret ever
    reaches the evidence ledger.
    """
    redacted_raw = redact_container_raw(raw_output)
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
        or f"{capability_id} raw output for {target} (mock container transport)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"container": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: ContainerObservation,
    *,
    session_id: SessionID | None = None,
    mode: ContainerMode = ContainerMode.CONTROLLED,
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
            "container": True,
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


def existing_evidence_id(evidence_store, evidence: Evidence) -> EvidenceID | None:
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
