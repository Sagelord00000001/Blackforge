from __future__ import annotations

import json

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
from blackforge.identity.models import (
    DirectoryObservation,
    GroupObservation,
    IdentityMode,
    IdentityObservation,
    MembershipObservation,
    MetadataObservation,
    Observation,
    PermissionAssignmentObservation,
    PermissionObservation,
    RelationshipObservation,
    ResourceObservation,
    RoleAssignmentObservation,
    RoleObservation,
)
from blackforge.identity.redaction import redact_identity_raw

_DIRECT_KIND_VALUES = frozenset(
    {
        "directory",
        "identity",
        "group",
        "role",
        "permission",
        "resource",
        "membership",
        "role_assignment",
        "permission_assignment",
    }
)
_DERIVED_KIND_VALUES = frozenset({"relationship", "metadata"})


def observation_confidence(
    observation: Observation, mode: IdentityMode
) -> Confidence:
    """Confidence policy for identity observations.

    * Anything inferred without directory interaction (``PASSIVE``) is LOW.
    * Direct authoritative records (directory/identity/group/role/permission/
      resource/membership/role_assignment/permission_assignment) are HIGH.
    * Metadata attributes observed from the authoritative ``directory``
      source are HIGH; correlated feeds are MEDIUM.
    * Derived relationship analysis is MEDIUM.
    """
    if mode == IdentityMode.PASSIVE:
        return Confidence.LOW
    if observation.kind in _DIRECT_KIND_VALUES:
        return Confidence.HIGH
    if isinstance(observation, MetadataObservation):
        return (
            Confidence.HIGH
            if observation.source == "directory"
            else Confidence.MEDIUM
        )
    if observation.kind in _DERIVED_KIND_VALUES:
        return Confidence.MEDIUM
    return Confidence.LOW


def observation_summary(observation: Observation) -> str:
    """One-line human summary for an identity observation."""
    if isinstance(observation, DirectoryObservation):
        return f"Directory {observation.directory} type={observation.directory_type}"
    if isinstance(observation, IdentityObservation):
        return (
            f"Identity {observation.identity} in {observation.directory} "
            f"type={observation.principal_type} "
            f"privilege={observation.privilege_level}"
        )
    if isinstance(observation, GroupObservation):
        return (
            f"Group {observation.group} in {observation.directory} "
            f"members={observation.membership_count}"
        )
    if isinstance(observation, RoleObservation):
        return (
            f"Role {observation.role} in {observation.directory} "
            f"privilege={observation.privilege_level}"
        )
    if isinstance(observation, PermissionObservation):
        return f"Permission {observation.permission} in {observation.directory}"
    if isinstance(observation, ResourceObservation):
        return (
            f"Resource {observation.resource} in {observation.directory} "
            f"type={observation.resource_type}"
        )
    if isinstance(observation, MembershipObservation):
        return (
            f"Membership {observation.identity} -> {observation.group} "
            f"resolved={observation.resolved}"
        )
    if isinstance(observation, RoleAssignmentObservation):
        return (
            f"Role assignment {observation.identity} -> {observation.role} "
            f"in {observation.directory}"
        )
    if isinstance(observation, PermissionAssignmentObservation):
        return (
            f"Permission assignment {observation.role} -> "
            f"{observation.permission} in {observation.directory}"
        )
    if isinstance(observation, RelationshipObservation):
        return (
            f"Relationship {observation.source} -{observation.relationship_type}-"
            f"> {observation.target} in {observation.directory}"
        )
    if isinstance(observation, MetadataObservation):
        return (
            f"Metadata {observation.identity}.{observation.attribute_key}="
            f"{observation.attribute_value} via {observation.source}"
        )
    return f"Identity observation {observation.kind}"


def observation_reference(observation: Observation) -> str:
    """Default evidence reference for an identity observation."""
    if isinstance(observation, DirectoryObservation):
        return observation.directory
    if isinstance(observation, GroupObservation):
        return observation.group
    if isinstance(observation, RoleObservation):
        return observation.role
    if isinstance(observation, PermissionObservation):
        return observation.permission
    if isinstance(observation, ResourceObservation):
        return observation.resource
    if isinstance(observation, PermissionAssignmentObservation):
        return observation.role
    if isinstance(observation, RelationshipObservation):
        return observation.source
    identity = getattr(observation, "identity", None)
    return identity or "unknown"


def artifact_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    raw_output: str,
    *,
    session_id: SessionID | None = None,
    mode: IdentityMode = IdentityMode.CONTROLLED,
    summary: str | None = None,
) -> Evidence:
    """Raw mock output preserved as authoritative ARTIFACT evidence.

    Credential-like fields (hashes, tickets, tokens, secrets) are recursively
    redacted from the raw document before the payload is stored so no
    plaintext secret ever reaches the evidence ledger.
    """
    redacted_raw = redact_identity_raw(raw_output)
    try:
        payload_doc = json.loads(redacted_raw)
    except (json.JSONDecodeError, TypeError):
        payload_doc = {"raw": redacted_raw}
    if isinstance(payload_doc, dict):
        payload_doc["mode"] = mode.value
        payload = json.dumps(payload_doc, sort_keys=True)
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
        or f"{capability_id} raw output for {target} (mock identity transport)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"identity": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: Observation,
    *,
    session_id: SessionID | None = None,
    mode: IdentityMode = IdentityMode.CONTROLLED,
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
        ),
        summary=observation_summary(observation),
        reference=observation_reference(observation),
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={
            "identity": True,
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
