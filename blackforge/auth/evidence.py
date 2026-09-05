from __future__ import annotations

import json

from blackforge.auth.models import (
    AccessControlObservation,
    AuthenticationSchemeObservation,
    AuthMode,
    AuthorizationSurfaceObservation,
    AuthSurfaceObservation,
    MfaSurfaceObservation,
    OAuthMetadataObservation,
    Observation,
    OidcMetadataObservation,
    PermissionObservation,
    ResourceAccessObservation,
    RoleObservation,
    SessionObservation,
)
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
        "auth_surface",
        "auth_scheme",
        "session",
        "oauth_metadata",
        "oidc_metadata",
        "mfa_surface",
        "authorization_surface",
    }
)
_DERIVED_KIND_VALUES = frozenset({"role", "permission"})
_VALIDATED_KIND_VALUES = frozenset({"resource_access", "access_control"})


def observation_confidence(observation: Observation, mode: AuthMode) -> Confidence:
    """Confidence policy for authentication/authorization observations.

    * Anything observed without an active probe (``PASSIVE``) is LOW.
    * Direct active observations of an authentication surface, scheme,
      session, OAuth/OIDC metadata, MFA surface, or authorization surface are
      HIGH.
    * Derived identity observations (roles, permissions) are MEDIUM.
    * Controlled, validated access results (resource access, access control)
      are HIGH — they are explicit outcomes from authorized test identities.
    """
    if mode == AuthMode.PASSIVE:
        return Confidence.LOW
    if observation.kind in _DIRECT_KIND_VALUES:
        return Confidence.HIGH
    if observation.kind in _DERIVED_KIND_VALUES:
        return Confidence.MEDIUM
    if observation.kind in _VALIDATED_KIND_VALUES:
        return Confidence.HIGH
    return Confidence.LOW


def observation_summary(observation: Observation) -> str:
    """One-line human summary for an auth observation (evidence summary)."""
    if isinstance(observation, AuthSurfaceObservation):
        return (
            f"Auth surface {observation.scheme} ({observation.scheme_type or '-'}) "
            f"on {observation.host}"
        )
    if isinstance(observation, AuthenticationSchemeObservation):
        return (
            f"Auth scheme {observation.scheme} on {observation.host} "
            f"present={observation.present}"
        )
    if isinstance(observation, SessionObservation):
        return (
            f"Session {observation.name} on {observation.host} "
            f"flags={','.join(observation.flags) or '-'}"
        )
    if isinstance(observation, OAuthMetadataObservation):
        return (
            f"OAuth2 metadata on {observation.host} "
            f"grants={','.join(observation.grant_types) or '-'} "
            f"pkce={observation.pkce_supported}"
        )
    if isinstance(observation, OidcMetadataObservation):
        return (
            f"OIDC metadata on {observation.host} "
            f"issuer={observation.issuer or '-'} alg={observation.id_token_signing_alg or '-'}"
        )
    if isinstance(observation, MfaSurfaceObservation):
        return (
            f"MFA surface on {observation.host} "
            f"status={observation.mfa_status.value}"
        )
    if isinstance(observation, AuthorizationSurfaceObservation):
        return (
            f"Authorization model {observation.authz_model} "
            f"on {observation.host}"
        )
    if isinstance(observation, RoleObservation):
        return f"Role {observation.role} on {observation.host}"
    if isinstance(observation, PermissionObservation):
        return (
            f"Permission {observation.permission} for {observation.identity or '-'} "
            f"on {observation.host} granted={observation.granted}"
        )
    if isinstance(observation, ResourceAccessObservation):
        return (
            f"Resource access for {observation.identity or '-'} -> "
            f"{observation.resource} on {observation.host} access={observation.access.value}"
        )
    if isinstance(observation, AccessControlObservation):
        return (
            f"Access control for {observation.identity or '-'} -> "
            f"{observation.resource} on {observation.host} "
            f"access={observation.access.value} expected={observation.expected_access.value} "
            f"consistent={observation.consistent}"
        )
    return f"Auth observation {observation.kind} on {observation.host}"


def observation_reference(observation: Observation) -> str:
    """Default evidence reference for an observation (its URL)."""
    return observation.url


def artifact_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    raw_output: str,
    *,
    session_id: SessionID | None = None,
    mode: AuthMode = AuthMode.ACTIVE,
    summary: str | None = None,
) -> Evidence:
    """Raw mock output preserved as authoritative ARTIFACT evidence."""
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.ARTIFACT,
        status=EvidenceStatus.OBSERVED,
        confidence=Confidence.HIGH,
        raw_data=raw_output,
        summary=summary
        or f"{capability_id} raw output for {target} (mock auth transport)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"auth": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: Observation,
    *,
    session_id: SessionID | None = None,
    mode: AuthMode = AuthMode.ACTIVE,
) -> Evidence:
    """Typed OBSERVATION evidence derived from a normalized observation."""
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.OBSERVATION,
        status=EvidenceStatus.OBSERVED,
        confidence=observation_confidence(observation, mode),
        raw_data=json.dumps(observation.model_dump(), sort_keys=True),
        summary=observation_summary(observation),
        reference=observation_reference(observation),
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={
            "auth": True,
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
