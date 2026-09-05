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
from blackforge.webapi.models import (
    ApiObservation,
    AuthSurfaceObservation,
    CookieObservation,
    CorsObservation,
    EndpointObservation,
    GraphQlObservation,
    Observation,
    OpenApiObservation,
    RequestOutcomeObservation,
    SecurityHeaderObservation,
    WebApiMode,
    WebApplicationObservation,
)

_DIRECT_KIND_VALUES = frozenset({"application", "endpoint", "request_response"})
_DOCUMENT_KIND_VALUES = frozenset(
    {"security_header", "cookie", "cors", "auth_surface", "api", "openapi", "graphql"}
)


def observation_confidence(observation: Observation, mode: WebApiMode) -> Confidence:
    """Confidence policy for web/api observations.

    * Direct active observations (an app responded, an endpoint answered, a
      plain GET round-trip) observed in ACTIVE mode get HIGH confidence.
    * Document-derived analysis (security headers, cookies, CORS, auth
      surfaces, API/OpenAPI/GraphQL metadata) gets MEDIUM confidence.
    * Anything observed without an active probe gets LOW confidence.
    """
    if mode == WebApiMode.PASSIVE:
        return Confidence.LOW
    if observation.kind in _DIRECT_KIND_VALUES:
        return Confidence.HIGH
    if observation.kind in _DOCUMENT_KIND_VALUES:
        return Confidence.MEDIUM
    return Confidence.LOW


def observation_summary(observation: Observation) -> str:
    """One-line human summary for an observation (evidence summary)."""
    if isinstance(observation, WebApplicationObservation):
        return (
            f"Web app {observation.url} title={observation.title or '-'} "
            f"tech={','.join(observation.technologies) or '-'} tls={observation.tls_version or '-'}"
        )
    if isinstance(observation, EndpointObservation):
        return (
            f"Endpoint {observation.method} {observation.url} status={observation.status_code} "
            f"content_type={observation.content_type or '-'}"
        )
    if isinstance(observation, ApiObservation):
        return (
            f"API {observation.url} style={observation.style} "
            f"kind={observation.kind_label or '-'} docs={observation.docs_url or '-'}"
        )
    if isinstance(observation, SecurityHeaderObservation):
        return (
            f"Security header {observation.header_name} "
            f"{'present' if observation.present else 'missing'} on {observation.url}"
        )
    if isinstance(observation, CookieObservation):
        return (
            f"Cookie {observation.name} on {observation.host} "
            f"flags={','.join(observation.flags) or '-'}"
        )
    if isinstance(observation, CorsObservation):
        return (
            f"CORS {observation.host} origins={len(observation.allow_origins)} "
            f"credentials={observation.allow_credentials} wildcard={observation.wildcard_origin}"
        )
    if isinstance(observation, AuthSurfaceObservation):
        return (
            f"Auth surface {observation.scheme} ({observation.scheme_type or '-'}) "
            f"on {observation.url}"
        )
    if isinstance(observation, OpenApiObservation):
        return (
            f"OpenAPI {observation.url} v={observation.spec_version or '-'} "
            f"operations={observation.operation_count} paths={observation.path_count}"
        )
    if isinstance(observation, GraphQlObservation):
        return (
            f"GraphQL {observation.url} introspection={observation.introspection_enabled} "
            f"types={observation.type_count} queries={observation.query_count}"
        )
    if isinstance(observation, RequestOutcomeObservation):
        return (
            f"Request {observation.method} {observation.url} "
            f"status={observation.status_code or '-'} rtt_ms={observation.rtt_ms or '-'}"
        )
    return f"Web observation {observation.kind} on {observation.host}"


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
    mode: WebApiMode = WebApiMode.ACTIVE,
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
        or f"{capability_id} raw output for {target} (mock web transport)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"webapi": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: Observation,
    *,
    session_id: SessionID | None = None,
    mode: WebApiMode = WebApiMode.ACTIVE,
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
            "webapi": True,
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
