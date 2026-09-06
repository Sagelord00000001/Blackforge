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
from blackforge.network.models import (
    BannerObservation,
    DnsObservation,
    ExposureObservation,
    HostObservation,
    InfrastructureObservation,
    NetworkEvidenceObservation,
    NetworkMode,
    Observation,
    PortObservation,
    ProtocolObservation,
    ServiceApplicationObservation,
    ServiceObservation,
    TlsObservation,
)
from blackforge.network.redaction import redact_banner_text

_DIRECT_KIND_VALUES = frozenset(
    {"host", "port", "service", "protocol", "banner", "dns", "tls"}
)
_DERIVED_KIND_VALUES = frozenset(
    {"exposure", "infrastructure", "service_application", "network_evidence"}
)


def observation_confidence(
    observation: Observation, mode: NetworkMode
) -> Confidence:
    """Confidence policy for network observations.

    * Anything observed without an active probe (``PASSIVE``) is LOW.
    * Direct active observations (host/port/service/protocol/banner/dns/tls)
      are HIGH.
    * Derived analysis (exposure/infrastructure/service_application/
      network_evidence) is MEDIUM.
    """
    if mode == NetworkMode.PASSIVE:
        return Confidence.LOW
    if observation.kind in _DIRECT_KIND_VALUES:
        return Confidence.HIGH
    if observation.kind in _DERIVED_KIND_VALUES:
        return Confidence.MEDIUM
    return Confidence.LOW


def observation_summary(observation: Observation) -> str:
    """One-line human summary for a network observation."""
    if isinstance(observation, HostObservation):
        return (
            f"Host {observation.host} ({observation.ip}) role={observation.role}"
        )
    if isinstance(observation, PortObservation):
        return (
            f"Port {observation.port}/{observation.transport} on {observation.host} "
            f"state={observation.state.value}"
        )
    if isinstance(observation, ServiceObservation):
        return (
            f"Service {observation.service} on {observation.host}:"
            f"{observation.port}/{observation.transport}"
        )
    if isinstance(observation, ProtocolObservation):
        return (
            f"Protocol {observation.protocol} on {observation.host}:"
            f"{observation.port}/{observation.transport}"
        )
    if isinstance(observation, BannerObservation):
        text = observation.banner[:60]
        suffix = "..." if len(observation.banner) > 60 else ""
        return (
            f"Banner on {observation.host}:{observation.port} "
            f"[{text}{suffix}] truncated={observation.truncated}"
        )
    if isinstance(observation, DnsObservation):
        return (
            f"DNS {observation.record_type} {observation.name} = "
            f"{observation.value} via {observation.server}"
        )
    if isinstance(observation, TlsObservation):
        return (
            f"TLS {observation.version} on {observation.host}:{observation.port} "
            f"subject={observation.certificate_subject}"
        )
    if isinstance(observation, ExposureObservation):
        return (
            f"Exposure on {observation.host} interface={observation.interface} "
            f"exposed={observation.exposed} public={observation.public}"
        )
    if isinstance(observation, InfrastructureObservation):
        return (
            f"Infrastructure {observation.infrastructure} for {observation.host} "
            f"role={observation.role} device={observation.network_device}"
        )
    if isinstance(observation, ServiceApplicationObservation):
        return (
            f"Service {observation.service} serves application "
            f"{observation.application} on {observation.host}"
        )
    if isinstance(observation, NetworkEvidenceObservation):
        return (
            f"Network evidence for {observation.host}: {observation.detail}"
        )
    return f"Network observation {observation.kind} on {observation.host}"


def observation_reference(observation: Observation) -> str:
    """Default evidence reference for an observation (its host or server)."""
    if isinstance(observation, DnsObservation):
        return observation.server
    host = getattr(observation, "host", None)
    return host or "unknown"


def artifact_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    raw_output: str,
    *,
    session_id: SessionID | None = None,
    mode: NetworkMode = NetworkMode.ACTIVE,
    summary: str | None = None,
) -> Evidence:
    """Raw mock output preserved as authoritative ARTIFACT evidence.

    JSON banners marked ``banner_is_json=True`` are credential-redacted
    before the raw payload is stored so no plaintext secrets ever reach the
    evidence ledger.
    """
    redacted_raw = _redact_raw_banner_json(raw_output)
    try:
        payload_doc = json.loads(redacted_raw)
    except (json.JSONDecodeError, TypeError):
        payload_doc = {"raw": redacted_raw}
    if isinstance(payload_doc, dict):
        payload_doc["mode"] = mode.value
        payload = json.dumps(payload_doc, sort_keys=True)
    else:
        payload = json.dumps({"mode": mode.value, "raw": redacted_raw}, sort_keys=True)
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
        or f"{capability_id} raw output for {target} (mock network transport)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"network": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: Observation,
    *,
    session_id: SessionID | None = None,
    mode: NetworkMode = NetworkMode.ACTIVE,
) -> Evidence:
    """Typed OBSERVATION evidence derived from a normalized observation.

    The mode is embedded in the raw payload so a PASSIVE observation never
    dedups onto an ACTIVE record (confidence is mode-derived); repeated runs
    in the same mode still coalesce.
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
            "network": True,
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


def _redact_raw_banner_json(raw: str) -> str:
    """Redact JSON-encoded banners within the raw tool output before storage.

    Only banners whose ``banner_is_json`` flag is true are redacted; all
    other raw data is stored verbatim.
    """
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw
    changed = False
    for obs in doc.get("observations", []):
        if (
            isinstance(obs, dict)
            and obs.get("kind") == "banner"
            and obs.get("banner_is_json")
            and isinstance(obs.get("banner"), str)
        ):
            obs["banner"] = redact_banner_text(obs["banner"])
            changed = True
    return json.dumps(doc, sort_keys=True) if changed else raw
