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
from blackforge.recon.models import (
    DNSObservation,
    HostObservation,
    HTTPObservation,
    NetworkObservation,
    Observation,
    PortObservation,
    ReconMode,
    ServiceObservation,
    TechnologyObservation,
    TLSObservation,
)

_DIRECT_KIND_VALUES = frozenset({"host", "port", "service", "http", "tls"})


def observation_confidence(observation: Observation, mode: ReconMode) -> Confidence:
    """Confidence policy for reconnaissance observations.

    * Directly observed network state (host up, open port/service, live HTTP
      and TLS responses) gets HIGH confidence.
    * Fingerprinted/banner-derived technology detection gets MEDIUM confidence.
    * Passive inference (DNS records, network-segment guesses, or anything
      observed without an active probe) gets LOW confidence.
    """
    if observation.kind in _DIRECT_KIND_VALUES and mode == ReconMode.ACTIVE:
        return Confidence.HIGH
    if observation.kind == "technology":
        return Confidence.MEDIUM
    return Confidence.LOW


def observation_summary(observation: Observation) -> str:
    """One-line human summary for an observation (used as evidence summary)."""
    if isinstance(observation, HostObservation):
        ips = ", ".join(observation.ip_addresses) or "-"
        return (
            f"Host {observation.host} status={observation.status} os={observation.os or 'unknown'} "
            f"ips=[{ips}]"
        )
    if isinstance(observation, PortObservation):
        return (
            f"Port {observation.host}:{observation.port}/{observation.protocol} "
            f"state={observation.state}"
        )
    if isinstance(observation, ServiceObservation):
        version = f" {observation.version}" if observation.version else ""
        return (
            f"Service {observation.host}:{observation.port}/{observation.protocol} "
            f"{observation.service}{version} state={observation.state}"
        )
    if isinstance(observation, TechnologyObservation):
        version = f" {observation.version}" if observation.version else ""
        port = f" port={observation.port}" if observation.port else ""
        return (
            f"Technology {observation.technology}{version} "
            f"(category={observation.category}{port}) on {observation.host}"
        )
    if isinstance(observation, DNSObservation):
        return (
            f"DNS {observation.host} {observation.record_type} "
            f"-> {', '.join(observation.answers)}"
        )
    if isinstance(observation, HTTPObservation):
        return (
            f"HTTP {observation.url} status={observation.status_code} "
            f"server={observation.server_header or '-'} title={observation.title or '-'}"
        )
    if isinstance(observation, TLSObservation):
        return (
            f"TLS {observation.host}:{observation.port} "
            f"subject={observation.certificate_subject} "
            f"valid={observation.not_before}..{observation.not_after}"
        )
    if isinstance(observation, NetworkObservation):
        return (
            f"Network {observation.cidr} name={observation.network_name or '-'} "
            f"exposure={observation.exposure} hosts={len(observation.hosts)}"
        )
    return f"Observation {observation.kind} on {observation.host}"


def observation_reference(observation: Observation) -> str:
    """Default evidence reference for an observation (host, URL, or CIDR)."""
    if isinstance(observation, HTTPObservation):
        return observation.url
    if isinstance(observation, NetworkObservation):
        return observation.cidr
    return observation.host


def artifact_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    raw_output: str,
    *,
    session_id: SessionID | None = None,
    mode: ReconMode = ReconMode.ACTIVE,
    summary: str | None = None,
) -> Evidence:
    """Raw tool output preserved as authoritative ARTIFACT evidence."""
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
        or f"{capability_id} raw output for {target} (mock tool)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"recon": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: Observation,
    *,
    session_id: SessionID | None = None,
    mode: ReconMode = ReconMode.ACTIVE,
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
            "recon": True,
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
