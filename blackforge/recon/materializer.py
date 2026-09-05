from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    MissionID,
    SessionID,
)
from blackforge.recon.models import (
    DNSObservation,
    HostObservation,
    HTTPObservation,
    NetworkObservation,
    Observation,
    PortObservation,
    ServiceObservation,
    TechnologyObservation,
    TLSObservation,
)
from blackforge.world_model.materializer import (
    EntityFact,
    RelationshipFact,
    WorldMaterializer,
)
from blackforge.world_model.models import (
    EntityType,
    EvidenceLinkRef,
    RelationshipType,
    WorldEntity,
)

if TYPE_CHECKING:
    from blackforge.world_model.store import WorldModelStore

_OBSERVED = [EvidenceStatus.OBSERVED]


def _ref(evidence_id: EvidenceID, **properties: str | None) -> EvidenceLinkRef:
    return EvidenceLinkRef(
        evidence_id=evidence_id,
        property_key=properties.get("property_key"),
        property_value=properties.get("property_value"),
    )


def _port_name(port: int, protocol: str) -> str:
    return f"{port}/{protocol.lower()}"


class MaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class MaterializeReport(BaseModel):
    entries: list[MaterializeEntry] = Field(default_factory=list)
    relationships_created: int = 0
    relationships_corroborated: int = 0

    @property
    def entities_created(self) -> int:
        return sum(1 for e in self.entries if e.action == "created")

    @property
    def entities_updated(self) -> int:
        return len(self.entries) - self.entities_created


class ReconWorldMaterializer:
    """Maps typed reconnaissance observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text:

    * HOST -> ASSET (name = hostname or IP literal)
    * SERVICE/PORT -> SERVICE (namespace = host) + ``ASSET EXPOSES SERVICE``
    * TECHNOLOGY -> TECHNOLOGY (namespace = host), connected via ``USES``
    * HTTP -> ENDPOINT (URL) + service and ``SERVICE EXPOSES ENDPOINT``
    * TLS -> ENDPOINT (namespace ``tls``), no edges
    * DNS -> evidence only; A/AAAA IP answers materialize as ASSET entities
    * NETWORK -> NETWORK (canonical CIDR), no auto edges

    All records carry row-level evidence references and use OBSERVED status
    (their supporting evidence is OBSERVED), so re-running the same
    reconnaissance corroborates instead of duplicating.
    """

    def __init__(self, store: WorldModelStore) -> None:
        self._store = store
        self._materializer = WorldMaterializer(store)

    @property
    def store(self) -> WorldModelStore:
        return self._store

    def materialize(
        self,
        mission_id: MissionID,
        observations: list[tuple[Observation, EvidenceID, Confidence]],
        *,
        session_id: SessionID | None = None,
    ) -> MaterializeReport:
        report = MaterializeReport()
        for observation, evidence_id, confidence in observations:
            self._materialize_one(
                mission_id,
                observation,
                evidence_id,
                confidence,
                report,
                session_id=session_id,
            )
        return report

    # ------------------------------------------------------------------
    # Per-kind mapping
    # ------------------------------------------------------------------
    def _materialize_one(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: MaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        if isinstance(observation, HostObservation):
            self._materialize_host(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, ServiceObservation):
            self._materialize_service(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, PortObservation):
            self._materialize_port(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, TechnologyObservation):
            self._materialize_technology(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, HTTPObservation):
            self._materialize_http(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, TLSObservation):
            self._materialize_tls(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, DNSObservation):
            self._materialize_dns(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, NetworkObservation):
            self._materialize_network(
                mission_id, observation, evidence_id, confidence, report, session_id
            )

    # ------------------------------------------------------------------
    def _materialize_host(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ASSET,
                name=obs.host,
                properties={
                    "ip_addresses": list(obs.ip_addresses),
                    "os": obs.os,
                    "status": obs.status,
                    "source": "recon.host_discovery",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="host", property_value=obs.host)],
            ),
            session_id,
        )
        self._record(report, "asset", entity, action)

    def _materialize_service(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        asset = self._ensure_asset(mission_id, obs.host, evidence_id, confidence, session_id)
        service, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SERVICE,
                name=_port_name(obs.port, obs.protocol),
                namespace=obs.host,
                properties={
                    "service": obs.service,
                    "version": obs.version,
                    "banner": obs.banner,
                    "state": obs.state,
                },
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="port", property_value=str(obs.port))],
            ),
            session_id,
        )
        self._link_exposes(mission_id, asset, service, evidence_id, confidence, report, session_id)
        self._record(report, "service", service, action)

    def _materialize_port(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        asset = self._ensure_asset(mission_id, obs.host, evidence_id, confidence, session_id)
        service, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SERVICE,
                name=_port_name(obs.port, obs.protocol),
                namespace=obs.host,
                properties={"service": "unknown", "state": obs.state},
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="port", property_value=str(obs.port))],
            ),
            session_id,
        )
        self._link_exposes(mission_id, asset, service, evidence_id, confidence, report, session_id)
        self._record(report, "service", service, action)

    def _materialize_technology(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        asset = self._ensure_asset(mission_id, obs.host, evidence_id, confidence, session_id)
        technology, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.TECHNOLOGY,
                name=obs.technology,
                namespace=obs.host,
                properties={
                    "category": obs.category,
                    "version": obs.version,
                    "port": obs.port,
                    "detection_confidence": obs.detection_confidence,
                },
                confidence=confidence,
                evidence=[
                    _ref(
                        evidence_id,
                        property_key="technology",
                        property_value=obs.technology,
                    )
                ],
            ),
            session_id,
        )
        if obs.port is not None:
            service = self._store.find_entity(
                mission_id,
                EntityType.SERVICE,
                _port_name(obs.port, "tcp"),
                namespace=obs.host,
            )
            source = service if service is not None else asset
        else:
            source = asset
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.USES,
                source_entity_id=str(source.id),
                target_entity_id=str(technology.id),
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        self._record(report, "technology", technology, action)

    def _materialize_http(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        asset = self._ensure_asset(mission_id, obs.host, evidence_id, confidence, session_id)
        port = obs.port or (443 if obs.url.startswith("https://") else 80)
        service_name = "https" if obs.url.startswith("https://") else "http"
        service, _ = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SERVICE,
                name=_port_name(port, "tcp"),
                namespace=obs.host,
                properties={"service": service_name, "state": "open"},
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="port", property_value=str(port))],
            ),
            session_id,
        )
        self._link_exposes(mission_id, asset, service, evidence_id, confidence, report, session_id)
        endpoint, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ENDPOINT,
                name=obs.url,
                properties={
                    "status_code": obs.status_code,
                    "server_header": obs.server_header,
                    "title": obs.title,
                    "redirect_location": obs.redirect_location,
                    "headers_count": len(obs.headers),
                },
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="url", property_value=obs.url)],
            ),
            session_id,
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.EXPOSES,
                source_entity_id=str(service.id),
                target_entity_id=str(endpoint.id),
                note="http metadata",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        self._record(report, "endpoint", endpoint, action)

    def _materialize_tls(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ENDPOINT,
                name=f"https://{obs.host}:{obs.port}/",
                namespace="tls",
                properties={
                    "certificate_subject": obs.certificate_subject,
                    "certificate_issuer": obs.certificate_issuer,
                    "not_before": obs.not_before,
                    "not_after": obs.not_after,
                    "tls_version": obs.tls_version,
                    "cipher": obs.cipher,
                    "sni_required": obs.sni_required,
                    "hostname_matches": obs.hostname_matches,
                },
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="tls", property_value=obs.host)],
            ),
            session_id,
        )
        self._record(report, "tls_endpoint", entity, action)

    def _materialize_dns(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        for answer in obs.answers:
            ip = self._try_ip(answer)
            if ip is None:
                continue
            entity, action = self._upsert_entity(
                mission_id,
                EntityFact(
                    entity_type=EntityType.ASSET,
                    name=ip,
                    properties={"source": "recon.dns", "dns_record": obs.record_type},
                    confidence=confidence,
                    evidence=[_ref(evidence_id, property_key="ip_address", property_value=ip)],
                ),
                session_id,
            )
            self._record(report, "asset", entity, action)

    def _materialize_network(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.NETWORK,
                name=obs.cidr,
                properties={
                    "network_name": obs.network_name,
                    "exposure": obs.exposure,
                    "hosts_count": len(obs.hosts),
                },
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="network", property_value=obs.cidr)],
            ),
            session_id,
        )
        self._record(report, "network", entity, action)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _ensure_asset(
        self,
        mission_id: MissionID,
        host: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        existing = self._store.find_entity(mission_id, EntityType.ASSET, host)
        if existing is not None:
            return existing
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ASSET,
                name=host,
                properties={"source": "recon"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _upsert_entity(
        self,
        mission_id: MissionID,
        fact: EntityFact,
        session_id: SessionID | None,
    ) -> tuple[WorldEntity, str]:
        result = self._materializer.materialize_entity(
            mission_id, fact, _OBSERVED, session_id
        )
        return result.entity, result.action.value

    def _link_exposes(
        self,
        mission_id: MissionID,
        asset: WorldEntity,
        service: WorldEntity,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: MaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.EXPOSES,
                source_entity_id=str(asset.id),
                target_entity_id=str(service.id),
                note="observed service",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    def _link_report(
        self,
        mission_id: MissionID,
        fact: RelationshipFact,
        report: MaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        result = self._materializer.materialize_relationship(mission_id, fact, session_id)
        if result.action.value == "created":
            report.relationships_created += 1
        else:
            report.relationships_corroborated += 1

    @staticmethod
    def _record(
        report: MaterializeReport,
        entity_type: str,
        entity: WorldEntity,
        action: str,
    ) -> None:
        report.entries.append(
            MaterializeEntry(
                entity_type=entity_type,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    @staticmethod
    def _try_ip(value: str) -> str | None:
        from blackforge.world_model.canonical import normalize_ip

        try:
            return normalize_ip(value)
        except ValueError:
            return None
