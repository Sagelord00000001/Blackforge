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
from blackforge.network.models import (
    BannerObservation,
    DnsObservation,
    ExposureObservation,
    HostObservation,
    InfrastructureObservation,
    NetworkEvidenceObservation,
    Observation,
    PortObservation,
    ProtocolObservation,
    ServiceApplicationObservation,
    ServiceObservation,
    TlsObservation,
)
from blackforge.world_model.materializer import (
    EntityFact,
    RelationshipFact,
    WorldMaterializer,
)
from blackforge.world_model.models import (
    AssertionSpec,
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


class NetworkMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class NetworkMaterializeReport(BaseModel):
    entries: list[NetworkMaterializeEntry] = Field(default_factory=list)
    relationships_created: int = 0
    relationships_corroborated: int = 0
    assertions_created: int = 0
    assertions_corroborated: int = 0

    @property
    def entities_created(self) -> int:
        return sum(1 for e in self.entries if e.action == "created")

    @property
    def entities_updated(self) -> int:
        return len(self.entries) - self.entities_created


class NetworkWorldMaterializer:
    """Maps typed network observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text. The
    base namespaces by host (or DNS server); the chain is:

    * HOST --HAS_PORT--> PORT --RUNS_SERVICE--> SERVICE
      --USES_PROTOCOL--> PROTOCOL (from host/port/service/protocol observation)
    * HOST --HAS_INTERFACE--> INTERFACE (from exposure observations)
    * HOST --MEMBER_OF--> NETWORK (from infrastructure observations)
    * SERVICE --SERVES--> APPLICATION (from service-application correlation)
    * Banner/TLS/DNS/evidence outcomes become assertions on the host so a
      re-run never churns entity versions.

    All edges are descriptive/structural. No offensive semantics (EXPLOITS,
    CAN_COMPROMISE, LEADS_TO, ENABLES) are ever produced here.
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
    ) -> NetworkMaterializeReport:
        report = NetworkMaterializeReport()
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
        report: NetworkMaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        if isinstance(observation, HostObservation):
            self._materialize_host(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, PortObservation):
            self._materialize_port(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, ServiceObservation):
            self._materialize_service(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, ProtocolObservation):
            self._materialize_protocol(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, ExposureObservation):
            self._materialize_exposure(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, InfrastructureObservation):
            self._materialize_infrastructure(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, ServiceApplicationObservation):
            self._materialize_correlation(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(
            observation,
            (BannerObservation, TlsObservation, DnsObservation, NetworkEvidenceObservation),
        ):
            self._assert_on_host(
                mission_id, observation, evidence_id, confidence, report, session_id
            )

    # ------------------------------------------------------------------
    def _materialize_host(
        self, mission_id, obs: HostObservation, evidence_id, confidence, report, session_id
    ) -> None:
        host, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.HOST,
                name=obs.ip,
                namespace=obs.host,
                properties={
                    "host": obs.host,
                    "ip": obs.ip,
                    "domain": obs.domain,
                    "is_network_device": obs.is_network_device,
                    "role": obs.role,
                    "operating_system": obs.operating_system,
                    "source": "network.host_discovery",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        report.entries.append(
            NetworkMaterializeEntry(
                entity_type="host",
                name=host.name,
                namespace=host.namespace,
                entity_id=str(host.id),
                action=action,
            )
        )

    def _materialize_port(
        self, mission_id, obs: PortObservation, evidence_id, confidence, report, session_id
    ) -> None:
        if obs.state.value != "open":
            return
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.PORT,
                name=str(obs.port),
                namespace=obs.host,
                properties={
                    "port": obs.port,
                    "transport": obs.transport,
                    "state": obs.state.value,
                    "host": obs.host,
                    "source": "network.port_discovery",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        host = self._ensure_host(mission_id, obs.host, evidence_id, confidence, session_id)
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_PORT,
                source_entity_id=str(host.id),
                target_entity_id=str(entity.id),
                note="host opens port",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            NetworkMaterializeEntry(
                entity_type="port",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_service(
        self, mission_id, obs: ServiceObservation, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SERVICE,
                name=obs.service,
                namespace=obs.host,
                properties={
                    "service": obs.service,
                    "version": obs.version,
                    "port": obs.port,
                    "transport": obs.transport,
                    "host": obs.host,
                    "source": "network.service_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        host = self._ensure_host(mission_id, obs.host, evidence_id, confidence, session_id)
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.RUNS_SERVICE,
                source_entity_id=str(host.id),
                target_entity_id=str(entity.id),
                note="host runs service",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            NetworkMaterializeEntry(
                entity_type="service",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_protocol(
        self, mission_id, obs: ProtocolObservation, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.PROTOCOL,
                name=obs.protocol,
                namespace=obs.host,
                properties={
                    "protocol": obs.protocol,
                    "port": obs.port,
                    "transport": obs.transport,
                    "host": obs.host,
                    "source": "network.protocol_identification",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        service = self._find_service(
            mission_id, obs.host, obs.port, evidence_id, confidence, session_id
        )
        if service is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.USES_PROTOCOL,
                    source_entity_id=str(service.id),
                    target_entity_id=str(entity.id),
                    note="service uses protocol",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            NetworkMaterializeEntry(
                entity_type="protocol",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_exposure(
        self, mission_id, obs: ExposureObservation, evidence_id, confidence, report, session_id
    ) -> None:
        host = self._ensure_host(mission_id, obs.host, evidence_id, confidence, session_id)
        interface, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.INTERFACE,
                name=obs.interface or "default",
                namespace=obs.host,
                properties={
                    "interface": obs.interface,
                    "exposed": obs.exposed,
                    "public": obs.public,
                    "host": obs.host,
                    "source": "network.network_exposure_analysis",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_INTERFACE,
                source_entity_id=str(host.id),
                target_entity_id=str(interface.id),
                note="host has interface",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            NetworkMaterializeEntry(
                entity_type="interface",
                name=interface.name,
                namespace=interface.namespace,
                entity_id=str(interface.id),
                action=action,
            )
        )

    def _materialize_infrastructure(
        self, mission_id, obs: InfrastructureObservation, evidence_id,
        confidence, report, session_id
    ) -> None:
        network, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.INFRASTRUCTURE,
                name=obs.infrastructure,
                namespace=None,
                properties={
                    "infrastructure": obs.infrastructure,
                    "role": obs.role,
                    "network_device": obs.network_device,
                    "source": "network.infrastructure_modeling",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        host_entity = self._ensure_host(
            mission_id, obs.host, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.MEMBER_OF,
                source_entity_id=str(host_entity.id),
                target_entity_id=str(network.id),
                note="host member of network",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            NetworkMaterializeEntry(
                entity_type="infrastructure",
                name=network.name,
                namespace=network.namespace,
                entity_id=str(network.id),
                action=action,
            )
        )

    def _materialize_correlation(
        self, mission_id, obs: ServiceApplicationObservation, evidence_id,
        confidence, report, session_id
    ) -> None:
        service = self._find_service_by_name(
            mission_id, obs.host, obs.service, evidence_id, confidence, session_id
        )
        if service is None:
            return
        application, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.APPLICATION,
                name=obs.application,
                namespace=obs.host,
                properties={
                    "application": obs.application,
                    "host": obs.host,
                    "source": "network.service_application_correlation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.SERVES,
                source_entity_id=str(service.id),
                target_entity_id=str(application.id),
                note="service serves application",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            NetworkMaterializeEntry(
                entity_type="application",
                name=application.name,
                namespace=application.namespace,
                entity_id=str(application.id),
                action=action,
            )
        )

    # ------------------------------------------------------------------
    # Assertions
    # ------------------------------------------------------------------
    def _assert_on_host(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: NetworkMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        host_entity = self._ensure_host_by_name(
            mission_id, _observation_host(observation), evidence_id, confidence, session_id
        )
        if host_entity is None:
            return
        for key, value in _assertion_pairs(observation):
            result = self._store.add_assertion(
                AssertionSpec(
                    mission_id=mission_id,
                    session_id=session_id,
                    entity_id=host_entity.id,
                    property_key=key,
                    property_value=value,
                    epistemic_status=EvidenceStatus.OBSERVED,
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                )
            )
            if result.action.value == "created":
                report.assertions_created += 1
            else:
                report.assertions_corroborated += 1

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _link_report(self, mission_id, fact, report, session_id) -> None:
        result = self._materializer.materialize_relationship(mission_id, fact, session_id)
        if result.action.value == "created":
            report.relationships_created += 1
        else:
            report.relationships_corroborated += 1

    def _upsert_entity(self, mission_id, fact, session_id) -> tuple[WorldEntity, str]:
        result = self._materializer.materialize_entity(
            mission_id, fact, _OBSERVED, session_id
        )
        return result.entity, result.action.value

    def _ensure_host(
        self,
        mission_id: MissionID,
        obs,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.HOST,
                name=obs.ip,
                namespace=obs.host,
                properties={
                    "host": obs.host,
                    "ip": obs.ip,
                    "source": "network",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _ensure_host(
        self,
        mission_id: MissionID,
        hostname: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        existing = self._ensure_host_by_name(
            mission_id, hostname, evidence_id, confidence, session_id
        )
        if existing is not None:
            return existing
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.HOST,
                name=hostname,
                namespace=hostname,
                properties={"host": hostname, "source": "network"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _ensure_host_by_name(
        self,
        mission_id: MissionID,
        hostname: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        existing = self._store.find_entity(mission_id, EntityType.HOST, hostname)
        if existing is not None:
            return existing
        from blackforge.world_model.query import WorldQuery

        query = WorldQuery(
            mission_id=mission_id,
            entity_type=EntityType.HOST,
            namespace=hostname,
            limit=1,
        )
        matches = self._store.list_entities(query)
        return matches[0] if matches else None

    def _find_service(
        self,
        mission_id: MissionID,
        host: str,
        port: int,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        from blackforge.world_model.query import WorldQuery

        query = WorldQuery(
            mission_id=mission_id,
            entity_type=EntityType.SERVICE,
            namespace=host,
            limit=100,
        )
        for entity in self._store.list_entities(query):
            props = entity.properties or {}
            try:
                if int(props.get("port", -1)) == port:
                    return entity
            except (TypeError, ValueError):
                continue
        return None

    def _find_service_by_name(
        self,
        mission_id: MissionID,
        host: str,
        service: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        from blackforge.world_model.query import WorldQuery

        query = WorldQuery(
            mission_id=mission_id,
            entity_type=EntityType.SERVICE,
            namespace=host,
            limit=100,
        )
        for entity in self._store.list_entities(query):
            if entity.name == service:
                return entity
        return None


def _observation_host(observation: Observation) -> str:
    """Host reference for assertion-bearing observations."""
    if isinstance(observation, DnsObservation):
        return observation.server
    return observation.host


def _assertion_pairs(observation: Observation) -> list[tuple[str, str]]:
    """Stable (key, value) assertion pairs for host-scoped observations."""
    if isinstance(observation, BannerObservation):
        return [
            (f"banner.{observation.port}", observation.banner.strip()),
            (f"banner_truncated.{observation.port}", str(observation.truncated).lower()),
        ]
    if isinstance(observation, TlsObservation):
        return [
            (f"tls.{observation.port}", f"version={observation.version}"),
            (
                f"tls_cert.{observation.port}",
                f"subject={observation.certificate_subject or 'none'}",
            ),
        ]
    if isinstance(observation, DnsObservation):
        return [
            (
                f"dns.{observation.record_type}.{observation.name}",
                observation.value,
            )
        ]
    if isinstance(observation, NetworkEvidenceObservation):
        return [(f"network_evidence.{observation.host}", observation.detail or "")]
    return []
