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
from blackforge.webapi.models import (
    ApiObservation,
    EndpointObservation,
    Observation,
    WebApplicationObservation,
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


class WebMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class WebMaterializeReport(BaseModel):
    entries: list[WebMaterializeEntry] = Field(default_factory=list)
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


class WebWorldMaterializer:
    """Maps typed web/api observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text:

    * APPLICATION -> APPLICATION (name = host, URL and tech in properties)
    * ENDPOINT -> ENDPOINT (name = URL) + ``APPLICATION CONTAINS ENDPOINT``
    * API -> API (name = URL) + ``APPLICATION CONTAINS API``
    * security_header / cookie / cors / auth_surface / openapi / graphql ->
      property-level ASSERTIONS bound to the host's APPLICATION entity
    * request_response -> ASSERTIONS bound to the observed ENDPOINT entity

    Analysis observations become assertions instead of entity properties so a
    re-run never churns entity versions; entities only change when the direct
    surface observations change (deterministic mock -> stable -> corroborate).
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
    ) -> WebMaterializeReport:
        report = WebMaterializeReport()
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
        report: WebMaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        if observation.kind in {
            "security_header", "cookie", "cors", "auth_surface", "openapi", "graphql"
        }:
            self._assert_on_application(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif observation.kind == "request_response":
            self._assert_on_endpoint(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, WebApplicationObservation):
            self._materialize_application(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, EndpointObservation):
            self._materialize_endpoint(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, ApiObservation):
            self._materialize_api(
                mission_id, observation, evidence_id, confidence, report, session_id
            )

    # ------------------------------------------------------------------
    def _materialize_application(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.APPLICATION,
                name=obs.host,
                properties={
                    "url": obs.url,
                    "title": obs.title,
                    "technologies": list(obs.technologies),
                    "scheme": obs.scheme,
                    "tls_version": obs.tls_version,
                    "source": "webapi.application_discovery",
                },
                confidence=confidence,
                evidence=[
                    _ref(evidence_id, property_key="url", property_value=obs.url)
                ],
            ),
            session_id,
        )
        self._record(report, "application", entity, action)

    def _materialize_endpoint(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        endpoint, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ENDPOINT,
                name=obs.url,
                properties={
                    "method": obs.method,
                    "status_code": obs.status_code,
                    "content_type": obs.content_type,
                    "title": obs.title,
                    "scheme": obs.scheme,
                    "tls_version": obs.tls_version,
                    "http_version": obs.http_version,
                },
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="url", property_value=obs.url)],
            ),
            session_id,
        )
        application = self._ensure_application(
            mission_id, obs.host, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.CONTAINS,
                source_entity_id=str(application.id),
                target_entity_id=str(endpoint.id),
                note="web application endpoint",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        self._record(report, "endpoint", endpoint, action)

    def _materialize_api(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        api, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.API,
                name=obs.url,
                properties={
                    "style": obs.style,
                    "kind": obs.kind_label,
                    "docs_url": obs.docs_url,
                    "source": "webapi.api_surface_discovery",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="url", property_value=obs.url)],
            ),
            session_id,
        )
        application = self._ensure_application(
            mission_id, obs.host, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.CONTAINS,
                source_entity_id=str(application.id),
                target_entity_id=str(api.id),
                note="api surface",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        self._record(report, "api", api, action)

    def _assert_on_application(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        application = self._ensure_application(
            mission_id, obs.host, evidence_id, confidence, session_id
        )
        for key, value in _assertion_pairs(obs):
            self._add_assertion(
                mission_id,
                application.id,
                key,
                value,
                obs,
                evidence_id,
                confidence,
                report,
                session_id,
            )

    def _assert_on_endpoint(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        endpoint, _ = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ENDPOINT,
                name=obs.url,
                properties={},
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key="url", property_value=obs.url)],
            ),
            session_id,
        )
        application = self._ensure_application(
            mission_id, obs.host, evidence_id, confidence, session_id
        )
        for key, value in _assertion_pairs(obs):
            self._add_assertion(
                mission_id,
                endpoint.id,
                key,
                value,
                obs,
                evidence_id,
                confidence,
                report,
                session_id,
            )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.CONTAINS,
                source_entity_id=str(application.id),
                target_entity_id=str(endpoint.id),
                note="observed web endpoint",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _ensure_application(
        self,
        mission_id: MissionID,
        host: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        existing = self._store.find_entity(mission_id, EntityType.APPLICATION, host)
        if existing is not None:
            return existing
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.APPLICATION,
                name=host,
                properties={"host": host, "source": "webapi"},
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

    def _add_assertion(
        self,
        mission_id: MissionID,
        entity_id,
        key: str,
        value: str,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: WebMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        result = self._store.add_assertion(
            AssertionSpec(
                mission_id=mission_id,
                session_id=session_id,
                entity_id=entity_id,
                property_key=key,
                property_value=value,
                epistemic_status=EvidenceStatus.VALIDATED
                if observation.kind
                in {"endpoint", "application", "request_response"}
                else EvidenceStatus.OBSERVED,
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            )
        )
        if result.action.value == "created":
            report.assertions_created += 1
        else:
            report.assertions_corroborated += 1

    def _link_report(
        self,
        mission_id: MissionID,
        fact: RelationshipFact,
        report: WebMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        result = self._materializer.materialize_relationship(mission_id, fact, session_id)
        if result.action.value == "created":
            report.relationships_created += 1
        else:
            report.relationships_corroborated += 1

    @staticmethod
    def _record(
        report: WebMaterializeReport,
        entity_type: str,
        entity: WorldEntity,
        action: str,
    ) -> None:
        report.entries.append(
            WebMaterializeEntry(
                entity_type=entity_type,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )


def _assertion_pairs(observation: Observation) -> list[tuple[str, str]]:
    """Stable property_key/property_value pairs for a web analysis observation."""
    if observation.kind == "security_header":
        value = observation.value if observation.present else observation.finding
        return [(f"security_header.{observation.header_name}", value)]
    if observation.kind == "cookie":
        return [
            (f"cookie.{observation.name}", _cookie_flags_summary(observation))
        ]
    if observation.kind == "cors":
        return [
            (
                "cors",
                (
                    f"origins={','.join(observation.allow_origins) or 'none'} "
                    f"credentials={str(observation.allow_credentials).lower()} "
                    f"wildcard={str(observation.wildcard_origin).lower()}"
                ),
            )
        ]
    if observation.kind == "auth_surface":
        label = observation.scheme_type or "observed"
        return [(f"auth_scheme.{observation.scheme}", label)]
    if observation.kind == "openapi":
        return [
            (
                "openapi_spec",
                (
                    f"v={observation.spec_version or 'unknown'} "
                    f"operations={observation.operation_count} "
                    f"schemes={','.join(observation.security_schemes) or 'none'}"
                ),
            )
        ]
    if observation.kind == "graphql":
        return [
            (
                "graphql",
                (
                    f"introspection={str(observation.introspection_enabled).lower()} "
                    f"types={observation.type_count} queries={observation.query_count}"
                ),
            )
        ]
    if observation.kind == "request_response":
        pairs: list[tuple[str, str]] = [("http_status", str(observation.status_code))]
        if observation.server_header:
            pairs.append(("server_header", observation.server_header))
        if observation.content_type:
            pairs.append(("content_type", observation.content_type))
        if observation.tls_version:
            pairs.append(("tls_version", observation.tls_version))
        return pairs
    return []


def _cookie_flags_summary(observation) -> str:
    flags = sorted(observation.flags)
    if observation.samesite and f"SameSite={observation.samesite}" not in flags:
        flags.append(f"SameSite={observation.samesite}")
    return "; ".join(flags) or "present"
