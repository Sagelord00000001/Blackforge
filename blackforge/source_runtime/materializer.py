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
from blackforge.source_runtime.models import CorrelationOutcome, CorrelationResult
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


def _ref(evidence_id: EvidenceID, **properties: str | None) -> EvidenceLinkRef:
    return EvidenceLinkRef(
        evidence_id=evidence_id,
        property_key=properties.get("property_key"),
        property_value=properties.get("property_value"),
    )


class SourceRuntimeMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class SourceRuntimeMaterializeReport(BaseModel):
    entries: list[SourceRuntimeMaterializeEntry] = Field(default_factory=list)
    relationships_created: int = 0
    relationships_corroborated: int = 0
    assertions_created: int = 0
    assertions_corroborated: int = 0
    contradictions_recorded: int = 0

    @property
    def entities_created(self) -> int:
        return sum(1 for e in self.entries if e.action == "created")

    @property
    def entities_updated(self) -> int:
        return len(self.entries) - self.entities_created


class SourceRuntimeWorldMaterializer:
    """Maps correlation outcomes into safe world model records.

    A correlation outcome materializes as a single ``SOURCE_COMPONENT`` entity
    carrying the correlation result (MATCH / DISCREPANCY / UNKNOWN /
    CONTRADICTION / NOT_COMPARABLE) as an assertion, plus a typed relationship
    between the correlated entity and itself is intentionally omitted — instead
    the outcome records ``DECLARED_AS`` / ``OBSERVED_AS`` / ``CORRESPONDS_TO`` /
    ``DIFFERS_FROM`` edges to a *pair* of entities: one representing the
    declared source side and one the observed runtime side.

    Only descriptive edges are produced. No offensive semantics (EXPLOITS,
    CAN_COMPROMISE, LEADS_TO, ENABLES, PRIVILEGE_ESCALATION_PATH) are ever
    created here.
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
        outcomes: list[tuple[CorrelationOutcome, EvidenceID, Confidence]],
        *,
        session_id: SessionID | None = None,
    ) -> SourceRuntimeMaterializeReport:
        report = SourceRuntimeMaterializeReport()
        for outcome, evidence_id, confidence in outcomes:
            self._materialize_one(
                mission_id, outcome, evidence_id, confidence, report, session_id
            )
        return report

    def _materialize_one(
        self,
        mission_id: MissionID,
        outcome: CorrelationOutcome,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: SourceRuntimeMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        # A single SOURCE_COMPONENT entity per correlated identity (the pair of
        # declared/observed states is recorded as relationship edges below).
        entity = self._store.find_entity(
            mission_id,
            EntityType.SOURCE_COMPONENT,
            outcome.identity.identity,
            namespace=None,
        )
        action = "created" if entity is None else "updated"
        if entity is None:
            created = self._upsert_entity(
                mission_id,
                EntityFact(
                    entity_type=EntityType.SOURCE_COMPONENT,
                    name=outcome.identity.identity,
                    properties={
                        "scope_kind": outcome.identity.scope_kind,
                        "correlation_result": outcome.result.value
                        if outcome.result
                        else CorrelationResult.UNKNOWN.value,
                        "capability_id": outcome.capability_id,
                        "source": "source_runtime",
                    },
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                session_id,
            )
            entity = created[0]
        report.entries.append(
            SourceRuntimeMaterializeEntry(
                entity_type=EntityType.SOURCE_COMPONENT.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )
        self._add_result_assertion(
            mission_id,
            session_id,
            entity,
            "correlation_result",
            outcome.result.value if outcome.result else CorrelationResult.UNKNOWN.value,
            confidence,
            evidence_id,
            report,
        )

        # Relationship edges: the source (declared) and runtime (observed)
        # states are represented as sibling entities capturing each side.
        source_entity, _ = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SOURCE_COMPONENT,
                name=f"{outcome.identity.identity}:source",
                properties={"correlation_side": "source"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        runtime_entity, _ = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SOURCE_COMPONENT,
                name=f"{outcome.identity.identity}:runtime",
                properties={"correlation_side": "runtime"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )

        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.DECLARED_AS,
                source_entity_id=str(entity.id),
                target_entity_id=str(source_entity.id),
                note="declared (source) state of the correlated identity",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.OBSERVED_AS,
                source_entity_id=str(entity.id),
                target_entity_id=str(runtime_entity.id),
                note="observed (runtime) state of the correlated identity",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        # The correlation edge between the two sides.
        edge_type = (
            RelationshipType.CORRESPONDS_TO
            if outcome.result == CorrelationResult.MATCH
            else RelationshipType.DIFFERS_FROM
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=edge_type,
                source_entity_id=str(source_entity.id),
                target_entity_id=str(runtime_entity.id),
                note=(
                    "source and runtime states correlate exactly"
                    if edge_type == RelationshipType.CORRESPONDS_TO
                    else f"source and runtime states differ ({outcome.result.value})"
                ),
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    def _add_result_assertion(
        self,
        mission_id: MissionID,
        session_id: SessionID | None,
        entity: WorldEntity,
        key: str,
        value: str,
        confidence: Confidence,
        evidence_id: EvidenceID,
        report: SourceRuntimeMaterializeReport,
    ) -> None:
        existing = self._store.list_assertions(str(entity.id))
        conflicts = [
            a
            for a in existing
            if a.property_key == key and a.property_value != value
        ]
        result = self._store.add_assertion(
            AssertionSpec(
                mission_id=mission_id,
                session_id=session_id,
                entity_id=entity.id,
                property_key=key,
                property_value=value,
                epistemic_status=EvidenceStatus.INFERRED,
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key=key, property_value=value)],
            )
        )
        if result.action.value == "created":
            if conflicts:
                report.contradictions_recorded += 1
            else:
                report.assertions_created += 1
        else:
            report.assertions_corroborated += 1

    def _link_report(
        self,
        mission_id: MissionID,
        fact: RelationshipFact,
        report: SourceRuntimeMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        result = self._materializer.materialize_relationship(
            mission_id, fact, session_id
        )
        if result.action.value == "created":
            report.relationships_created += 1
        else:
            report.relationships_corroborated += 1

    def _upsert_entity(
        self,
        mission_id: MissionID,
        fact: EntityFact,
        session_id: SessionID | None,
    ) -> tuple[WorldEntity, str]:
        result = self._materializer.materialize_entity(
            mission_id, fact, [EvidenceStatus.OBSERVED], session_id
        )
        return result.entity, result.action.value


__all__ = [
    "SourceRuntimeMaterializeEntry",
    "SourceRuntimeMaterializeReport",
    "SourceRuntimeWorldMaterializer",
]
