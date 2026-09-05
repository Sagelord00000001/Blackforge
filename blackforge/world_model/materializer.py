from pydantic import BaseModel, Field

from blackforge.core.types import (
    Confidence,
    EvidenceStatus,
    MissionID,
    SessionID,
)
from blackforge.world_model.models import (
    EntityMutationResult,
    EntityType,
    EvidenceLinkRef,
    RelationshipMutationResult,
    RelationshipSpec,
    RelationshipType,
)
from blackforge.world_model.rules import highest_status
from blackforge.world_model.store import WorldModelStore


class EntityFact(BaseModel):
    """Typed, schema-constrained entity materialization instruction.

    The materializer NEVER parses free text or guesses entity types; callers
    state the type explicitly. Evidence determines the epistemic floor.
    """

    entity_type: EntityType
    name: str
    namespace: str | None = None
    properties: dict = Field(default_factory=dict)
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[EvidenceLinkRef] = Field(default_factory=list)


class RelationshipFact(BaseModel):
    """Typed relationship materialization instruction."""

    relationship_type: RelationshipType
    source_entity_id: str
    target_entity_id: str
    note: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[EvidenceLinkRef] = Field(default_factory=list)


class WorldMaterializer:
    """Deterministic, evidence-driven materializer.

    Turns typed facts into world model records. Free-form LLM extraction and
    autonomous discovery are explicitly out of scope: the materializer only
    applies fixed rules (a status floor derived from linked evidence) and
    persists through :class:`WorldModelStore` semantics (dedup, corroboration,
    supersession, contradiction handling).
    """

    def __init__(self, store: WorldModelStore) -> None:
        self._store = store

    @property
    def store(self) -> WorldModelStore:
        return self._store

    def materialize_entity(
        self,
        mission_id: MissionID,
        fact: EntityFact,
        evidence_statuses: list[EvidenceStatus] | None = None,
        session_id: SessionID | None = None,
    ) -> EntityMutationResult:
        """Materialize an entity from a typed fact.

        The entity's epistemic status never exceeds the highest status of the
        supporting evidence (no-fake-authority): when no evidence status list is
        supplied the entity is recorded as ``HYPOTHESIZED`` regardless of any
        requested status, and the caller may then upgrade through the evidence
        workflow.
        """
        from blackforge.world_model.models import EntitySpec

        statuses = list(evidence_statuses or [])
        floor_status = highest_status(statuses) if statuses else EvidenceStatus.HYPOTHESIZED
        spec = EntitySpec(
            mission_id=mission_id,
            session_id=session_id,
            entity_type=fact.entity_type,
            name=fact.name,
            namespace=fact.namespace,
            properties=dict(fact.properties),
            epistemic_status=floor_status,
            confidence=fact.confidence,
            evidence=list(fact.evidence),
        )
        return self._store.add_entity(spec)

    def materialize_relationship(
        self,
        mission_id: MissionID,
        fact: RelationshipFact,
        session_id: SessionID | None = None,
    ) -> RelationshipMutationResult:
        """Materialize a relationship between two already-materialized entities.

        Endpoints must exist in the mission (resolved by ID); the store enforces
        mission isolation and active lifecycle.
        """
        spec = RelationshipSpec(
            mission_id=mission_id,
            session_id=session_id,
            relationship_type=fact.relationship_type,
            source_entity_id=fact.source_entity_id,
            target_entity_id=fact.target_entity_id,
            note=fact.note,
            confidence=fact.confidence,
            evidence=list(fact.evidence),
        )
        return self._store.add_relationship(spec)
