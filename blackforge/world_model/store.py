from __future__ import annotations

import time
from typing import Any

from blackforge.core.errors import WorldRuleError
from blackforge.core.logging import get_logger
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    MissionID,
    SessionID,
)
from blackforge.world_model.canonical import (
    build_entity_canonical_key,
    build_relationship_canonical_key,
    compute_assertion_dedup_key,
    compute_entity_dedup_key,
    compute_relationship_dedup_key,
    normalize_entity_name,
)
from blackforge.world_model.models import (
    AssertionMutationResult,
    AssertionSpec,
    EntityMutationResult,
    EntitySpec,
    EntityType,
    RelationshipMutationResult,
    RelationshipSpec,
    RelationshipType,
    WorldAssertion,
    WorldEntity,
    WorldLifecycle,
    WorldMutation,
    WorldRelationship,
)
from blackforge.world_model.query import NeighborhoodResult, RelationshipQuery, WorldQuery
from blackforge.world_model.repository import (
    InMemoryWorldRepository,
    WorldRepository,
    canonical_json,
)
from blackforge.world_model.rules import (
    can_supersede,
    status_requires_evidence,
    stronger_confidence,
)

log = get_logger("world_model.store")

_HC_MISSION = MissionID("health_check")
_HC_NAMESPACE = "__health_check__"


class WorldModelStore:
    """Application-facing world model facade.

    Owns the cross-record semantics on top of a persistence repository:

    * **Deterministic identity** — entities dedup on a canonical key scoped to
      ``(mission_id, entity_type, namespace, normalized_name)``; internal IDs
      are never the dedup basis.
    * **Corroboration** — identical content merges evidence and raises
      confidence/status only from new evidence.
    * **Supersession** — an OBSERVED/VALIDATED observation with different
      content supersedes the previous version; history is preserved.
    * **Contradictions** — a HYPOTHESIZED/INFERRED claim that conflicts with
      the authoritative record is stored as an assertion, never a silent
      overwrite.
    * **Evidence provenance** — property-level or row-level evidence links,
      with reverse lookups in both directions.

    Mission isolation is enforced at every entry point: all operations require
    ``mission_id`` (either explicitly or via the entity the operation is
    indexed by), and cross-mission reads are impossible by construction.
    """

    def __init__(self, repository: WorldRepository | None = None) -> None:
        self._repo: WorldRepository = repository or InMemoryWorldRepository()

    @property
    def repository(self) -> WorldRepository:
        return self._repo

    # ------------------------------------------------------------------ #
    # Entities
    # ------------------------------------------------------------------ #
    def add_entity(self, spec: EntitySpec) -> EntityMutationResult:
        """Create, corroborate, supersede, or record a contradiction."""
        normalized_name = self._normalize_name(spec.entity_type, spec.name)
        canonical_key = build_entity_canonical_key(
            spec.entity_type, normalized_name, spec.namespace
        )
        dedup_key = compute_entity_dedup_key(spec.mission_id, canonical_key)

        if status_requires_evidence(spec.epistemic_status) and not spec.evidence:
            raise WorldRuleError(
                f"{spec.epistemic_status.value} entities require supporting evidence: "
                f"{spec.entity_type.value} '{spec.name}'"
            )

        now = time.time()
        with self._repo.transaction():
            current = self._repo.find_entity_current(
                str(spec.mission_id), canonical_key
            )

            if current is None:
                entity = WorldEntity(
                    mission_id=spec.mission_id,
                    session_id=spec.session_id,
                    entity_type=spec.entity_type,
                    namespace=spec.namespace,
                    canonical_key=canonical_key,
                    dedup_key=dedup_key,
                    name=normalized_name,
                    properties=dict(spec.properties),
                    epistemic_status=spec.epistemic_status,
                    lifecycle=WorldLifecycle.ACTIVE,
                    confidence=spec.confidence,
                    version=1,
                    first_seen=now,
                    last_seen=now,
                    created_at=now,
                )
                self._repo.store_entity(entity)
                self._link_entity_evidence(entity, spec.evidence)
                log.info(
                    "world_entity_created",
                    entity_id=str(entity.id),
                    mission_id=str(spec.mission_id),
                    type=entity.entity_type.value,
                    canonical_key=canonical_key,
                )
                return EntityMutationResult(
                    action=WorldMutation.CREATED, entity=entity
                )

            if current.lifecycle in (WorldLifecycle.SUPERSEDED, WorldLifecycle.ARCHIVED):
                entity = self._spawn_next_version(current, spec, canonical_key, dedup_key, now)
                self._link_entity_evidence(entity, spec.evidence)
                return EntityMutationResult(
                    action=WorldMutation.CREATED, entity=entity, previous=current
                )

            same_content = canonical_json(current.properties) == canonical_json(
                spec.properties
            )
            if same_content:
                entity = self._corroborate_entity(
                    current, spec.evidence, spec.confidence, now
                )
                log.info(
                    "world_entity_corroborated",
                    entity_id=str(entity.id),
                    mission_id=str(spec.mission_id),
                )
                return EntityMutationResult(
                    action=WorldMutation.CORROBORATED, entity=entity
                )

            if can_supersede(spec.epistemic_status):
                entity = self._supersede_entity(current, spec, canonical_key, dedup_key, now)
                self._link_entity_evidence(entity, spec.evidence)
                log.info(
                    "world_entity_superseded",
                    entity_id=str(entity.id),
                    mission_id=str(spec.mission_id),
                    previous=str(current.id),
                )
                return EntityMutationResult(
                    action=WorldMutation.SUPERSEDED,
                    entity=entity,
                    previous=current,
                )

            assertion = self._record_contradiction_assertion(current, spec, now)
            log.info(
                "world_contradiction_recorded",
                entity_id=str(current.id),
                mission_id=str(spec.mission_id),
                assertion_id=str(assertion.id),
            )
            return EntityMutationResult(
                action=WorldMutation.CONTRADICTION_RECORDED,
                entity=current,
                previous=current,
                assertion=assertion,
            )

    def get_entity(self, entity_id: str) -> WorldEntity | None:
        return self._repo.retrieve_entity(entity_id)

    def find_entity(
        self,
        mission_id: MissionID,
        entity_type: EntityType,
        name: str,
        namespace: str | None = None,
    ) -> WorldEntity | None:
        """Resolve the current entity by its canonical identity."""
        normalized = self._normalize_name(entity_type, name)
        canonical_key = build_entity_canonical_key(entity_type, normalized, namespace)
        return self._repo.find_entity_current(str(mission_id), canonical_key)

    def list_entities(self, query: WorldQuery) -> list[WorldEntity]:
        return self._repo.list_entities(
            mission_id=str(query.mission_id),
            entity_type=query.entity_type,
            session_id=query.session_id,
            namespace=query.namespace,
            epistemic_status=query.epistemic_status,
            lifecycle=query.lifecycle,
            name_contains=query.name_contains,
            limit=query.limit,
            offset=query.offset,
        )

    def count_entities(
        self,
        mission_id: MissionID,
        entity_type: EntityType | None = None,
        session_id: SessionID | None = None,
        lifecycle: WorldLifecycle | None = None,
    ) -> int:
        return self._repo.count_entities(
            str(mission_id),
            entity_type=entity_type,
            session_id=session_id,
            lifecycle=lifecycle,
        )

    def archive_entity(self, entity_id: str) -> WorldEntity | None:
        """Soft-delete: lifecycle ACTIVE -> ARCHIVED. History is preserved."""
        entity = self._repo.retrieve_entity(entity_id)
        if entity is None or entity.lifecycle != WorldLifecycle.ACTIVE:
            return None
        updated = self._repo.update_entity(
            entity_id,
            {"lifecycle": WorldLifecycle.ARCHIVED, "updated_at": time.time()},
        )
        log.info("world_entity_archived", entity_id=str(entity_id))
        return updated

    # ------------------------------------------------------------------ #
    # Relationships
    # ------------------------------------------------------------------ #
    def add_relationship(self, spec: RelationshipSpec) -> RelationshipMutationResult:
        """Create or corroborate a typed, directional relationship.

        One logical relationship holds many evidence references; identity and
        support are distinct. Direction is deterministic per relationship type
        (symmetric types dedup order-insensitively).
        """
        source = self._require_active_entity(spec.mission_id, spec.source_entity_id)
        target = self._require_active_entity(spec.mission_id, spec.target_entity_id)
        if str(source.id) == str(target.id):
            raise WorldRuleError("self-loop relationships are not supported")

        pair = build_relationship_canonical_key(
            spec.relationship_type, source.canonical_key, target.canonical_key
        )
        dedup_key = compute_relationship_dedup_key(
            spec.mission_id, spec.relationship_type, pair
        )

        now = time.time()
        with self._repo.transaction():
            current = self._repo.find_relationship_current(
                str(spec.mission_id), dedup_key
            )
            if current is None:
                relationship = WorldRelationship(
                    mission_id=spec.mission_id,
                    session_id=spec.session_id,
                    relationship_type=spec.relationship_type,
                    source_entity_id=source.id,
                    target_entity_id=target.id,
                    dedup_key=dedup_key,
                    note=spec.note,
                    lifecycle=WorldLifecycle.ACTIVE,
                    confidence=spec.confidence,
                    first_seen=now,
                    last_seen=now,
                    created_at=now,
                )
                self._repo.store_relationship(relationship)
                self._link_relationship_evidence(relationship, spec.evidence)
                log.info(
                    "world_relationship_created",
                    relationship_id=str(relationship.id),
                    mission_id=str(spec.mission_id),
                    rel_type=relationship.relationship_type.value,
                    source=str(source.id),
                    target=str(target.id),
                )
                return RelationshipMutationResult(
                    action=WorldMutation.CREATED, relationship=relationship
                )

            updates: dict[str, Any] = {"last_seen": now, "updated_at": now}
            if current.note is None and spec.note:
                updates["note"] = spec.note
            confidence = stronger_confidence(current.confidence, spec.confidence)
            if confidence != current.confidence:
                updates["confidence"] = confidence
            updated = self._repo.update_relationship(
                str(current.id), updates
            ) or current
            self._link_relationship_evidence(updated, spec.evidence)
            log.info(
                "world_relationship_corroborated",
                relationship_id=str(updated.id),
                mission_id=str(spec.mission_id),
            )
            return RelationshipMutationResult(
                action=WorldMutation.CORROBORATED, relationship=updated
            )

    def get_relationship(self, relationship_id: str) -> WorldRelationship | None:
        return self._repo.retrieve_relationship(relationship_id)

    def list_relationships(self, query: RelationshipQuery) -> list[WorldRelationship]:
        return self._repo.list_relationships(
            mission_id=str(query.mission_id),
            relationship_type=query.relationship_type,
            source_entity_id=query.source_entity_id,
            target_entity_id=query.target_entity_id,
            lifecycle=query.lifecycle,
            limit=query.limit,
        )

    # ------------------------------------------------------------------ #
    # Assertions
    # ------------------------------------------------------------------ #
    def add_assertion(self, spec: AssertionSpec) -> AssertionMutationResult:
        """Record a property-level belief bound to an existing entity."""
        entity = self._require_active_entity(spec.mission_id, spec.entity_id)
        dedup_key = compute_assertion_dedup_key(
            spec.mission_id,
            str(entity.id),
            spec.property_key,
            spec.property_value,
            spec.epistemic_status,
        )
        now = time.time()
        with self._repo.transaction():
            existing = self._repo.find_assertion_by_dedup_key(
                str(spec.mission_id), dedup_key
            )
            if existing is not None:
                for evidence_id in _evidence_ids(spec.evidence):
                    self._repo.link_assertion_evidence(
                        str(existing.id), evidence_id
                    )
                self._repo.update_assertion(
                    str(existing.id),
                    {"updated_at": now, "lifecycle": WorldLifecycle.ACTIVE},
                )
                refetched = self._repo.retrieve_assertion(str(existing.id)) or existing
                return AssertionMutationResult(
                    action=WorldMutation.CORROBORATED, assertion=refetched
                )

            assertion = WorldAssertion(
                mission_id=spec.mission_id,
                session_id=spec.session_id,
                entity_id=entity.id,
                property_key=spec.property_key,
                property_value=spec.property_value,
                epistemic_status=spec.epistemic_status,
                lifecycle=WorldLifecycle.ACTIVE,
                confidence=spec.confidence,
                dedup_key=dedup_key,
                created_at=now,
            )
            self._repo.store_assertion(assertion)
            for evidence_id in _evidence_ids(spec.evidence):
                self._repo.link_assertion_evidence(str(assertion.id), evidence_id)
            log.info(
                "world_assertion_created",
                assertion_id=str(assertion.id),
                entity_id=str(entity.id),
                property_key=spec.property_key,
            )
            return AssertionMutationResult(
                action=WorldMutation.CREATED, assertion=assertion
            )

    def list_assertions(
        self, entity_id: str, lifecycle: WorldLifecycle | None = None
    ) -> list[WorldAssertion]:
        return self._repo.list_assertions(entity_id, lifecycle=lifecycle)

    # ------------------------------------------------------------------ #
    # Evidence provenance
    # ------------------------------------------------------------------ #
    def evidence_for_entity(self, entity_id: str) -> list[dict[str, Any]]:
        return self._repo.evidence_for_entity(entity_id)

    def entities_for_evidence(self, evidence_id: str) -> list[str]:
        return self._repo.entities_for_evidence(evidence_id)

    def evidence_for_relationship(self, relationship_id: str) -> list[dict[str, Any]]:
        return self._repo.evidence_for_relationship(relationship_id)

    def evidence_for_assertion(self, assertion_id: str) -> list[dict[str, Any]]:
        return self._repo.evidence_for_assertion(assertion_id)

    # ------------------------------------------------------------------ #
    # Neighborhood query (bounded, deterministic — no pathfinding)
    # ------------------------------------------------------------------ #
    def neighborhood(
        self,
        entity_id: str,
        direction: str = "both",
        max_depth: int = 1,
        relationship_types: list[RelationshipType] | None = None,
        limit: int = 100,
    ) -> NeighborhoodResult | None:
        """Return the bounded neighborhood around an entity.

        Offensive pathfinding is explicitly out of scope. Depth is capped at 2
        and results are sorted deterministically by
        ``(relationship_type, canonical_key, id)``.
        """
        entity = self._repo.retrieve_entity(entity_id)
        if entity is None:
            return None
        depth = max(1, min(int(max_depth), 2))

        relation_types = set(relationship_types or [])
        visited: set[str] = {str(entity.id)}
        frontier: list[str] = [str(entity.id)]
        levels: dict[str, int] = {str(entity.id): 0}
        entities: dict[str, WorldEntity] = {}
        relationships: dict[str, WorldRelationship] = {}

        for _ in range(depth):
            next_frontier: list[str] = []
            for current in frontier:
                for relationship in self._repo.list_relationships(
                    mission_id=str(entity.mission_id),
                    limit=1000,
                ):
                    rel_id = str(relationship.id)
                    if relationship_types and relationship.relationship_type not in relation_types:
                        continue
                    symmetric = relationship.relationship_type in {
                        RelationshipType.CONNECTS_TO,
                        RelationshipType.ASSOCIATED_WITH,
                    }
                    out = str(relationship.source_entity_id) == current
                    incoming = str(relationship.target_entity_id) == current
                    if not (symmetric and (out or incoming)):
                        if direction in ("out", "both") and not out:
                            continue
                        if direction in ("in", "both") and not incoming:
                            continue
                    neighbor_id = (
                        str(relationship.target_entity_id)
                        if out
                        else str(relationship.source_entity_id)
                    )
                    neighbor = self._repo.retrieve_entity(neighbor_id)
                    if neighbor is None:
                        continue
                    levels[neighbor_id] = levels[current] + 1
                    entities[neighbor_id] = neighbor
                    relationships[rel_id] = relationship
                    if neighbor_id not in visited:
                        visited.add(neighbor_id)
                        next_frontier.append(neighbor_id)
            frontier = next_frontier
            if not frontier:
                break

        ordered_rels = sorted(
            relationships.values(),
            key=lambda r: (
                r.relationship_type.value,
                str(r.id),
            ),
        )[:limit]
        ordered_entities = sorted(
            entities.values(),
            key=lambda e: (e.canonical_key, str(e.id)),
        )
        return NeighborhoodResult(
            entity=entity,
            depth=max(levels.values()) if levels else 0,
            entities=ordered_entities,
            relationships=ordered_rels,
        )

    # ------------------------------------------------------------------ #
    # Health / lifecycle
    # ------------------------------------------------------------------ #
    def health_check(self) -> bool:
        """Self-contained health probe: schema, write/read, relationship and
        evidence-linkage capability, then self-cleanup. No network access."""
        try:
            if not self._repo.schema_ready():
                return False
            now = time.time()
            with self._repo.transaction():
                a = WorldEntity(
                    mission_id=_HC_MISSION,
                    entity_type=EntityType.ASSET,
                    namespace=_HC_NAMESPACE,
                    canonical_key=f"{EntityType.ASSET.value}|{_HC_NAMESPACE}|__hc_a__",
                    dedup_key="hc_a",
                    name="__hc_a__",
                    epistemic_status=EvidenceStatus.INFERRED,
                    lifecycle=WorldLifecycle.ACTIVE,
                    confidence=Confidence.LOW,
                    created_at=now,
                    first_seen=now,
                    last_seen=now,
                )
                b = WorldEntity(
                    mission_id=_HC_MISSION,
                    entity_type=EntityType.ASSET,
                    namespace=_HC_NAMESPACE,
                    canonical_key=f"{EntityType.ASSET.value}|{_HC_NAMESPACE}|__hc_b__",
                    dedup_key="hc_b",
                    name="__hc_b__",
                    epistemic_status=EvidenceStatus.INFERRED,
                    lifecycle=WorldLifecycle.ACTIVE,
                    confidence=Confidence.LOW,
                    created_at=now,
                    first_seen=now,
                    last_seen=now,
                )
                self._repo.store_entity(a)
                self._repo.store_entity(b)
                if self._repo.retrieve_entity(str(a.id)) is None:
                    return False
                rel = WorldRelationship(
                    mission_id=_HC_MISSION,
                    relationship_type=RelationshipType.ASSOCIATED_WITH,
                    source_entity_id=a.id,
                    target_entity_id=b.id,
                    dedup_key="hc_rel",
                    lifecycle=WorldLifecycle.ACTIVE,
                    confidence=Confidence.LOW,
                    created_at=now,
                    first_seen=now,
                    last_seen=now,
                )
                self._repo.store_relationship(rel)
                if self._repo.retrieve_relationship(str(rel.id)) is None:
                    return False
                self._repo.link_entity_evidence(str(a.id), EvidenceID("hc_ev"))
                self._repo.link_relationship_evidence(str(rel.id), EvidenceID("hc_ev"))
                if self._repo.entities_for_evidence("hc_ev") == []:
                    return False
                self._repo.delete_relationship(str(rel.id))
                self._repo.delete_entity(str(a.id))
                self._repo.delete_entity(str(b.id))
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._repo.close()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _normalize_name(self, entity_type: EntityType, name: str) -> str:
        try:
            return normalize_entity_name(entity_type, name)
        except (ValueError, TypeError) as exc:
            raise WorldRuleError(
                f"cannot canonicalize {entity_type.value} name: {name!r}"
            ) from exc

    def _link_entity_evidence(self, entity: WorldEntity, evidence: list) -> None:
        for ref in evidence:
            self._repo.link_entity_evidence(
                str(entity.id),
                ref.evidence_id,
                ref.property_key,
                ref.property_value,
            )

    def _link_relationship_evidence(
        self, relationship: WorldRelationship, evidence: list
    ) -> None:
        for ref in evidence:
            self._repo.link_relationship_evidence(
                str(relationship.id), ref.evidence_id, ref.note
            )

    def _corroborate_entity(
        self, entity: WorldEntity, evidence: list, incoming_confidence: Confidence, now: float
    ) -> WorldEntity:
        for ref in evidence:
            self._link_entity_evidence(entity, [ref])
        confidence = stronger_confidence(entity.confidence, incoming_confidence)
        updates: dict[str, Any] = {"last_seen": now, "updated_at": now}
        if confidence != entity.confidence:
            updates["confidence"] = confidence
        updated = self._repo.update_entity(str(entity.id), updates)
        return updated or entity

    def _supersede_entity(
        self,
        current: WorldEntity,
        spec: EntitySpec,
        canonical_key: str,
        dedup_key: str,
        now: float,
    ) -> WorldEntity:
        self._repo.update_entity(
            str(current.id),
            {
                "lifecycle": WorldLifecycle.SUPERSEDED,
                "updated_at": now,
            },
        )
        return self._spawn_next_version(current, spec, canonical_key, dedup_key, now)

    def _spawn_next_version(
        self,
        current: WorldEntity,
        spec: EntitySpec,
        canonical_key: str,
        dedup_key: str,
        now: float,
    ) -> WorldEntity:
        entity = WorldEntity(
            mission_id=spec.mission_id,
            session_id=spec.session_id or current.session_id,
            entity_type=spec.entity_type,
            namespace=spec.namespace or current.namespace,
            canonical_key=canonical_key,
            dedup_key=dedup_key,
            name=canonical_key.rsplit("|", 1)[-1],
            properties=dict(spec.properties),
            epistemic_status=spec.epistemic_status,
            lifecycle=WorldLifecycle.ACTIVE,
            confidence=spec.confidence,
            version=current.version + 1,
            supersedes=current.id,
            first_seen=now,
            last_seen=now,
            created_at=now,
        )
        self._repo.store_entity(entity)
        return entity

    def _record_contradiction_assertion(
        self, entity: WorldEntity, spec: EntitySpec, now: float
    ) -> WorldAssertion:
        conflicting = _first_conflicting_property(entity.properties, spec.properties)
        key = conflicting or next(iter(spec.properties), "property")
        value = spec.properties.get(key)
        dedup_key = compute_assertion_dedup_key(
            spec.mission_id,
            str(entity.id),
            key,
            str(value) if value is not None else None,
            spec.epistemic_status,
        )
        assertion = WorldAssertion(
            mission_id=spec.mission_id,
            session_id=spec.session_id,
            entity_id=entity.id,
            property_key=key,
            property_value=str(value) if value is not None else None,
            epistemic_status=spec.epistemic_status,
            lifecycle=WorldLifecycle.ACTIVE,
            confidence=spec.confidence,
            dedup_key=dedup_key,
            created_at=now,
        )
        self._repo.store_assertion(assertion)
        for evidence_id in _evidence_ids(spec.evidence):
            self._repo.link_assertion_evidence(str(assertion.id), evidence_id)
        return assertion

    def _require_active_entity(self, mission_id: MissionID, entity_id: str) -> WorldEntity:
        entity = self._repo.retrieve_entity(str(entity_id))
        if entity is None:
            raise WorldRuleError(
                f"relationship endpoint does not exist: {entity_id}"
            )
        if str(entity.mission_id) != str(mission_id):
            raise WorldRuleError(
                f"relationship endpoint {entity_id} belongs to "
                f"mission {entity.mission_id}, not {mission_id}"
            )
        if entity.lifecycle != WorldLifecycle.ACTIVE:
            raise WorldRuleError(
                f"relationship endpoint is not active: {entity_id} "
                f"(lifecycle={entity.lifecycle.value})"
            )
        return entity


def _evidence_ids(evidence: list) -> list[str]:
    return [str(item.evidence_id) for item in evidence]


def _first_conflicting_property(existing: dict, incoming: dict) -> str | None:
    for key, value in incoming.items():
        if existing.get(key) != value:
            return key
    return None
