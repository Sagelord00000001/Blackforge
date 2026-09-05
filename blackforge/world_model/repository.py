from __future__ import annotations

import json
import sqlite3
import threading
from abc import abstractmethod
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

from blackforge.core.logging import get_logger
from blackforge.core.types import (
    Confidence,
    EvidenceStatus,
    MissionID,
    SessionID,
    WorldAssertionID,
    WorldEntityID,
    WorldRelationshipID,
)
from blackforge.world_model.models import (
    EntityType,
    RelationshipType,
    WorldAssertion,
    WorldEntity,
    WorldLifecycle,
    WorldRelationship,
)

log = get_logger("world_model.repository")


def canonical_json(obj: Any) -> str:
    """Stable JSON serialization so equal-but-reordered structures compare equal."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def decode_json(raw: str | None, fallback: Any = None) -> Any:
    """Materialize stored JSON, falling back to raw text on parse failure."""
    if raw is None:
        return fallback
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def _confidence_to_score(confidence: Confidence) -> float:
    return confidence.to_score()


def _score_to_confidence(score: float) -> Confidence:
    return Confidence.from_score(float(score))


def _entity_from_row(row: sqlite3.Row) -> WorldEntity:
    return WorldEntity(
        id=WorldEntityID(row["id"]),
        mission_id=MissionID(row["mission_id"]),
        session_id=SessionID(row["session_id"]) if row["session_id"] else None,
        entity_type=EntityType(row["entity_type"]),
        namespace=row["namespace"],
        canonical_key=row["canonical_key"],
        dedup_key=row["dedup_key"],
        name=row["name"],
        properties=decode_json(row["properties"], {}),
        epistemic_status=EvidenceStatus(row["epistemic_status"]),
        lifecycle=WorldLifecycle(row["lifecycle"]),
        confidence=_score_to_confidence(row["confidence"]),
        version=int(row["version"]),
        supersedes=(
            WorldEntityID(row["supersedes"]) if row["supersedes"] else None
        ),
        first_seen=float(row["first_seen"]),
        last_seen=float(row["last_seen"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]) if row["updated_at"] else None,
    )


def _relationship_from_row(row: sqlite3.Row) -> WorldRelationship:
    return WorldRelationship(
        id=WorldRelationshipID(row["id"]),
        mission_id=MissionID(row["mission_id"]),
        session_id=SessionID(row["session_id"]) if row["session_id"] else None,
        relationship_type=RelationshipType(row["relationship_type"]),
        source_entity_id=WorldEntityID(row["source_entity_id"]),
        target_entity_id=WorldEntityID(row["target_entity_id"]),
        dedup_key=row["dedup_key"],
        note=row["note"],
        lifecycle=WorldLifecycle(row["lifecycle"]),
        confidence=_score_to_confidence(row["confidence"]),
        first_seen=float(row["first_seen"]),
        last_seen=float(row["last_seen"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]) if row["updated_at"] else None,
    )


def _assertion_from_row(row: sqlite3.Row) -> WorldAssertion:
    return WorldAssertion(
        id=WorldAssertionID(row["id"]),
        mission_id=MissionID(row["mission_id"]),
        session_id=SessionID(row["session_id"]) if row["session_id"] else None,
        entity_id=WorldEntityID(row["entity_id"]),
        property_key=row["property_key"],
        property_value=row["property_value"],
        epistemic_status=EvidenceStatus(row["epistemic_status"]),
        lifecycle=WorldLifecycle(row["lifecycle"]),
        confidence=_score_to_confidence(row["confidence"]),
        dedup_key=row["dedup_key"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]) if row["updated_at"] else None,
    )


class WorldRepository:
    """Persistence interface for the world model.

    All stored content is treated as untrusted; only parameterized SQL is
    used. Repositories guarantee each logical identity is unique
    (``(mission_id, canonical_key, version)`` for entities,
    ``(mission_id, dedup_key)`` for relationships) and that evidence links can
    be looked up in both directions.
    """

    @abstractmethod
    def schema_ready(self) -> bool:
        """Return whether the backing store is initialized and reachable."""

    @abstractmethod
    def store_entity(self, entity: WorldEntity) -> None:
        """Persist a new entity record."""

    @abstractmethod
    def update_entity(self, entity_id: str, updates: dict[str, Any]) -> WorldEntity | None:
        """Apply in-place updates to an entity record."""

    @abstractmethod
    def delete_entity(self, entity_id: str) -> None:
        """Hard-delete an entity (world-model layer only; used by health probes)."""

    @abstractmethod
    def retrieve_entity(self, entity_id: str) -> WorldEntity | None:
        """Return an entity by internal ID, or None."""

    @abstractmethod
    def find_entity_current(self, mission_id: str, canonical_key: str) -> WorldEntity | None:
        """Return the latest record for a canonical identity, if any."""

    @abstractmethod
    def list_entities(
        self,
        mission_id: str,
        entity_type: EntityType | None = None,
        session_id: SessionID | None = None,
        namespace: str | None = None,
        epistemic_status: EvidenceStatus | None = None,
        lifecycle: WorldLifecycle | None = None,
        name_contains: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[WorldEntity]:
        """Deterministically list entities within a mission."""

    @abstractmethod
    def count_entities(
        self,
        mission_id: str,
        entity_type: EntityType | None = None,
        session_id: SessionID | None = None,
        lifecycle: WorldLifecycle | None = None,
    ) -> int:
        """Count entities within a mission."""

    @abstractmethod
    def store_relationship(self, relationship: WorldRelationship) -> None:
        """Persist a new relationship record."""

    @abstractmethod
    def update_relationship(
        self, relationship_id: str, updates: dict[str, Any]
    ) -> WorldRelationship | None:
        """Apply in-place updates to a relationship record."""

    @abstractmethod
    def delete_relationship(self, relationship_id: str) -> None:
        """Hard-delete a relationship (world-model layer only; unused normally)."""

    @abstractmethod
    def retrieve_relationship(self, relationship_id: str) -> WorldRelationship | None:
        """Return a relationship by internal ID, or None."""

    @abstractmethod
    def find_relationship_current(
        self, mission_id: str, dedup_key: str
    ) -> WorldRelationship | None:
        """Return the active relationship for a canonical identity, if any."""

    @abstractmethod
    def list_relationships(
        self,
        mission_id: str,
        relationship_type: RelationshipType | None = None,
        source_entity_id: str | None = None,
        target_entity_id: str | None = None,
        lifecycle: WorldLifecycle | None = None,
        limit: int = 50,
    ) -> list[WorldRelationship]:
        """Deterministically list relationships within a mission."""

    @abstractmethod
    def store_assertion(self, assertion: WorldAssertion) -> None:
        """Persist a new assertion bound to an entity."""

    @abstractmethod
    def retrieve_assertion(self, assertion_id: str) -> WorldAssertion | None:
        """Return an assertion by internal ID, or None."""

    @abstractmethod
    def update_assertion(
        self, assertion_id: str, updates: dict[str, Any]
    ) -> WorldAssertion | None:
        """Apply in-place updates to an assertion."""

    @abstractmethod
    def find_assertion_by_dedup_key(
        self, mission_id: str, dedup_key: str
    ) -> WorldAssertion | None:
        """Return the current assertion for a canonical identity, if any."""

    @abstractmethod
    def list_assertions(
        self,
        entity_id: str,
        lifecycle: WorldLifecycle | None = None,
        limit: int = 50,
    ) -> list[WorldAssertion]:
        """List assertions bound to an entity."""

    @abstractmethod
    def link_entity_evidence(
        self,
        entity_id: str,
        evidence_id: str,
        property_key: str | None = None,
        property_value: str | None = None,
    ) -> None:
        """Attach an evidence reference (optionally property-scoped) to an entity."""

    @abstractmethod
    def evidence_for_entity(self, entity_id: str) -> list[dict[str, Any]]:
        """Return evidence references for an entity (with property scope)."""

    @abstractmethod
    def entities_for_evidence(self, evidence_id: str) -> list[str]:
        """Reverse lookup: entities supported by an evidence ID."""

    @abstractmethod
    def link_relationship_evidence(
        self,
        relationship_id: str,
        evidence_id: str,
        note: str | None = None,
    ) -> None:
        """Attach an evidence reference to a relationship."""

    @abstractmethod
    def evidence_for_relationship(self, relationship_id: str) -> list[dict[str, Any]]:
        """Return evidence references for a relationship."""

    @abstractmethod
    def link_assertion_evidence(self, assertion_id: str, evidence_id: str) -> None:
        """Attach an evidence reference to an assertion."""

    @abstractmethod
    def evidence_for_assertion(self, assertion_id: str) -> list[dict[str, Any]]:
        """Return evidence references for an assertion."""

    @abstractmethod
    def transaction(self) -> Iterator[None]:
        """Context manager providing an atomic unit of work."""

    @abstractmethod
    def health_check(self) -> bool:
        """Connection/storage-level health probe (does not touch model records)."""

    @abstractmethod
    def close(self) -> None:
        """Release resources."""


class InMemoryWorldRepository(WorldRepository):
    """Pure in-memory repository for tests and the in-memory configuration."""

    def __init__(self) -> None:
        self._entities: dict[str, WorldEntity] = {}
        self._relationships: dict[str, WorldRelationship] = {}
        self._assertions: dict[str, WorldAssertion] = {}
        self._entity_evidence: dict[str, list[dict[str, Any]]] = {}
        self._relationship_evidence: dict[str, list[dict[str, Any]]] = {}
        self._assertion_evidence: dict[str, list[dict[str, Any]]] = {}
        self._evidence_to_entities: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    def schema_ready(self) -> bool:
        return True

    def store_entity(self, entity: WorldEntity) -> None:
        with self._lock:
            self._entities[str(entity.id)] = entity.model_copy(deep=True)

    def update_entity(self, entity_id: str, updates: dict[str, Any]) -> WorldEntity | None:
        with self._lock:
            entity = self._entities.get(entity_id)
            if entity is None:
                return None
            for key, value in updates.items():
                setattr(entity, key, value)
            return entity.model_copy(deep=True)

    def delete_entity(self, entity_id: str) -> None:
        with self._lock:
            self._entities.pop(entity_id, None)

    def retrieve_entity(self, entity_id: str) -> WorldEntity | None:
        with self._lock:
            entity = self._entities.get(entity_id)
            return entity.model_copy(deep=True) if entity else None

    def find_entity_current(self, mission_id: str, canonical_key: str) -> WorldEntity | None:
        with self._lock:
            candidates = [
                e
                for e in self._entities.values()
                if e.mission_id == mission_id and e.canonical_key == canonical_key
            ]
            if not candidates:
                return None
            latest = sorted(candidates, key=lambda e: e.version)[-1]
            return latest.model_copy(deep=True)

    def _matches_entity_filters(
        self,
        entity: WorldEntity,
        mission_id: str,
        entity_type: EntityType | None,
        session_id: SessionID | None,
        namespace: str | None,
        epistemic_status: EvidenceStatus | None,
        lifecycle: WorldLifecycle | None,
        name_contains: str | None,
    ) -> bool:
        if str(entity.mission_id) != mission_id:
            return False
        if entity_type is not None and entity.entity_type != entity_type:
            return False
        if session_id is not None and entity.session_id != session_id:
            return False
        if namespace is not None and entity.namespace != namespace:
            return False
        if epistemic_status is not None and entity.epistemic_status != epistemic_status:
            return False
        if lifecycle is not None and entity.lifecycle != lifecycle:
            return False
        return not (
            name_contains is not None and name_contains not in entity.name
        )

    def list_entities(
        self,
        mission_id: str,
        entity_type: EntityType | None = None,
        session_id: SessionID | None = None,
        namespace: str | None = None,
        epistemic_status: EvidenceStatus | None = None,
        lifecycle: WorldLifecycle | None = None,
        name_contains: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[WorldEntity]:
        with self._lock:
            matched = [
                e
                for e in self._entities.values()
                if self._matches_entity_filters(
                    e,
                    mission_id,
                    entity_type,
                    session_id,
                    namespace,
                    epistemic_status,
                    lifecycle,
                    name_contains,
                )
            ]
            matched.sort(key=lambda e: (e.canonical_key, str(e.id)))
            return [e.model_copy(deep=True) for e in matched[offset : offset + limit]]

    def count_entities(
        self,
        mission_id: str,
        entity_type: EntityType | None = None,
        session_id: SessionID | None = None,
        lifecycle: WorldLifecycle | None = None,
    ) -> int:
        with self._lock:
            return len(
                [
                    e
                    for e in self._entities.values()
                    if self._matches_entity_filters(
                        e,
                        mission_id,
                        entity_type,
                        session_id,
                        None,
                        None,
                        lifecycle,
                        None,
                    )
                ]
            )

    def store_relationship(self, relationship: WorldRelationship) -> None:
        with self._lock:
            self._relationships[str(relationship.id)] = relationship.model_copy(deep=True)

    def update_relationship(
        self, relationship_id: str, updates: dict[str, Any]
    ) -> WorldRelationship | None:
        with self._lock:
            relationship = self._relationships.get(relationship_id)
            if relationship is None:
                return None
            for key, value in updates.items():
                setattr(relationship, key, value)
            return relationship.model_copy(deep=True)

    def delete_relationship(self, relationship_id: str) -> None:
        with self._lock:
            self._relationships.pop(relationship_id, None)

    def retrieve_relationship(self, relationship_id: str) -> WorldRelationship | None:
        with self._lock:
            relationship = self._relationships.get(relationship_id)
            return relationship.model_copy(deep=True) if relationship else None

    def find_relationship_current(
        self, mission_id: str, dedup_key: str
    ) -> WorldRelationship | None:
        with self._lock:
            for relationship in self._relationships.values():
                if (
                    str(relationship.mission_id) == mission_id
                    and relationship.dedup_key == dedup_key
                    and relationship.lifecycle == WorldLifecycle.ACTIVE
                ):
                    return relationship.model_copy(deep=True)
            return None

    def list_relationships(
        self,
        mission_id: str,
        relationship_type: RelationshipType | None = None,
        source_entity_id: str | None = None,
        target_entity_id: str | None = None,
        lifecycle: WorldLifecycle | None = None,
        limit: int = 50,
    ) -> list[WorldRelationship]:
        with self._lock:
            matched = []
            for relationship in self._relationships.values():
                if str(relationship.mission_id) != mission_id:
                    continue
                if (
                    relationship_type is not None
                    and relationship.relationship_type != relationship_type
                ):
                    continue
                if (
                    source_entity_id is not None
                    and str(relationship.source_entity_id) != source_entity_id
                ):
                    continue
                if (
                    target_entity_id is not None
                    and str(relationship.target_entity_id) != target_entity_id
                ):
                    continue
                if lifecycle is not None and relationship.lifecycle != lifecycle:
                    continue
                matched.append(relationship)
            matched.sort(
                key=lambda r: (
                    r.relationship_type.value,
                    str(r.source_entity_id),
                    str(r.target_entity_id),
                )
            )
            return [r.model_copy(deep=True) for r in matched[:limit]]

    def store_assertion(self, assertion: WorldAssertion) -> None:
        with self._lock:
            self._assertions[str(assertion.id)] = assertion.model_copy(deep=True)

    def retrieve_assertion(self, assertion_id: str) -> WorldAssertion | None:
        with self._lock:
            assertion = self._assertions.get(assertion_id)
            return assertion.model_copy(deep=True) if assertion else None

    def update_assertion(
        self, assertion_id: str, updates: dict[str, Any]
    ) -> WorldAssertion | None:
        with self._lock:
            assertion = self._assertions.get(assertion_id)
            if assertion is None:
                return None
            for key, value in updates.items():
                setattr(assertion, key, value)
            return assertion.model_copy(deep=True)

    def find_assertion_by_dedup_key(
        self, mission_id: str, dedup_key: str
    ) -> WorldAssertion | None:
        with self._lock:
            for assertion in self._assertions.values():
                if (
                    str(assertion.mission_id) == mission_id
                    and assertion.dedup_key == dedup_key
                    and assertion.lifecycle == WorldLifecycle.ACTIVE
                ):
                    return assertion.model_copy(deep=True)
            return None

    def list_assertions(
        self, entity_id: str, lifecycle: WorldLifecycle | None = None, limit: int = 50
    ) -> list[WorldAssertion]:
        with self._lock:
            matched = [
                a
                for a in self._assertions.values()
                if str(a.entity_id) == entity_id
                and (lifecycle is None or a.lifecycle == lifecycle)
            ]
            matched.sort(key=lambda a: a.created_at)
            return [a.model_copy(deep=True) for a in matched[:limit]]

    def link_entity_evidence(
        self,
        entity_id: str,
        evidence_id: str,
        property_key: str | None = None,
        property_value: str | None = None,
    ) -> None:
        with self._lock:
            ref = {
                "evidence_id": str(evidence_id),
                "property_key": property_key,
                "property_value": property_value,
            }
            existing = self._entity_evidence.setdefault(str(entity_id), [])
            for item in existing:
                if (
                    item["evidence_id"] == str(evidence_id)
                    and item["property_key"] == property_key
                    and item["property_value"] == property_value
                ):
                    return
            existing.append(ref)
            self._evidence_to_entities.setdefault(str(evidence_id), set()).add(str(entity_id))

    def evidence_for_entity(self, entity_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._entity_evidence.get(str(entity_id), []))

    def entities_for_evidence(self, evidence_id: str) -> list[str]:
        with self._lock:
            return sorted(self._evidence_to_entities.get(str(evidence_id), set()))

    def link_relationship_evidence(
        self, relationship_id: str, evidence_id: str, note: str | None = None
    ) -> None:
        with self._lock:
            ref = {
                "evidence_id": str(evidence_id),
                "note": note,
            }
            existing = self._relationship_evidence.setdefault(str(relationship_id), [])
            for item in existing:
                if item["evidence_id"] == str(evidence_id):
                    return
            existing.append(ref)

    def evidence_for_relationship(self, relationship_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._relationship_evidence.get(str(relationship_id), []))

    def link_assertion_evidence(self, assertion_id: str, evidence_id: str) -> None:
        with self._lock:
            refs = self._assertion_evidence.setdefault(str(assertion_id), [])
            if str(evidence_id) not in {r["evidence_id"] for r in refs}:
                refs.append({"evidence_id": str(evidence_id)})

    def evidence_for_assertion(self, assertion_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._assertion_evidence.get(str(assertion_id), []))

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def health_check(self) -> bool:
        return True

    def close(self) -> None:
        pass


_SCHEMA = """
CREATE TABLE IF NOT EXISTS world_entities (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    session_id TEXT,
    entity_type TEXT NOT NULL,
    namespace TEXT,
    canonical_key TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    name TEXT NOT NULL,
    properties TEXT NOT NULL DEFAULT '{}',
    epistemic_status TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    confidence REAL NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    supersedes TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS world_relationships (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    session_id TEXT,
    relationship_type TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    note TEXT,
    lifecycle TEXT NOT NULL,
    confidence REAL NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS world_assertions (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    session_id TEXT,
    entity_id TEXT NOT NULL,
    property_key TEXT NOT NULL,
    property_value TEXT,
    epistemic_status TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    confidence REAL NOT NULL,
    dedup_key TEXT,
    created_at REAL NOT NULL,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS world_entity_evidence (
    entity_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    property_key TEXT NOT NULL DEFAULT '',
    property_value TEXT,
    linked_at REAL NOT NULL,
    PRIMARY KEY (entity_id, evidence_id, property_key)
);

CREATE TABLE IF NOT EXISTS world_relationship_evidence (
    relationship_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    note TEXT,
    linked_at REAL NOT NULL,
    PRIMARY KEY (relationship_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS world_assertion_evidence (
    assertion_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    linked_at REAL NOT NULL,
    PRIMARY KEY (assertion_id, evidence_id)
);
"""

_INDEXES = [
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_we_identity "
    "ON world_entities(mission_id, canonical_key, version)",
    "CREATE INDEX IF NOT EXISTS idx_we_canonical ON world_entities(mission_id, canonical_key)",
    "CREATE INDEX IF NOT EXISTS idx_we_type ON world_entities(mission_id, entity_type)",
    "CREATE INDEX IF NOT EXISTS idx_we_session ON world_entities(mission_id, session_id)",
    "CREATE INDEX IF NOT EXISTS idx_we_lifecycle ON world_entities(lifecycle)",
    "CREATE INDEX IF NOT EXISTS idx_we_status ON world_entities(epistemic_status)",
    "CREATE INDEX IF NOT EXISTS idx_we_confidence ON world_entities(confidence)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_wr_identity "
    "ON world_relationships(mission_id, dedup_key)",
    "CREATE INDEX IF NOT EXISTS idx_wr_type ON world_relationships(mission_id, relationship_type)",
    "CREATE INDEX IF NOT EXISTS idx_wr_source ON world_relationships(source_entity_id)",
    "CREATE INDEX IF NOT EXISTS idx_wr_target ON world_relationships(target_entity_id)",
    "CREATE INDEX IF NOT EXISTS idx_wr_pair "
    "ON world_relationships(source_entity_id, target_entity_id)",
    "CREATE INDEX IF NOT EXISTS idx_wr_lifecycle ON world_relationships(lifecycle)",
    "CREATE INDEX IF NOT EXISTS idx_wa_entity ON world_assertions(entity_id)",
    "CREATE INDEX IF NOT EXISTS idx_wa_lifecycle ON world_assertions(lifecycle)",
    "CREATE INDEX IF NOT EXISTS idx_wa_status ON world_assertions(epistemic_status)",
    "CREATE INDEX IF NOT EXISTS idx_wee_evidence ON world_entity_evidence(evidence_id)",
    "CREATE INDEX IF NOT EXISTS idx_wre_evidence ON world_relationship_evidence(evidence_id)",
    "CREATE INDEX IF NOT EXISTS idx_wae_evidence ON world_assertion_evidence(evidence_id)",
]


class SQLiteWorldRepository(WorldRepository):
    """SQLite persistence for the world model.

    Mirrors the memory/evidence repository pattern: a single shared
    connection in autocommit mode with explicit ``BEGIN IMMEDIATE``
    transactions under a re-entrant lock. All SQL is parameterized.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        if db_path not in (":memory:", ""):
            import os

            parent = os.path.dirname(os.path.abspath(db_path))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.isolation_level = None
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._closed = False
        self._tx_depth = 0
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            for stmt in _INDEXES:
                self._conn.execute(stmt)

    @property
    def db_path(self) -> str:
        return self._db_path

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            if self._closed:
                raise RuntimeError("repository is closed")
            self._tx_depth += 1
            if self._tx_depth == 1:
                self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            with self._lock:
                self._tx_depth -= 1
                if self._tx_depth == 0:
                    self._conn.execute("ROLLBACK")
            raise
        else:
            with self._lock:
                self._tx_depth -= 1
                if self._tx_depth == 0:
                    self._conn.execute("COMMIT")

    def schema_ready(self) -> bool:
        try:
            with self._lock:
                tables = {
                    row["name"]
                    for row in self._conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                required = {
                    "world_entities",
                    "world_relationships",
                    "world_assertions",
                    "world_entity_evidence",
                    "world_relationship_evidence",
                    "world_assertion_evidence",
                }
                return required.issubset(tables) and not self._closed
        except sqlite3.Error:
            return False

    def _entity_updates_kv(self, updates: dict[str, Any]) -> dict[str, Any]:
        kv: dict[str, Any] = {}
        for key in (
            "session_id",
            "namespace",
            "properties",
            "epistemic_status",
            "lifecycle",
            "confidence",
            "version",
            "supersedes",
            "last_seen",
            "updated_at",
        ):
            if key not in updates:
                continue
            value = updates[key]
            if key == "properties":
                kv["properties"] = canonical_json(value)
            elif key == "confidence":
                kv["confidence"] = _confidence_to_score(value)
            elif key == "session_id":
                kv["session_id"] = str(value) if value else None
            elif key == "supersedes":
                kv["supersedes"] = str(value) if value else None
            else:
                kv[key] = value
        return kv

    def store_entity(self, entity: WorldEntity) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO world_entities (
                    id, mission_id, session_id, entity_type, namespace,
                    canonical_key, dedup_key, name, properties, epistemic_status,
                    lifecycle, confidence, version, supersedes, first_seen,
                    last_seen, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(entity.id),
                    str(entity.mission_id),
                    str(entity.session_id) if entity.session_id else None,
                    entity.entity_type.value,
                    entity.namespace,
                    entity.canonical_key,
                    entity.dedup_key,
                    entity.name,
                    canonical_json(entity.properties),
                    entity.epistemic_status.value,
                    entity.lifecycle.value,
                    _confidence_to_score(entity.confidence),
                    entity.version,
                    str(entity.supersedes) if entity.supersedes else None,
                    entity.first_seen,
                    entity.last_seen,
                    entity.created_at,
                    entity.updated_at,
                ),
            )

    def update_entity(self, entity_id: str, updates: dict[str, Any]) -> WorldEntity | None:
        if not updates:
            return self.retrieve_entity(entity_id)
        kv = self._entity_updates_kv(updates)
        with self._lock:
            self._conn.execute(
                f"UPDATE world_entities SET {', '.join(f'{k}=?' for k in kv)} WHERE id=?",
                (*kv.values(), str(entity_id)),
            )
            return self.retrieve_entity(entity_id)

    def delete_entity(self, entity_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM world_entity_evidence WHERE entity_id=?",
                (str(entity_id),),
            )
            self._conn.execute(
                "DELETE FROM world_entities WHERE id=?", (str(entity_id),)
            )

    def retrieve_entity(self, entity_id: str) -> WorldEntity | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM world_entities WHERE id=?", (str(entity_id),)
            ).fetchone()
            return _entity_from_row(row) if row else None

    def find_entity_current(self, mission_id: str, canonical_key: str) -> WorldEntity | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM world_entities
                WHERE mission_id=? AND canonical_key=?
                ORDER BY version DESC LIMIT 1
                """,
                (str(mission_id), canonical_key),
            ).fetchone()
            return _entity_from_row(row) if row else None

    def _build_entity_filters(
        self,
        mission_id: str,
        entity_type: EntityType | None,
        session_id: SessionID | None,
        namespace: str | None,
        epistemic_status: EvidenceStatus | None,
        lifecycle: WorldLifecycle | None,
        name_contains: str | None,
    ) -> tuple[str, list[Any]]:
        clauses = ["mission_id = ?"]
        params: list[Any] = [str(mission_id)]
        if entity_type is not None:
            clauses.append("entity_type = ?")
            params.append(entity_type.value)
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(str(session_id))
        if namespace is not None:
            clauses.append("namespace = ?")
            params.append(namespace)
        if epistemic_status is not None:
            clauses.append("epistemic_status = ?")
            params.append(epistemic_status.value)
        if lifecycle is not None:
            clauses.append("lifecycle = ?")
            params.append(lifecycle.value)
        if name_contains is not None:
            clauses.append("name LIKE ?")
            params.append(f"%{name_contains}%")
        return " AND ".join(clauses), params

    def list_entities(
        self,
        mission_id: str,
        entity_type: EntityType | None = None,
        session_id: SessionID | None = None,
        namespace: str | None = None,
        epistemic_status: EvidenceStatus | None = None,
        lifecycle: WorldLifecycle | None = None,
        name_contains: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[WorldEntity]:
        where, params = self._build_entity_filters(
            mission_id,
            entity_type,
            session_id,
            namespace,
            epistemic_status,
            lifecycle,
            name_contains,
        )
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM world_entities
                WHERE {where}
                ORDER BY canonical_key, id
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()
            return [_entity_from_row(r) for r in rows]

    def count_entities(
        self,
        mission_id: str,
        entity_type: EntityType | None = None,
        session_id: SessionID | None = None,
        lifecycle: WorldLifecycle | None = None,
    ) -> int:
        where, params = self._build_entity_filters(
            mission_id, entity_type, session_id, None, None, lifecycle, None
        )
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM world_entities WHERE {where}",
                params,
            ).fetchone()
            return int(row["n"])

    def _relationship_updates_kv(self, updates: dict[str, Any]) -> dict[str, Any]:
        kv: dict[str, Any] = {}
        for key in ("session_id", "note", "lifecycle", "confidence", "last_seen", "updated_at"):
            if key not in updates:
                continue
            value = updates[key]
            if key == "confidence":
                kv["confidence"] = _confidence_to_score(value)
            elif key == "session_id":
                kv["session_id"] = str(value) if value else None
            else:
                kv[key] = value
        return kv

    def store_relationship(self, relationship: WorldRelationship) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO world_relationships (
                    id, mission_id, session_id, relationship_type,
                    source_entity_id, target_entity_id, dedup_key, note,
                    lifecycle, confidence, first_seen, last_seen, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(relationship.id),
                    str(relationship.mission_id),
                    str(relationship.session_id) if relationship.session_id else None,
                    relationship.relationship_type.value,
                    str(relationship.source_entity_id),
                    str(relationship.target_entity_id),
                    relationship.dedup_key,
                    relationship.note,
                    relationship.lifecycle.value,
                    _confidence_to_score(relationship.confidence),
                    relationship.first_seen,
                    relationship.last_seen,
                    relationship.created_at,
                    relationship.updated_at,
                ),
            )

    def update_relationship(
        self, relationship_id: str, updates: dict[str, Any]
    ) -> WorldRelationship | None:
        if not updates:
            return self.retrieve_relationship(relationship_id)
        kv = self._relationship_updates_kv(updates)
        with self._lock:
            self._conn.execute(
                f"UPDATE world_relationships SET {', '.join(f'{k}=?' for k in kv)} WHERE id=?",
                (*kv.values(), str(relationship_id)),
            )
            return self.retrieve_relationship(relationship_id)

    def delete_relationship(self, relationship_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM world_relationship_evidence WHERE relationship_id=?",
                (str(relationship_id),),
            )
            self._conn.execute(
                "DELETE FROM world_relationships WHERE id=?", (str(relationship_id),)
            )

    def retrieve_relationship(self, relationship_id: str) -> WorldRelationship | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM world_relationships WHERE id=?", (str(relationship_id),)
            ).fetchone()
            return _relationship_from_row(row) if row else None

    def find_relationship_current(
        self, mission_id: str, dedup_key: str
    ) -> WorldRelationship | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM world_relationships
                WHERE mission_id=? AND dedup_key=? AND lifecycle='active'
                LIMIT 1
                """,
                (str(mission_id), dedup_key),
            ).fetchone()
            return _relationship_from_row(row) if row else None

    def list_relationships(
        self,
        mission_id: str,
        relationship_type: RelationshipType | None = None,
        source_entity_id: str | None = None,
        target_entity_id: str | None = None,
        lifecycle: WorldLifecycle | None = None,
        limit: int = 50,
    ) -> list[WorldRelationship]:
        clauses = ["mission_id = ?"]
        params: list[Any] = [str(mission_id)]
        if relationship_type is not None:
            clauses.append("relationship_type = ?")
            params.append(relationship_type.value)
        if source_entity_id is not None:
            clauses.append("source_entity_id = ?")
            params.append(str(source_entity_id))
        if target_entity_id is not None:
            clauses.append("target_entity_id = ?")
            params.append(str(target_entity_id))
        if lifecycle is not None:
            clauses.append("lifecycle = ?")
            params.append(lifecycle.value)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM world_relationships
                WHERE {' AND '.join(clauses)}
                ORDER BY relationship_type, source_entity_id, target_entity_id
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
            return [_relationship_from_row(r) for r in rows]

    def store_assertion(self, assertion: WorldAssertion) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO world_assertions (
                    id, mission_id, session_id, entity_id, property_key,
                    property_value, epistemic_status, lifecycle, confidence,
                    dedup_key, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(assertion.id),
                    str(assertion.mission_id),
                    str(assertion.session_id) if assertion.session_id else None,
                    str(assertion.entity_id),
                    assertion.property_key,
                    assertion.property_value,
                    assertion.epistemic_status.value,
                    assertion.lifecycle.value,
                    _confidence_to_score(assertion.confidence),
                    assertion.dedup_key,
                    assertion.created_at,
                    assertion.updated_at,
                ),
            )

    def retrieve_assertion(self, assertion_id: str) -> WorldAssertion | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM world_assertions WHERE id=?", (str(assertion_id),)
            ).fetchone()
            return _assertion_from_row(row) if row else None

    def update_assertion(
        self, assertion_id: str, updates: dict[str, Any]
    ) -> WorldAssertion | None:
        if not updates:
            return self.retrieve_assertion(assertion_id)
        kv: dict[str, Any] = {}
        for key in ("epistemic_status", "lifecycle", "confidence", "updated_at"):
            if key not in updates:
                continue
            value = updates[key]
            if key == "confidence":
                kv["confidence"] = _confidence_to_score(value)
            elif key == "epistemic_status":
                kv["epistemic_status"] = value.value
            elif key == "lifecycle":
                kv["lifecycle"] = value.value
            else:
                kv[key] = value
        with self._lock:
            if kv:
                self._conn.execute(
                    f"UPDATE world_assertions SET {', '.join(f'{k}=?' for k in kv)} WHERE id=?",
                    (*kv.values(), str(assertion_id)),
                )
            return self.retrieve_assertion(assertion_id)

    def find_assertion_by_dedup_key(
        self, mission_id: str, dedup_key: str
    ) -> WorldAssertion | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM world_assertions
                WHERE mission_id=? AND dedup_key=? AND lifecycle='active'
                LIMIT 1
                """,
                (str(mission_id), dedup_key),
            ).fetchone()
            return _assertion_from_row(row) if row else None

    def list_assertions(
        self, entity_id: str, lifecycle: WorldLifecycle | None = None, limit: int = 50
    ) -> list[WorldAssertion]:
        clauses = ["entity_id = ?"]
        params: list[Any] = [str(entity_id)]
        if lifecycle is not None:
            clauses.append("lifecycle = ?")
            params.append(lifecycle.value)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM world_assertions
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
            return [_assertion_from_row(r) for r in rows]

    def link_entity_evidence(
        self,
        entity_id: str,
        evidence_id: str,
        property_key: str | None = None,
        property_value: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO world_entity_evidence (
                    entity_id, evidence_id, property_key, property_value, linked_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(entity_id),
                    str(evidence_id),
                    property_key or "",
                    property_value,
                    _now(),
                ),
            )

    def evidence_for_entity(self, entity_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT evidence_id, property_key, property_value, linked_at
                FROM world_entity_evidence
                WHERE entity_id=? ORDER BY property_key, evidence_id
                """,
                (str(entity_id),),
            ).fetchall()
            return [
                {
                    "evidence_id": row["evidence_id"],
                    "property_key": row["property_key"] or None,
                    "property_value": row["property_value"],
                    "linked_at": row["linked_at"],
                }
                for row in rows
            ]

    def entities_for_evidence(self, evidence_id: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT entity_id FROM world_entity_evidence
                WHERE evidence_id=? ORDER BY entity_id
                """,
                (str(evidence_id),),
            ).fetchall()
            return [row["entity_id"] for row in rows]

    def link_relationship_evidence(
        self, relationship_id: str, evidence_id: str, note: str | None = None
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO world_relationship_evidence (
                    relationship_id, evidence_id, note, linked_at
                ) VALUES (?, ?, ?, ?)
                """,
                (str(relationship_id), str(evidence_id), note, _now()),
            )

    def evidence_for_relationship(self, relationship_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT evidence_id, note, linked_at
                FROM world_relationship_evidence
                WHERE relationship_id=? ORDER BY evidence_id
                """,
                (str(relationship_id),),
            ).fetchall()
            return [
                {
                    "evidence_id": row["evidence_id"],
                    "note": row["note"],
                    "linked_at": row["linked_at"],
                }
                for row in rows
            ]

    def link_assertion_evidence(self, assertion_id: str, evidence_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO world_assertion_evidence (
                    assertion_id, evidence_id, linked_at
                ) VALUES (?, ?, ?)
                """,
                (str(assertion_id), str(evidence_id), _now()),
            )

    def evidence_for_assertion(self, assertion_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT evidence_id, linked_at
                FROM world_assertion_evidence
                WHERE assertion_id=? ORDER BY evidence_id
                """,
                (str(assertion_id),),
            ).fetchall()
            return [
                {
                    "evidence_id": row["evidence_id"],
                    "linked_at": row["linked_at"],
                }
                for row in rows
            ]

    def health_check(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conn.close()


def _now() -> float:
    import time

    return time.time()
