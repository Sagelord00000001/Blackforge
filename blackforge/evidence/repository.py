from __future__ import annotations

import json
import os
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
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    RelationshipID,
    SessionID,
    TaskID,
)
from blackforge.evidence.models import (
    ConfidenceChange,
    Evidence,
    EvidenceLifecycle,
    EvidenceLink,
    EvidenceRelation,
    EvidenceRelationship,
    Provenance,
)
from blackforge.evidence.query import EvidenceQuery
from blackforge.evidence.rules import (
    compute_evidence_dedup_key,
    evidence_dedup_content,
)

log = get_logger("evidence.repository")


class EvidenceRepository:
    """Persistence interface for evidence records and their relationships.

    Higher-level code depends on this interface, never on SQLite directly.
    Evidence content is treated as untrusted data: only parameterized SQL is
    used, and nothing stored is ever eval-ed or executed.
    """

    @abstractmethod
    def store(self, evidence: Evidence) -> Evidence:
        """Persist an evidence record. Idempotent for the same ID."""

    @abstractmethod
    def retrieve(self, evidence_id: EvidenceID | str) -> Evidence | None:
        """Fetch a single evidence record by ID."""

    @abstractmethod
    def search(self, query: EvidenceQuery) -> list[Evidence]:
        """Deterministic structured retrieval, newest first."""

    @abstractmethod
    def list(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Evidence]:
        """List all evidence, newest first."""

    @abstractmethod
    def count(self, query: EvidenceQuery | None = None) -> int:
        """Count evidence matching optional filters."""

    @abstractmethod
    def get_by_mission(self, mission_id: MissionID) -> list[Evidence]:
        """All evidence for a mission, newest first."""

    @abstractmethod
    def get_by_dedup_key(self, dedup_key: str) -> Evidence | None:
        """Return the most recent evidence with this dedup key, if any."""

    @abstractmethod
    def add_relationship(
        self,
        source_id: EvidenceID | str,
        relation_type: EvidenceRelation,
        target_id: EvidenceID | str,
        *,
        note: str | None = None,
    ) -> EvidenceRelationship:
        """Create a typed directed relationship between two evidence records."""

    @abstractmethod
    def get_relationships(self, evidence_id: EvidenceID | str) -> list[EvidenceRelationship]:
        """Return relationships touching this record (incoming or outgoing)."""

    @abstractmethod
    def related_evidence(
        self,
        evidence_id: EvidenceID | str,
        relation_type: EvidenceRelation | None = None,
    ) -> list[EvidenceLink]:
        """Return counterpart evidence linked to this record, deterministically."""

    @abstractmethod
    def transaction(self) -> Iterator[None]:
        """Context manager providing an atomic unit of work."""

    @abstractmethod
    def health_check(self) -> bool:
        """Non-destructive check that the backend is usable."""

    @abstractmethod
    def close(self) -> None:
        """Release any held resources. Idempotent-safe."""


def _coerce_evidence_query(query: EvidenceQuery | None) -> EvidenceQuery:
    return query or EvidenceQuery()


class InMemoryEvidenceRepository(EvidenceRepository):
    """Pure in-memory evidence store for tests and discardable runtimes."""

    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}
        self._order: list[str] = []
        self._relationships: list[EvidenceRelationship] = []
        self._lock = threading.RLock()

    def store(self, evidence: Evidence) -> Evidence:
        with self._lock:
            was_present = str(evidence.id) in self._evidence
            evidence.dedup_key = evidence.dedup_key or compute_evidence_dedup_key(
                evidence.mission_id,
                evidence.target,
                evidence.source_capability,
                evidence.evidence_type,
                evidence_dedup_content(evidence),
            )
            self._evidence[str(evidence.id)] = evidence
            if not was_present:
                self._order.append(str(evidence.id))
            return evidence

    def retrieve(self, evidence_id: EvidenceID | str) -> Evidence | None:
        with self._lock:
            return self._evidence.get(str(evidence_id))

    def search(self, query: EvidenceQuery) -> list[Evidence]:
        q = query or EvidenceQuery()
        with self._lock:
            results = []
            for evidence_id in reversed(self._order):
                ev = self._evidence[evidence_id]
                if not self._matches(ev, q):
                    continue
                results.append(ev)
                if len(results) >= q.limit:
                    break
            start = min(q.offset, len(results))
            return results[start:]

    def list(self, limit: int = 50, offset: int = 0) -> list[Evidence]:
        with self._lock:
            records = [self._evidence[i] for i in reversed(self._order)]
            return records[offset : offset + limit]

    def count(self, query: EvidenceQuery | None = None) -> int:
        q = _coerce_evidence_query(query)
        with self._lock:
            return sum(1 for ev in self._evidence.values() if self._matches(ev, q))

    def get_by_mission(self, mission_id: MissionID) -> list[Evidence]:
        with self._lock:
            return [
                self._evidence[eid]
                for eid in reversed(self._order)
                if self._evidence[eid].mission_id == mission_id
            ]

    def get_by_dedup_key(self, dedup_key: str) -> Evidence | None:
        with self._lock:
            for evidence_id in reversed(self._order):
                ev = self._evidence[evidence_id]
                if ev.dedup_key == dedup_key:
                    return ev
            return None

    def add_relationship(
        self,
        source_id: EvidenceID | str,
        relation_type: EvidenceRelation,
        target_id: EvidenceID | str,
        *,
        note: str | None = None,
    ) -> EvidenceRelationship:
        source, target = str(source_id), str(target_id)
        if source == target:
            raise ValueError("evidence cannot relate to itself")
        if source not in self._evidence or target not in self._evidence:
            raise ValueError("relationship references unknown evidence")
        relationship = EvidenceRelationship(
            source_id=EvidenceID(source),
            relation_type=relation_type,
            target_id=EvidenceID(target),
            note=note,
        )
        with self._lock:
            self._relationships.append(relationship)
        return relationship

    def get_relationships(self, evidence_id: EvidenceID | str) -> list[EvidenceRelationship]:
        key = str(evidence_id)
        with self._lock:
            return [
                r
                for r in self._relationships
                if str(r.source_id) == key or str(r.target_id) == key
            ]

    def related_evidence(
        self,
        evidence_id: EvidenceID | str,
        relation_type: EvidenceRelation | None = None,
    ) -> list[EvidenceLink]:
        key = str(evidence_id)
        links: list[EvidenceLink] = []
        with self._lock:
            for r in sorted(self._relationships, key=lambda r: (r.created_at, str(r.id))):
                if relation_type is not None and r.relation_type != relation_type:
                    continue
                if str(r.source_id) == key:
                    counterpart = self._evidence.get(str(r.target_id))
                    if counterpart is not None:
                        links.append(
                            EvidenceLink(
                                relation=r.relation_type,
                                evidence=counterpart,
                                direction="outgoing",
                            )
                        )
                elif str(r.target_id) == key:
                    counterpart = self._evidence.get(str(r.source_id))
                    if counterpart is not None:
                        links.append(
                            EvidenceLink(
                                relation=r.relation_type,
                                evidence=counterpart,
                                direction="incoming",
                            )
                        )
            return links

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    def health_check(self) -> bool:
        return True

    def close(self) -> None:
        with self._lock:
            self._evidence.clear()
            self._order.clear()
            self._relationships.clear()

    def _matches(self, ev: Evidence, q: EvidenceQuery) -> bool:
        if q.mission_id and ev.mission_id != q.mission_id:
            return False
        if q.session_id and ev.session_id != q.session_id:
            return False
        if q.status and ev.status != q.status:
            return False
        if q.lifecycle and ev.lifecycle != q.lifecycle:
            return False
        if q.source_capability and ev.source_capability != q.source_capability:
            return False
        if q.evidence_type and ev.evidence_type != q.evidence_type:
            return False
        if q.confidence and ev.confidence != q.confidence:
            return False
        if q.created_after is not None and ev.timestamp <= q.created_after:
            return False
        if q.created_before is not None and ev.timestamp >= q.created_before:
            return False
        if q.keyword:
            haystack = json.dumps(
                [ev.target, ev.raw_data, ev.summary, ev.reference],
                default=str,
            )
            if q.keyword not in ev.target and q.keyword not in haystack:
                return False
        if q.related_to:
            matched = self._touches_relation(ev, q)
            if not matched:
                return False
        return True

    def _touches_relation(self, ev: Evidence, q: EvidenceQuery) -> bool:
        key = str(ev.id)
        for r in self._relationships:
            if q.relation_type is not None and r.relation_type != q.relation_type:
                continue
            if str(r.source_id) == key and str(r.target_id) == str(q.related_to):
                return True
            if str(r.target_id) == key and str(r.source_id) == str(q.related_to):
                return True
        return False


_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        mission_id TEXT NOT NULL,
        session_id TEXT,
        task_id TEXT,
        timestamp REAL NOT NULL,
        updated_at REAL,
        source_capability TEXT NOT NULL,
        target TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        status TEXT NOT NULL,
        lifecycle TEXT NOT NULL,
        confidence TEXT NOT NULL,
        confidence_changes TEXT NOT NULL DEFAULT '[]',
        raw_data TEXT,
        summary TEXT,
        reference TEXT,
        dedup_key TEXT,
        provenance TEXT NOT NULL DEFAULT '{}',
        meta TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_relationships (
        id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        relation_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        note TEXT,
        created_at REAL NOT NULL
    )
    """,
]

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_evidence_mission ON evidence(mission_id)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_lifecycle ON evidence(lifecycle)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_source ON evidence(source_capability)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_dedup ON evidence(dedup_key)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_created ON evidence(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_rel_source ON evidence_relationships(source_id)",
    "CREATE INDEX IF NOT EXISTS idx_rel_target ON evidence_relationships(target_id)",
    "CREATE INDEX IF NOT EXISTS idx_rel_type ON evidence_relationships(relation_type)",
]


class SQLiteEvidenceRepository(EvidenceRepository):
    """SQLite persistence for evidence, mirroring the Phase 2 memory pattern.

    Autocommit mode with explicit ``BEGIN IMMEDIATE`` transactions under a
    re-entrant lock. All queries are parameterized; fetched rows are mapped
    back into Pydantic domain models without leaking SQL into higher layers.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        if db_path not in (":memory:", ""):
            parent = os.path.dirname(os.path.abspath(db_path))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.isolation_level = None
        self._conn.row_factory = sqlite3.Row
        self._closure_lock = threading.RLock()
        self._lock = threading.RLock()
        self._closed = False
        self._create_tables()

    def _create_tables(self) -> None:
        with self._closure_lock:
            for stmt in _SCHEMA:
                self._conn.execute(stmt)
            for stmt in _INDEXES:
                self._conn.execute(stmt)

    @property
    def db_path(self) -> str:
        return self._db_path

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            if self._closed:
                raise sqlite3.OperationalError("repository is closed")
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def store(self, evidence: Evidence) -> Evidence:
        evidence.dedup_key = evidence.dedup_key or compute_evidence_dedup_key(
            evidence.mission_id,
            evidence.target,
            evidence.source_capability,
            evidence.evidence_type,
            evidence_dedup_content(evidence),
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO evidence (
                    id, mission_id, session_id, task_id, timestamp, updated_at,
                    source_capability, target, evidence_type, status, lifecycle,
                    confidence, confidence_changes, raw_data, summary, reference,
                    dedup_key, provenance, meta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(evidence.id),
                    str(evidence.mission_id),
                    str(evidence.session_id) if evidence.session_id else None,
                    str(evidence.task_id) if evidence.task_id else None,
                    evidence.timestamp,
                    evidence.updated_at,
                    evidence.source_capability,
                    evidence.target,
                    evidence.evidence_type.value,
                    evidence.status.value,
                    evidence.lifecycle.value,
                    evidence.confidence.value,
                    json.dumps([c.model_dump() for c in evidence.confidence_changes]),
                    evidence.raw_data,
                    evidence.summary,
                    evidence.reference,
                    evidence.dedup_key,
                    evidence.provenance.model_dump_json(),
                    json.dumps(evidence.metadata),
                ),
            )
        log.debug(
            "evidence_stored",
            evidence_id=str(evidence.id),
            mission_id=str(evidence.mission_id),
        )
        return evidence

    def retrieve(self, evidence_id: EvidenceID | str) -> Evidence | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM evidence WHERE id = ?", (str(evidence_id),)
            ).fetchone()
        return self._row_to_evidence(row) if row else None

    def search(self, query: EvidenceQuery) -> list[Evidence]:
        q = query or EvidenceQuery()
        where, params = self._build_where(q)
        sql = (
            f"SELECT * FROM evidence WHERE {where} "
            "ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, params + [q.limit, q.offset]).fetchall()
        return [self._row_to_evidence(r) for r in rows]

    def list(self, limit: int = 50, offset: int = 0) -> list[Evidence]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM evidence ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._row_to_evidence(r) for r in rows]

    def count(self, query: EvidenceQuery | None = None) -> int:
        q = _coerce_evidence_query(query)
        where, params = self._build_where(q)
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM evidence WHERE {where}", params
            ).fetchone()
        return int(row["n"])

    def get_by_mission(self, mission_id: MissionID) -> list[Evidence]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM evidence WHERE mission_id = ? "
                "ORDER BY timestamp DESC, id DESC",
                (str(mission_id),),
            ).fetchall()
        return [self._row_to_evidence(r) for r in rows]

    def get_by_dedup_key(self, dedup_key: str) -> Evidence | None:
        if not dedup_key:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM evidence WHERE dedup_key = ? "
                "ORDER BY timestamp DESC, id DESC LIMIT 1",
                (dedup_key,),
            ).fetchone()
        return self._row_to_evidence(row) if row else None

    def add_relationship(
        self,
        source_id: EvidenceID | str,
        relation_type: EvidenceRelation,
        target_id: EvidenceID | str,
        *,
        note: str | None = None,
    ) -> EvidenceRelationship:
        source, target = str(source_id), str(target_id)
        if source == target:
            raise ValueError("evidence cannot relate to itself")
        with self._lock:
            for eid in (source, target):
                if self._conn.execute(
                    "SELECT 1 FROM evidence WHERE id = ?", (eid,)
                ).fetchone() is None:
                    raise ValueError("relationship references unknown evidence")
            relationship = EvidenceRelationship(
                source_id=EvidenceID(source),
                relation_type=relation_type,
                target_id=EvidenceID(target),
                note=note,
            )
            self._conn.execute(
                """
                INSERT INTO evidence_relationships
                (id, source_id, relation_type, target_id, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(relationship.id),
                    str(relationship.source_id),
                    relationship.relation_type.value,
                    str(relationship.target_id),
                    relationship.note,
                    relationship.created_at,
                ),
            )
        return relationship

    def get_relationships(
        self, evidence_id: EvidenceID | str
    ) -> list[EvidenceRelationship]:
        key = str(evidence_id)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM evidence_relationships "
                "WHERE source_id = ? OR target_id = ? ORDER BY created_at, id",
                (key, key),
            ).fetchall()
        return [self._row_to_relationship(r) for r in rows]

    def related_evidence(
        self,
        evidence_id: EvidenceID | str,
        relation_type: EvidenceRelation | None = None,
    ) -> list[EvidenceLink]:
        key = str(evidence_id)
        query = (
            "SELECT * FROM evidence_relationships "
            "WHERE (source_id = ? OR target_id = ?)"
            + (" AND relation_type = ?" if relation_type else "")
        )
        params: list[Any] = [key, key]
        if relation_type:
            params.append(relation_type.value)
        with self._lock:
            rows = self._conn.execute(
                query + " ORDER BY created_at, id", params
            ).fetchall()
        links: list[EvidenceLink] = []
        for row in rows:
            rel = self._row_to_relationship(row)
            if str(rel.source_id) == key:
                counterpart = self.retrieve(rel.target_id)
                direction = "outgoing"
            else:
                counterpart = self.retrieve(rel.source_id)
                direction = "incoming"
            if counterpart is not None:
                links.append(
                    EvidenceLink(
                        relation=rel.relation_type,
                        evidence=counterpart,
                        direction=direction,
                    )
                )
        return links

    def health_check(self) -> bool:
        try:
            with self._lock:
                if self._closed:
                    return False
                self._conn.execute("SELECT 1").fetchone()
                for table in ("evidence", "evidence_relationships"):
                    self._conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()
            return True
        except Exception:
            return False

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True

    def _build_where(self, q: EvidenceQuery) -> tuple[str, list[Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        if q.mission_id:
            conditions.append("mission_id = ?")
            params.append(str(q.mission_id))
        if q.session_id:
            conditions.append("session_id = ?")
            params.append(str(q.session_id))
        if q.status:
            conditions.append("status = ?")
            params.append(q.status.value)
        if q.lifecycle:
            conditions.append("lifecycle = ?")
            params.append(q.lifecycle.value)
        if q.source_capability:
            conditions.append("source_capability = ?")
            params.append(q.source_capability)
        if q.evidence_type:
            conditions.append("evidence_type = ?")
            params.append(q.evidence_type.value)
        if q.confidence:
            conditions.append("confidence = ?")
            params.append(q.confidence.value)
        if q.created_after is not None:
            conditions.append("timestamp > ?")
            params.append(q.created_after)
        if q.created_before is not None:
            conditions.append("timestamp < ?")
            params.append(q.created_before)
        if q.keyword:
            conditions.append(
                "(target LIKE ? OR raw_data LIKE ? OR summary LIKE ? OR reference LIKE ?)"
            )
            pattern = f"%{q.keyword}%"
            params.extend([pattern, pattern, pattern, pattern])
        if q.related_to:
            if q.relation_type:
                conditions.append(
                    "(id IN (SELECT source_id FROM evidence_relationships "
                    "WHERE target_id = ? AND relation_type = ?) "
                    "OR id IN (SELECT target_id FROM evidence_relationships "
                    "WHERE source_id = ? AND relation_type = ?))"
                )
                params.extend(
                    [
                        str(q.related_to),
                        q.relation_type.value,
                        str(q.related_to),
                        q.relation_type.value,
                    ]
                )
            else:
                conditions.append(
                    "(id IN (SELECT source_id FROM evidence_relationships WHERE target_id = ?) "
                    "OR id IN (SELECT target_id FROM evidence_relationships WHERE source_id = ?))"
                )
                params.extend([str(q.related_to), str(q.related_to)])
        where = conditions and " AND ".join(conditions) or "1=1"
        return where, params

    @staticmethod
    def _row_to_relationship(row: sqlite3.Row) -> EvidenceRelationship:
        return EvidenceRelationship(
            id=RelationshipID(value=str(row["id"])),
            source_id=EvidenceID(value=str(row["source_id"])),
            relation_type=EvidenceRelation(row["relation_type"]),
            target_id=EvidenceID(value=str(row["target_id"])),
            note=row["note"],
            created_at=float(row["created_at"]),
        )

    @staticmethod
    def _row_to_evidence(row: sqlite3.Row) -> Evidence:
        try:
            provenance = Provenance.model_validate_json(row["provenance"])
        except Exception:
            provenance = Provenance()
        confidence_changes = [
            ConfidenceChange(**c) for c in json.loads(row["confidence_changes"] or "[]")
        ]
        return Evidence(
            id=EvidenceID(value=str(row["id"])),
            mission_id=MissionID(value=str(row["mission_id"])),
            session_id=(
                SessionID(value=str(row["session_id"])) if row["session_id"] else None
            ),
            task_id=TaskID(value=str(row["task_id"])) if row["task_id"] else None,
            timestamp=float(row["timestamp"]),
            updated_at=float(row["updated_at"]) if row["updated_at"] else None,
            source_capability=row["source_capability"],
            target=row["target"],
            evidence_type=EvidenceType(row["evidence_type"]),
            status=EvidenceStatus(row["status"]),
            lifecycle=EvidenceLifecycle(row["lifecycle"]),
            confidence=Confidence(row["confidence"]),
            confidence_changes=confidence_changes,
            raw_data=row["raw_data"],
            summary=row["summary"],
            reference=row["reference"],
            dedup_key=row["dedup_key"],
            provenance=provenance,
            metadata=json.loads(row["meta"] or "{}"),
        )


class SQLiteEvidenceBackend(SQLiteEvidenceRepository):
    """Backward-compatible alias."""


class InMemoryEvidenceBackend(InMemoryEvidenceRepository):
    """Backward-compatible alias."""
