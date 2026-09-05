from __future__ import annotations

import hashlib
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
    EvidenceID,
    EvidenceStatus,
    MemoryID,
    MissionID,
    SessionID,
)
from blackforge.memory.base import (
    MemoryBackend,
    MemoryLifecycle,
    MemoryQuery,
    MemoryRecord,
    MemoryType,
)
from blackforge.memory.provenance import MemoryProvenance, MemorySource

log = get_logger("memory.repository")


def canonical_json(obj: Any) -> str:
    """Stable JSON serialization so equal-but-reordered structures dedup equally."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compute_dedup_key(
    memory_type: MemoryType | str, key: str, content: Any
) -> str:
    """Deterministic content hash for the (type, key, content) triple."""
    type_value = (
        memory_type.value if isinstance(memory_type, MemoryType) else str(memory_type)
    )
    payload = f"{type_value}|{key}|{canonical_json(content)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def coerce_query(
    query: str | MemoryQuery | None = None,
    memory_type: MemoryType | None = None,
    tags: list[str] | None = None,
    limit: int = 50,
) -> MemoryQuery:
    """Normalize legacy positional search arguments into a MemoryQuery."""
    if isinstance(query, MemoryQuery):
        merged = query.model_copy(deep=True)
        if memory_type is not None:
            merged.memory_type = memory_type
        if tags:
            merged.tags = list(tags)
        return merged
    keyword = str(query) if query else None
    return MemoryQuery(
        keyword=keyword,
        memory_type=memory_type,
        tags=list(tags) if tags else [],
        limit=limit,
    )


class MemoryRepository(MemoryBackend):
    """Persistence interface for memory records.

    Extends the backend ABC with logical-retrieval helpers used by the
    dedup/versioning semantics in :class:`MemoryManager`. Stored content is
    treated as untrusted data: only parameterized SQL is used.
    """

    @abstractmethod
    def get_by_dedup_key(self, dedup_key: str) -> MemoryRecord | None:
        """Return the most recent record with this dedup key, if any."""

    @abstractmethod
    def find_by_logical_key(
        self, memory_type: MemoryType, key: str
    ) -> MemoryRecord | None:
        """Return the current (highest-version, non-superseded) record for (type, key)."""

    @abstractmethod
    def transaction(self) -> Iterator[None]:
        """Context manager providing an atomic unit of work."""


class InMemoryRepository(MemoryRepository):
    """Pure in-memory repository for tests and the in-memory configuration."""

    def __init__(self) -> None:
        self._records: dict[str, MemoryRecord] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def store(self, record: MemoryRecord) -> str:
        with self._lock:
            if not record.id:
                record.id = MemoryID()
            record.dedup_key = record.dedup_key or compute_dedup_key(
                record.memory_type, record.key, record.content
            )
            was_present = record.id in self._records
            self._records[record.id] = record
            if not was_present:
                self._order.append(str(record.id))
            return str(record.id)

    def retrieve(self, record_id: str) -> MemoryRecord | None:
        with self._lock:
            return self._records.get(str(record_id))

    def update(self, record_id: str, updates: dict[str, Any]) -> MemoryRecord | None:
        import time

        with self._lock:
            record = self._records.get(str(record_id))
            if not record:
                return None
            for k, v in updates.items():
                if hasattr(record, k):
                    setattr(record, k, v)
            record.updated_at = time.time()
            if "content" in updates:
                record.dedup_key = compute_dedup_key(
                    record.memory_type, record.key, record.content
                )
            return record

    def delete(self, record_id: str) -> bool:
        with self._lock:
            key = str(record_id)
            if key in self._records:
                del self._records[key]
                if key in self._order:
                    self._order.remove(key)
                return True
            return False

    def search(
        self,
        query: str | MemoryQuery | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        q = coerce_query(query, memory_type, tags, limit)
        with self._lock:
            results: list[MemoryRecord] = []
            for record_id in reversed(self._order):
                rec = self._records[record_id]
                if not self._matches(rec, q):
                    continue
                results.append(rec)
                if len(results) >= q.limit:
                    break
            start = min(q.offset, len(results))
            return results[start:]

    def list(
        self,
        memory_type: MemoryType | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MemoryRecord]:
        with self._lock:
            records = [
                rec
                for rec in (self._records[i] for i in reversed(self._order))
                if memory_type is None or rec.memory_type == memory_type
            ]
            return records[offset : offset + limit]

    def count(self, query: str | MemoryQuery | None = None) -> int:
        q = coerce_query(query)
        with self._lock:
            return sum(1 for rec in self._records.values() if self._matches(rec, q))

    def health_check(self) -> bool:
        return True

    def close(self) -> None:
        self._records.clear()
        self._order.clear()

    def get_by_dedup_key(self, dedup_key: str) -> MemoryRecord | None:
        with self._lock:
            for record_id in reversed(self._order):
                rec = self._records[record_id]
                if rec.dedup_key == dedup_key:
                    return rec
            return None

    def find_by_logical_key(
        self, memory_type: MemoryType, key: str
    ) -> MemoryRecord | None:
        with self._lock:
            candidates = [
                rec
                for rec in self._records.values()
                if rec.memory_type == memory_type
                and rec.key == key
                and rec.lifecycle != MemoryLifecycle.SUPERSEDED
            ]
            if not candidates:
                return None
            return max(candidates, key=lambda r: r.version)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    @staticmethod
    def _matches(rec: MemoryRecord, q: MemoryQuery) -> bool:
        if q.memory_type and rec.memory_type != q.memory_type:
            return False
        if q.mission_id and rec.mission_id != q.mission_id:
            return False
        if q.session_id and rec.session_id != q.session_id:
            return False
        if q.status and rec.status != q.status:
            return False
        if q.lifecycle and rec.lifecycle != q.lifecycle:
            return False
        if q.source and rec.source != q.source:
            return False
        if q.confidence_min is not None and rec.confidence < q.confidence_min:
            return False
        if q.confidence_max is not None and rec.confidence > q.confidence_max:
            return False
        if q.created_after is not None and rec.created_at <= q.created_after:
            return False
        if q.created_before is not None and rec.created_at >= q.created_before:
            return False
        if q.keyword and q.keyword not in rec.key and q.keyword not in json.dumps(
            rec.content, default=str
        ):
            return False
        return not q.tags or any(t in rec.tags for t in q.tags)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    id TEXT PRIMARY KEY,
    memory_type TEXT NOT NULL,
    key TEXT NOT NULL,
    content TEXT,
    status TEXT NOT NULL,
    confidence REAL NOT NULL,
    mission_id TEXT,
    session_id TEXT,
    source TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    supersedes TEXT,
    dedup_key TEXT,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    provenance TEXT NOT NULL DEFAULT '{}',
    tags TEXT NOT NULL DEFAULT '[]',
    meta TEXT NOT NULL DEFAULT '{}',
    expires_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL
)
"""

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_memory_type ON memory(memory_type)",
    "CREATE INDEX IF NOT EXISTS idx_memory_key ON memory(key)",
    "CREATE INDEX IF NOT EXISTS idx_memory_mission ON memory(mission_id)",
    "CREATE INDEX IF NOT EXISTS idx_memory_session ON memory(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_memory_status ON memory(status)",
    "CREATE INDEX IF NOT EXISTS idx_memory_lifecycle ON memory(lifecycle)",
    "CREATE INDEX IF NOT EXISTS idx_memory_dedup ON memory(dedup_key)",
    "CREATE INDEX IF NOT EXISTS idx_memory_created ON memory(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_memory_version ON memory(key, version)",
]


def load_content(raw: str | None) -> Any:
    """Materialize stored content, falling back to the raw string on parse failure."""
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def encode_content(content: Any) -> str | None:
    if content is None:
        return None
    return canonical_json(content)


class SQLiteMemoryRepository(MemoryRepository):
    """SQLite persistence for memory records.

    Uses autocommit mode with explicit ``BEGIN IMMEDIATE`` transactions under a
    re-entrant lock. Reads and writes are serialized through the same lock so a
    single connection is safe even with ``check_same_thread=False``.
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
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.execute(_SCHEMA)
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

    def store(self, record: MemoryRecord) -> str:
        record.dedup_key = record.dedup_key or compute_dedup_key(
            record.memory_type, record.key, record.content
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO memory (
                    id, memory_type, key, content, status, confidence,
                    mission_id, session_id, source, lifecycle, version,
                    supersedes, dedup_key, evidence_ids, provenance,
                    tags, meta, expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.id),
                    record.memory_type.value,
                    record.key,
                    encode_content(record.content),
                    record.status.value,
                    record.confidence,
                    str(record.mission_id) if record.mission_id else None,
                    str(record.session_id) if record.session_id else None,
                    record.source.value,
                    record.lifecycle.value,
                    record.version,
                    str(record.supersedes) if record.supersedes else None,
                    record.dedup_key,
                    json.dumps(
                        [str(e) for e in record.evidence_ids]
                        if record.evidence_ids
                        else []
                    ),
                    record.provenance.model_dump_json(),
                    json.dumps(record.tags),
                    canonical_json(record.metadata),
                    record.expires_at,
                    record.created_at,
                    record.updated_at,
                ),
            )
        log.debug("memory_stored", record_id=str(record.id), key=record.key)
        return str(record.id)

    def retrieve(self, record_id: str) -> MemoryRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory WHERE id = ?", (str(record_id),)
            ).fetchone()
        return self._row_to_record(row) if row else None

    def update(self, record_id: str, updates: dict[str, Any]) -> MemoryRecord | None:
        import time

        record = self.retrieve(record_id)
        if not record:
            return None
        for k, v in updates.items():
            if hasattr(record, k):
                setattr(record, k, v)
        record.updated_at = time.time()
        if "content" in updates:
            record.dedup_key = compute_dedup_key(
                record.memory_type, record.key, record.content
            )
        return self._persist(record)

    def delete(self, record_id: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM memory WHERE id = ?", (str(record_id),)
            )
        return cursor.rowcount > 0

    def search(
        self,
        query: str | MemoryQuery | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        q = coerce_query(query, memory_type, tags, limit)
        where, params = self._build_where(q)
        sql = (
            f"SELECT * FROM memory WHERE {where} ORDER BY created_at DESC, version DESC "
            "LIMIT ? OFFSET ?"
        )
        with self._lock:
            rows = self._conn.execute(
                sql, params + [q.limit, q.offset]
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def list(
        self,
        memory_type: MemoryType | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MemoryRecord]:
        params: list[Any] = []
        where = "1=1"
        if memory_type is not None:
            where = "memory_type = ?"
            params.append(memory_type.value)
        sql = (
            f"SELECT * FROM memory WHERE {where} ORDER BY created_at DESC, version DESC "
            "LIMIT ? OFFSET ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, params + [limit, offset]).fetchall()
        return [self._row_to_record(r) for r in rows]

    def count(self, query: str | MemoryQuery | None = None) -> int:
        q = coerce_query(query)
        where, params = self._build_where(q)
        sql = f"SELECT COUNT(*) AS n FROM memory WHERE {where}"
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return int(row["n"])

    def health_check(self) -> bool:
        try:
            with self._lock:
                if self._closed:
                    return False
                self._conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True

    def get_by_dedup_key(self, dedup_key: str) -> MemoryRecord | None:
        if not dedup_key:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory WHERE dedup_key = ? "
                "ORDER BY created_at DESC, version DESC LIMIT 1",
                (dedup_key,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def find_by_logical_key(
        self, memory_type: MemoryType, key: str
    ) -> MemoryRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory WHERE memory_type = ? AND key = ? "
                "AND lifecycle != ? ORDER BY version DESC LIMIT 1",
                (memory_type.value, key, MemoryLifecycle.SUPERSEDED.value),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def _persist(self, record: MemoryRecord) -> MemoryRecord:
        self.store(record)
        return record

    def _build_where(self, q: MemoryQuery) -> tuple[str, list[Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        if q.memory_type:
            conditions.append("memory_type = ?")
            params.append(q.memory_type.value)
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
        if q.source:
            conditions.append("source = ?")
            params.append(q.source.value)
        if q.confidence_min is not None:
            conditions.append("confidence >= ?")
            params.append(q.confidence_min)
        if q.confidence_max is not None:
            conditions.append("confidence <= ?")
            params.append(q.confidence_max)
        if q.created_after is not None:
            conditions.append("created_at > ?")
            params.append(q.created_after)
        if q.created_before is not None:
            conditions.append("created_at < ?")
            params.append(q.created_before)
        if q.keyword:
            conditions.append("(key LIKE ? OR content LIKE ?)")
            pattern = f"%{q.keyword}%"
            params.extend([pattern, pattern])
        if q.tags:
            tag_conditions = " OR ".join("tags LIKE ?" for _ in q.tags)
            conditions.append(f"({tag_conditions})")
            params.extend([f'%"{t}"%' for t in q.tags])
        where = conditions and " AND ".join(conditions) or "1=1"
        return where, params

    def _row_to_record(self, row: sqlite3.Row) -> MemoryRecord:
        try:
            provenance = MemoryProvenance.model_validate_json(row["provenance"])
        except Exception:
            provenance = MemoryProvenance()
        evidence_ids = [
            EvidenceID(value)
            for value in json.loads(row["evidence_ids"] or "[]")
        ]
        return MemoryRecord(
            id=MemoryID(value=str(row["id"])),
            memory_type=MemoryType(row["memory_type"]),
            key=row["key"],
            content=load_content(row["content"]),
            status=EvidenceStatus(row["status"]),
            confidence=float(row["confidence"]),
            mission_id=(
                MissionID(value=row["mission_id"]) if row["mission_id"] else None
            ),
            session_id=(
                SessionID(value=row["session_id"]) if row["session_id"] else None
            ),
            source=MemorySource(row["source"]),
            provenance=provenance,
            evidence_ids=evidence_ids,
            lifecycle=MemoryLifecycle(row["lifecycle"]),
            version=int(row["version"]),
            supersedes=(
                MemoryID(value=row["supersedes"]) if row["supersedes"] else None
            ),
            dedup_key=row["dedup_key"],
            tags=json.loads(row["tags"] or "[]"),
            metadata=json.loads(row["meta"] or "{}"),
            expires_at=row["expires_at"],
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]) if row["updated_at"] else None,
        )


class SQLiteMemoryBackend(SQLiteMemoryRepository):
    """Backward-compatible alias for Phase 0 imports."""


class InMemoryBackend(InMemoryRepository):
    """Backward-compatible alias for Phase 0 imports."""
