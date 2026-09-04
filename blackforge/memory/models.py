from __future__ import annotations

import uuid
from typing import Any

from blackforge.core.logging import get_logger
from blackforge.memory.base import MemoryBackend, MemoryRecord, MemoryType

log = get_logger("memory.sqlite")


class SQLiteMemoryBackend(MemoryBackend):
    """Simple SQLite-backed memory for Phase 0. Replaced later with a proper store."""

    def __init__(self, db_path: str = ":memory:") -> None:
        import sqlite3

        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory (
                id TEXT PRIMARY KEY,
                memory_type TEXT NOT NULL,
                key TEXT NOT NULL,
                content TEXT,
                tags TEXT DEFAULT '[]',
                meta TEXT DEFAULT '{}',
                created_at REAL NOT NULL,
                updated_at REAL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memory_type ON memory(memory_type)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_key ON memory(key)")
        self._conn.commit()

    def store(self, record: MemoryRecord) -> str:
        import json

        if not record.id:
            record.id = uuid.uuid4().hex[:16]
        self._conn.execute(
            """
            INSERT OR REPLACE INTO memory (id, memory_type, key, content, tags, meta, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.memory_type.value,
                record.key,
                str(record.content) if record.content else None,
                json.dumps(record.tags),
                json.dumps(record.metadata),
                record.created_at,
                record.updated_at,
            ),
        )
        self._conn.commit()
        log.debug("memory_stored", record_id=record.id, key=record.key)
        return record.id

    def retrieve(self, record_id: str) -> MemoryRecord | None:
        import json

        row = self._conn.execute(
            "SELECT * FROM memory WHERE id = ?", (record_id,)
        ).fetchone()
        if not row:
            return None
        return MemoryRecord(
            id=row["id"],
            memory_type=MemoryType(row["memory_type"]),
            key=row["key"],
            content=row["content"],
            tags=json.loads(row["tags"]),
            metadata=json.loads(row["meta"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def update(self, record_id: str, updates: dict[str, Any]) -> MemoryRecord | None:
        import json

        record = self.retrieve(record_id)
        if not record:
            return None
        for k, v in updates.items():
            if hasattr(record, k):
                setattr(record, k, v)
        record.updated_at = __import__("time").time()
        self._conn.execute(
            """
            UPDATE memory SET content=?, tags=?, meta=?, updated_at=?
            WHERE id=?
            """,
            (
                str(record.content) if record.content else None,
                json.dumps(record.tags),
                json.dumps(record.metadata),
                record.updated_at,
                record_id,
            ),
        )
        self._conn.commit()
        return record

    def delete(self, record_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM memory WHERE id = ?", (record_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def search(
        self,
        query: str | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        import json

        conditions: list[str] = []
        params: list[Any] = []
        if memory_type:
            conditions.append("memory_type = ?")
            params.append(memory_type.value)
        if query:
            conditions.append("(key LIKE ? OR content LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%"])

        where = " AND ".join(conditions) if conditions else "1=1"
        rows = self._conn.execute(
            f"SELECT * FROM memory WHERE {where} ORDER BY created_at DESC LIMIT ?",
            params + [limit],
        ).fetchall()

        results: list[MemoryRecord] = []
        for row in rows:
            rec = MemoryRecord(
                id=row["id"],
                memory_type=MemoryType(row["memory_type"]),
                key=row["key"],
                content=row["content"],
                tags=json.loads(row["tags"]),
                metadata=json.loads(row["meta"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            if tags and not any(t in rec.tags for t in tags):
                continue
            results.append(rec)
        return results

    def close(self) -> None:
        self._conn.close()


class InMemoryBackend(MemoryBackend):
    """Pure in-memory backend for testing."""

    def __init__(self) -> None:
        self._records: dict[str, MemoryRecord] = {}

    def store(self, record: MemoryRecord) -> str:
        if not record.id:
            record.id = uuid.uuid4().hex[:16]
        self._records[record.id] = record
        return record.id

    def retrieve(self, record_id: str) -> MemoryRecord | None:
        return self._records.get(record_id)

    def update(self, record_id: str, updates: dict[str, Any]) -> MemoryRecord | None:
        record = self._records.get(record_id)
        if not record:
            return None
        for k, v in updates.items():
            if hasattr(record, k):
                setattr(record, k, v)
        record.updated_at = __import__("time").time()
        return record

    def delete(self, record_id: str) -> bool:
        return self._records.pop(record_id, None) is not None

    def search(
        self,
        query: str | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        results: list[MemoryRecord] = []
        for rec in self._records.values():
            if memory_type and rec.memory_type != memory_type:
                continue
            if query and query not in rec.key and query not in str(rec.content):
                continue
            if tags and not any(t in rec.tags for t in tags):
                continue
            results.append(rec)
            if len(results) >= limit:
                break
        return results
