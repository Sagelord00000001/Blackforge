from __future__ import annotations

from typing import Any

from blackforge.core.logging import get_logger
from blackforge.core.types import MemoryID
from blackforge.memory.base import (
    MemoryBackend,
    MemoryLifecycle,
    MemoryQuery,
    MemoryRecord,
    MemoryType,
)
from blackforge.memory.repository import (
    InMemoryRepository,
    MemoryRepository,
    canonical_json,
    compute_dedup_key,
)

log = get_logger("memory.manager")


class MemoryManager(MemoryBackend):
    """Application-facing memory facade.

    Owns cross-record semantics on top of a persistence repository:

    * **Deduplication** — a record whose ``dedup_key`` already exists is a
      no-op returning the existing ID, so idempotent writes never duplicate.
    * **Logical versioning** — writing a new content value under an existing
      ``(memory_type, key)`` creates a new version and marks the previous one
      ``SUPERSEDED`` in the same transaction.
    * **In-place update** — ``update()`` mutates a specific record without
      creating new versions.
    """

    def __init__(self, repository: MemoryRepository | None = None) -> None:
        self._repo: MemoryRepository = repository or InMemoryRepository()

    @property
    def repository(self) -> MemoryRepository:
        return self._repo

    @property
    def backend(self) -> MemoryBackend:
        return self

    def store(self, record: MemoryRecord) -> str:
        record = record.model_copy(deep=True)
        if not record.id:
            record.id = MemoryID()
        if not record.dedup_key:
            record.dedup_key = compute_dedup_key(
                record.memory_type, record.key, record.content
            )
        with self._repo.transaction():
            existing = self._repo.get_by_dedup_key(record.dedup_key)
            if existing is not None:
                log.debug(
                    "memory_dedup_noop",
                    record_id=str(existing.id),
                    dedup_key=record.dedup_key,
                )
                return str(existing.id)

            current = self._repo.find_by_logical_key(
                record.memory_type, record.key
            )
            if current is not None:
                if canonical_json(current.content) == canonical_json(
                    record.content
                ):
                    return str(current.id)
                current.lifecycle = MemoryLifecycle.SUPERSEDED
                self._repo.update(str(current.id), {"lifecycle": MemoryLifecycle.SUPERSEDED})
                record.version = current.version + 1
                record.supersedes = MemoryID(value=str(current.id))
            else:
                record.version = 1
                record.supersedes = None
            return self._repo.store(record)

    def update(self, record_id: str, updates: dict[str, Any]) -> MemoryRecord | None:
        return self._repo.update(record_id, updates)

    def retrieve(self, record_id: str) -> MemoryRecord | None:
        return self._repo.retrieve(record_id)

    def delete(self, record_id: str) -> bool:
        return self._repo.delete(record_id)

    def search(
        self,
        query: str | MemoryQuery | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        return self._repo.search(query, memory_type, tags, limit)

    def list(
        self,
        memory_type: MemoryType | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MemoryRecord]:
        return self._repo.list(memory_type, limit, offset)

    def count(self, query: str | MemoryQuery | None = None) -> int:
        return self._repo.count(query)

    def health_check(self) -> bool:
        return self._repo.health_check()

    def close(self) -> None:
        self._repo.close()

    def get_by_dedup_key(self, dedup_key: str) -> MemoryRecord | None:
        return self._repo.get_by_dedup_key(dedup_key)

    def find_by_logical_key(
        self, memory_type: MemoryType, key: str
    ) -> MemoryRecord | None:
        return self._repo.find_by_logical_key(memory_type, key)
