from __future__ import annotations

import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, EvidenceStatus, MemoryID, MissionID, SessionID
from blackforge.memory.provenance import MemoryProvenance, MemorySource


class MemoryType(str, Enum):
    WORKING = "working"
    KNOWLEDGE = "knowledge"
    EXPERIENCE = "experience"
    EVIDENCE = "evidence"


class MemoryLifecycle(str, Enum):
    WORKING = "working"
    ACTIVE = "active"
    ARCHIVED = "archived"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"


class MemoryRecord(BaseModel):
    """A single memory record with first-class provenance and confidence.

    The record is backend-independent; repositories persist it and
    materialize it back without loss. ``content`` may be any JSON-serializable
    value. ``status`` uses the shared ``EvidenceStatus`` enum rather than a
    competing memory-specific epistemic enum.
    """

    id: MemoryID = Field(default_factory=MemoryID)
    memory_type: MemoryType = MemoryType.WORKING
    key: str = ""
    content: Any = None

    status: EvidenceStatus = EvidenceStatus.OBSERVED
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    mission_id: MissionID | None = None
    session_id: SessionID | None = None

    source: MemorySource = MemorySource.OBSERVATION
    provenance: MemoryProvenance = Field(default_factory=MemoryProvenance)
    evidence_ids: list[EvidenceID] = Field(default_factory=list)

    lifecycle: MemoryLifecycle = MemoryLifecycle.ACTIVE
    version: int = 1
    supersedes: MemoryID | None = None
    dedup_key: str | None = None

    tags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)

    expires_at: float | None = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float | None = None


class MemoryQuery(BaseModel):
    """Structured, deterministic retrieval filters for memory search."""

    query: str | None = None
    memory_type: MemoryType | None = None
    mission_id: MissionID | None = None
    session_id: SessionID | None = None
    status: EvidenceStatus | None = None
    lifecycle: MemoryLifecycle | None = None
    tags: list[str] = Field(default_factory=list)
    source: MemorySource | None = None
    confidence_min: float | None = None
    confidence_max: float | None = None
    created_after: float | None = None
    created_before: float | None = None
    keyword: str | None = None
    limit: int = 50
    offset: int = 0


class MemoryBackend(ABC):
    """Backend-independent memory interface.

    Higher-level Blackforge code (bootstrap, app, orchestrators) depends on
    this interface, never on SQLite or any concrete repository.
    """

    @abstractmethod
    def store(self, record: MemoryRecord) -> str:
        """Persist a record, returning its memory ID."""

    @abstractmethod
    def retrieve(self, record_id: str) -> MemoryRecord | None:
        """Fetch a single record by ID."""

    @abstractmethod
    def update(self, record_id: str, updates: dict[str, Any]) -> MemoryRecord | None:
        """Apply field updates to an existing record, returning the updated record."""

    @abstractmethod
    def delete(self, record_id: str) -> bool:
        """Hard-delete a record. Returns True if a record was removed."""

    @abstractmethod
    def search(
        self,
        query: str | MemoryQuery | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        """Deterministic structured retrieval with filters."""

    @abstractmethod
    def list(
        self,
        memory_type: MemoryType | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MemoryRecord]:
        """List records, newest first."""

    @abstractmethod
    def count(self, query: str | MemoryQuery | None = None) -> int:
        """Count records matching optional filters."""

    @abstractmethod
    def health_check(self) -> bool:
        """Non-destructive check that the backend is usable."""

    @abstractmethod
    def close(self) -> None:
        """Release any held resources. Idempotent-safe where applicable."""
