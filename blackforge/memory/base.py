from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from blackforge.core.types import TimestampedModel


class MemoryType(str, Enum):
    WORKING = "working"
    KNOWLEDGE = "knowledge"
    EXPERIENCE = "experience"
    EVIDENCE = "evidence"


class MemoryRecord(BaseModel):
    id: str = ""
    memory_type: MemoryType
    key: str
    content: Any = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    created_at: float = Field(default_factory=lambda: __import__("time").time())
    updated_at: float | None = None


class MemoryBackend(ABC):
    @abstractmethod
    def store(self, record: MemoryRecord) -> str:
        ...

    @abstractmethod
    def retrieve(self, record_id: str) -> MemoryRecord | None:
        ...

    @abstractmethod
    def update(self, record_id: str, updates: dict[str, Any]) -> MemoryRecord | None:
        ...

    @abstractmethod
    def delete(self, record_id: str) -> bool:
        ...

    @abstractmethod
    def search(
        self,
        query: str | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[MemoryRecord]:
        ...
