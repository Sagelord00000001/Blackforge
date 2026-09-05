from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaMode
from pydantic_core import core_schema


def _gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class _IDStr(str):
    """String subclass with pydantic v2 support via __get_pydantic_core_schema__."""

    _prefix: str = ""

    def __new__(cls, value: str | None = None) -> _IDStr:
        return super().__new__(cls, value or _gen_id(cls._prefix))

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: str(v)
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, _core_schema: Any, handler: GetJsonSchemaHandler
    ) -> dict[str, Any]:
        return {"type": "string"}

    @classmethod
    def _validate(cls, v: Any) -> _IDStr:
        if isinstance(v, cls):
            return v
        return cls(str(v))


class MissionID(_IDStr):
    _prefix = "mission"


class TaskID(_IDStr):
    _prefix = "task"


class EvidenceID(_IDStr):
    _prefix = "ev"


class FindingID(_IDStr):
    _prefix = "find"


class RelationshipID(_IDStr):
    _prefix = "rel"


class WorldEntityID(_IDStr):
    _prefix = "went"


class WorldRelationshipID(_IDStr):
    _prefix = "wrel"


class WorldAssertionID(_IDStr):
    _prefix = "wast"


class CapabilityID(_IDStr):
    _prefix = "cap"


class AssetID(_IDStr):
    _prefix = "asset"


class MemoryID(_IDStr):
    _prefix = "mem"


class SessionID(_IDStr):
    _prefix = "sess"


class MissionStatus(str, Enum):
    CREATED = "created"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class EvidenceType(str, Enum):
    OBSERVATION = "observation"
    ARTIFACT = "artifact"
    REQUEST = "request"
    RESPONSE = "response"
    SCREENSHOT = "screenshot"
    LOG = "log"
    COMMAND_RESULT = "command_result"
    SOURCE_ANALYSIS = "source_analysis"
    VALIDATION_RESULT = "validation_result"


class EvidenceStatus(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    HYPOTHESIZED = "hypothesized"
    VALIDATED = "validated"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

    def to_score(self) -> float:
        """Deterministic numeric mapping used at the evidence <-> memory boundary.

        ``score`` is authoritative for numeric bridges; ``confidence`` stays
        an enum on evidence to preserve Phase 1/2 compatibility.
        """
        return {"low": 0.3, "medium": 0.5, "high": 0.8, "confirmed": 0.95}[self.value]

    @classmethod
    def from_score(cls, score: float) -> Confidence:
        """Inverse: map a numeric score back to the nearest confidence level."""
        if score <= 0.4:
            return cls.LOW
        if score <= 0.65:
            return cls.MEDIUM
        if score <= 0.9:
            return cls.HIGH
        return cls.CONFIRMED


class ProvenanceType(str, Enum):
    DIRECT = "direct"
    DERIVED = "derived"
    REPORTED = "reported"
    INFERRED = "inferred"


class RiskLevel(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthorizationDecision(str, Enum):
    AUTHORIZED = "authorized"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


class TaskCategory(str, Enum):
    EXTRACTION = "extraction"
    CLASSIFICATION = "classification"
    ANALYSIS = "analysis"
    PLANNING = "planning"
    SECURITY_REASONING = "security_reasoning"
    SUMMARIZATION = "summarization"


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    APPLICATION = "application"
    ASSET = "asset"


class TimestampedModel(BaseModel):
    created_at: float = Field(default_factory=lambda: time.time())
    updated_at: float | None = None

    def touch(self) -> None:
        self.updated_at = time.time()
