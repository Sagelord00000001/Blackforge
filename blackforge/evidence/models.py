from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, Field

from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    ProvenanceType,
    RelationshipID,
    SessionID,
    TaskID,
)


class Provenance(BaseModel):
    capability_id: str | None = None
    task_id: TaskID | None = None
    input_hash: str | None = None
    output_hash: str | None = None
    provenance_type: ProvenanceType = ProvenanceType.DIRECT
    parent_evidence_id: EvidenceID | None = None


class EvidenceLifecycle(str, Enum):
    """Lifecycle of an evidence record — distinct from its epistemic status.

    ``EvidenceStatus`` answers *how we know* (observed/inferred/hypothesized/
    validated). ``EvidenceLifecycle`` answers *what is the record's lifecycle
    state* (active/superseded/invalidated/archived). A record can be
    ``VALIDATED`` yet later ``SUPERSEDED`` or ``INVALIDATED``; the history
    remains visible instead of being destructively overwritten.
    """

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    INVALIDATED = "invalidated"
    ARCHIVED = "archived"


class EvidenceRelation(str, Enum):
    """Typed, queryable relationships between evidence records.

    These are evidence-level links, not attack-graph edges.
    """

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    DERIVED_FROM = "derived_from"
    VALIDATES = "validates"
    INVALIDATES = "invalidates"
    SUPERSEDES = "supersedes"
    CORROBORATES = "corroborates"
    RELATED_TO = "related_to"


class ConfidenceChange(BaseModel):
    """Audited confidence adjustment. Confidence changes must be explainable."""

    previous: Confidence
    new: Confidence
    reason: str
    changed_at: float = Field(default_factory=time.time)


class EvidenceRelationship(BaseModel):
    """A directed, typed edge between two evidence records."""

    id: RelationshipID = Field(default_factory=RelationshipID)
    source_id: EvidenceID
    relation_type: EvidenceRelation
    target_id: EvidenceID
    note: str | None = None
    created_at: float = Field(default_factory=time.time)


class EvidenceLink(BaseModel):
    """A relationship paired with the counterpart evidence, for retrieval."""

    relation: EvidenceRelation
    evidence: Evidence
    direction: str


class Evidence(BaseModel):
    """A single auditable piece of evidence.

    Evidence is authoritative and effectively immutable: the epistemic
    ``status`` changes only through the transition rules in the evidence
    controller, the ``lifecycle`` only through lifecycle operations, and
    core content is never destructively overwritten.
    """

    id: EvidenceID = Field(default_factory=EvidenceID)
    mission_id: MissionID
    session_id: SessionID | None = None
    task_id: TaskID | None = None
    timestamp: float = Field(default_factory=lambda: __import__("time").time())
    updated_at: float | None = None
    source_capability: str
    target: str
    evidence_type: EvidenceType
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    lifecycle: EvidenceLifecycle = EvidenceLifecycle.ACTIVE
    confidence: Confidence = Confidence.MEDIUM
    confidence_changes: list[ConfidenceChange] = Field(default_factory=list)
    raw_data: str | None = None
    summary: str | None = None
    reference: str | None = None
    dedup_key: str | None = None
    provenance: Provenance = Field(default_factory=Provenance)
    metadata: dict = Field(default_factory=dict)
