from __future__ import annotations

from pydantic import BaseModel, Field

from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    ProvenanceType,
    TaskID,
)


class Provenance(BaseModel):
    capability_id: str | None = None
    task_id: TaskID | None = None
    input_hash: str | None = None
    output_hash: str | None = None
    provenance_type: ProvenanceType = ProvenanceType.DIRECT
    parent_evidence_id: EvidenceID | None = None


class Evidence(BaseModel):
    id: EvidenceID = Field(default_factory=EvidenceID)
    mission_id: MissionID
    task_id: TaskID | None = None
    timestamp: float = Field(default_factory=lambda: __import__("time").time())
    source_capability: str
    target: str
    evidence_type: EvidenceType
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    confidence: Confidence = Confidence.MEDIUM
    raw_data: str | None = None
    reference: str | None = None
    provenance: Provenance = Field(default_factory=Provenance)
    metadata: dict = Field(default_factory=dict)
