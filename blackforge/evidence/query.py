from pydantic import BaseModel

from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    SessionID,
)
from blackforge.evidence.models import EvidenceLifecycle, EvidenceRelation


class EvidenceQuery(BaseModel):
    """Deterministic, structured retrieval filters for evidence.

    SQLite-backed stores translate these into parameterized ``WHERE``
    clauses. ``limit``/``offset`` provide deterministic paging (results are
    ordered newest-first).
    """

    mission_id: MissionID | None = None
    session_id: SessionID | None = None
    status: EvidenceStatus | None = None
    lifecycle: EvidenceLifecycle | None = None
    source_capability: str | None = None
    evidence_type: EvidenceType | None = None
    confidence: Confidence | None = None
    created_after: float | None = None
    created_before: float | None = None
    keyword: str | None = None
    related_to: EvidenceID | None = None
    relation_type: EvidenceRelation | None = None
    limit: int = 50
    offset: int = 0
