from __future__ import annotations

from typing import TYPE_CHECKING, Any

from blackforge.core.logging import get_logger
from blackforge.core.types import EvidenceID, EvidenceStatus, ProvenanceType
from blackforge.evidence.models import Evidence
from blackforge.memory.base import MemoryRecord, MemoryType
from blackforge.memory.provenance import MemoryProvenance, MemorySource

if TYPE_CHECKING:
    from blackforge.evidence.store import EvidenceStore
    from blackforge.memory.manager import MemoryManager

log = get_logger("evidence.bridge")


def map_memory_source(evidence: Evidence) -> MemorySource:
    """Deterministic mapping from evidence to a memory source tag.

    Directly observed output from a capability is a capability execution or
    observation; derived/inferred provenance is LLM inference; validated
    output maps to a validated experiment. The mapping never upgrades the
    epistemic standing of the record.
    """
    if evidence.status == EvidenceStatus.VALIDATED:
        return MemorySource.VALIDATED_EXPERIMENT
    if evidence.provenance.provenance_type in (
        ProvenanceType.DERIVED,
        ProvenanceType.INFERRED,
    ):
        return MemorySource.LLM_INFERENCE
    return MemorySource.CAPABILITY_EXECUTION


def default_memory_content(evidence: Evidence) -> dict[str, Any]:
    """Compact memory snapshot — references, never a copy of large artifacts.

    Full evidence stays authoritative in the evidence store; memory keeps a
    lightweight reference plus an optional summary.
    """
    return {
        "evidence_id": str(evidence.id),
        "target": evidence.target,
        "summary": evidence.summary,
    }


class EvidenceMemoryBridge:
    """Controlled, traceable link between authoritative evidence and memory.

    * ``materialize_memory`` creates a persistent memory record from evidence,
      preserving status, confidence, mission/session context, provenance and
      an explicit evidence reference.
    * Reverse lookups answer "which memory supports this evidence?" and
      "which evidence supports this memory?" through lightweight references.

    Transaction boundary: evidence and memory use separate SQLite files, so a
    single cross-store transaction is NOT claimed. The bridge writes evidence
    first (authoritative) and memory second; if the memory write fails the
    in-memory engine rolls its transaction back and the bridge compensates by
    removing the just-created memory record so no orphan/partial state remains
    within a process. Documented in ``docs/evidence.md``.
    """

    def __init__(
        self,
        evidence_store: EvidenceStore,
        memory: MemoryManager,
    ) -> None:
        self.evidence_store = evidence_store
        self.memory = memory

    def materialize_memory(
        self,
        evidence_or_id: Evidence | EvidenceID | str,
        *,
        memory_type: MemoryType = MemoryType.KNOWLEDGE,
        key: str | None = None,
        content: Any | None = None,
        meta: dict | None = None,
    ) -> MemoryRecord | None:
        """Create a persistent memory record that references the evidence.

        ``content`` may be overridden; by default a compact reference snapshot
        is used. ``key`` defaults to ``<target>:<evidence_type>``. The record
        inherits the evidence's epistemic status, confidence score, mission
        and session context. Returns the stored record, or ``None`` when the
        evidence does not exist.
        """
        evidence = self._resolve_evidence(evidence_or_id)
        if evidence is None:
            return None
        record = self._build_record(
            evidence,
            memory_type=memory_type,
            key=key,
            content=content,
            meta=meta,
        )
        memory_id = self.memory.store(record)
        return self.memory.retrieve(memory_id)

    def memory_for_evidence(
        self, evidence_or_id: Evidence | EvidenceID | str
    ) -> list[MemoryRecord]:
        """Memory records that reference the given evidence."""
        evidence = self._resolve_evidence(evidence_or_id)
        if evidence is None:
            return []
        return self.memory.find_by_evidence_id(str(evidence.id))

    def evidence_for_memory(
        self,
        record_or_id: MemoryRecord | str,
    ) -> list[Evidence]:
        """Evidence referenced by a memory record (the authoritative support)."""
        record = self._resolve_memory(record_or_id)
        if record is None:
            return []
        return [
            self.evidence_store.get(eid)
            for eid in record.evidence_ids
            if self.evidence_store.get(eid) is not None
        ]

    def create_evidence_and_memory(
        self,
        evidence: Evidence,
        *,
        memory_type: MemoryType = MemoryType.KNOWLEDGE,
        key: str | None = None,
        content: Any | None = None,
        meta: dict | None = None,
    ) -> tuple[Evidence, MemoryRecord | None]:
        """Store evidence, then materialize a referencing memory record.

        The evidence is authoritative: it is stored first. If memory
        materialization fails, the just-created memory record is rolled back
        and the exception re-raised, leaving no partially linked state inside
        the process (see module docstring for the boundary).
        """
        stored = self.evidence_store.add(evidence)
        try:
            record = self.materialize_memory(
                stored,
                memory_type=memory_type,
                key=key,
                content=content,
                meta=meta,
            )
        except Exception:
            self._cleanup_memory(stored)
            raise
        return stored, record

    # ------------------------------------------------------------------

    def _build_record(
        self,
        evidence: Evidence,
        *,
        memory_type: MemoryType,
        key: str | None,
        content: Any | None,
        meta: dict | None,
    ) -> MemoryRecord:
        record_key = key or f"{evidence.target}:{evidence.evidence_type.value}"
        source = map_memory_source(evidence)
        return MemoryRecord(
            memory_type=memory_type,
            key=record_key,
            content=content if content is not None else default_memory_content(evidence),
            status=evidence.status,
            confidence=evidence.confidence.to_score(),
            mission_id=evidence.mission_id,
            session_id=evidence.session_id,
            source=source,
            provenance=MemoryProvenance(
                source=source,
                source_detail=str(evidence.id),
                provenance_type=evidence.provenance.provenance_type,
                task_id=evidence.provenance.task_id,
                capability_id=evidence.provenance.capability_id or evidence.source_capability,
                input_hash=evidence.provenance.input_hash,
                output_hash=evidence.provenance.output_hash,
                evidence_ids=[str(evidence.id)],
                recorded_at=_now(),
            ),
            evidence_ids=[evidence.id],
            tags=[evidence.evidence_type.value],
            metadata=dict(meta or {}) | {"evidence_type": evidence.evidence_type.value},
        )

    def _resolve_evidence(self, value: Evidence | EvidenceID | str) -> Evidence | None:
        if isinstance(value, Evidence):
            return value
        return self.evidence_store.get(value)

    def _resolve_memory(self, value: MemoryRecord | str) -> MemoryRecord | None:
        if isinstance(value, MemoryRecord):
            return value
        return self.memory.retrieve(value)

    def _cleanup_memory(self, evidence: Evidence) -> None:
        created = self.memory.find_by_evidence_id(str(evidence.id))
        for rec in created:
            self.memory.delete(str(rec.id))


def _now() -> float:
    import time

    return time.time()
