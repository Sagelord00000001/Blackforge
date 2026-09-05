from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.core.errors import EvidenceRuleError
from blackforge.core.logging import get_logger
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    ProvenanceType,
    SessionID,
)
from blackforge.evidence.models import (
    ConfidenceChange,
    Evidence,
    EvidenceLifecycle,
    EvidenceLink,
    EvidenceRelation,
    EvidenceRelationship,
    Provenance,
)
from blackforge.evidence.repository import (
    EvidenceRepository,
    InMemoryEvidenceRepository,
    compute_evidence_dedup_key,
    evidence_dedup_content,
)
from blackforge.evidence.rules import can_transition_status

if TYPE_CHECKING:
    from blackforge.evidence.query import EvidenceQuery

log = get_logger("evidence.store")


class EvidenceStore:
    """Application-facing evidence controller.

    Evidence is authoritative and auditable. This facade enforces the
    transition rules: nothing may reach ``VALIDATED`` without a validation
    workflow, and lifecycle operations (supersede/invalidate/archive) never
    rewrite the epistemic record. The legacy in-memory-only API
    (``add``/``get``/``get_by_mission``/``count``) is preserved.
    """

    def __init__(self, repository: EvidenceRepository | None = None) -> None:
        self._repo: EvidenceRepository = repository or InMemoryEvidenceRepository()

    @property
    def repository(self) -> EvidenceRepository:
        return self._repo

    def add(self, evidence: Evidence, *, via_validation: bool = False) -> Evidence:
        """Store evidence, applying dedup and status rules.

        Creation of ``VALIDATED`` evidence is reserved for a validation
        workflow (``via_validation=True``). Identical evidence (same
        mission/target/capability/type/payload) is de-duplicated
        deterministically; the existing record is returned.
        """
        with self._repo.transaction():
            return self._add(evidence, via_validation=via_validation)

    def add_claim(
        self,
        mission_id: MissionID,
        claim: str,
        *,
        session_id: SessionID | None = None,
        source_capability: str = "llm_inference",
        target: str = "",
        confidence: Confidence = Confidence.LOW,
        evidence_type: EvidenceType = EvidenceType.OBSERVATION,
        metadata: dict | None = None,
    ) -> Evidence:
        """Record an LLM/analysis claim as HYPOTHESIZED evidence.

        LLM or reasoning output never becomes authoritative evidence on its
        own: it enters as a hypothesis and can only reach ``VALIDATED``
        through an authorized validation workflow.
        """
        evidence = Evidence(
            mission_id=mission_id,
            session_id=session_id,
            source_capability=source_capability,
            target=target or "llm_claim",
            evidence_type=evidence_type,
            status=EvidenceStatus.HYPOTHESIZED,
            confidence=confidence,
            raw_data=claim,
            summary=claim,
            provenance=Provenance(
                capability_id=source_capability,
                provenance_type=ProvenanceType.INFERRED,
            ),
            metadata=dict(metadata or {}),
        )
        return self.add(evidence)

    def add_validation(
        self,
        mission_id: MissionID,
        target: str,
        result: str,
        *,
        source_capability: str,
        session_id: SessionID | None = None,
        confidence: Confidence = Confidence.HIGH,
        validates_id: EvidenceID | None = None,
        metadata: dict | None = None,
    ) -> Evidence:
        """Record the output of an authorized validation workflow.

        This is the only path that creates ``VALIDATED`` evidence a
        hypothesis can be confirmed against; the ``VALIDATES`` relationship
        is recorded when ``validates_id`` is given.
        """
        evidence = Evidence(
            mission_id=mission_id,
            session_id=session_id,
            source_capability=source_capability,
            target=target,
            evidence_type=EvidenceType.VALIDATION_RESULT,
            status=EvidenceStatus.VALIDATED,
            confidence=confidence,
            raw_data=result,
            summary=result,
            provenance=Provenance(
                capability_id=source_capability,
                provenance_type=ProvenanceType.DIRECT,
            ),
            metadata=dict(metadata or {}),
        )
        with self._repo.transaction():
            stored = self._add(evidence, via_validation=True)
            if validates_id is not None:
                if self._repo.retrieve(validates_id) is None:
                    raise EvidenceRuleError(
                        f"Cannot validate unknown evidence {validates_id}"
                    )
                self._repo.add_relationship(
                    stored.id,
                    EvidenceRelation.VALIDATES,
                    validates_id,
                )
        return stored

    def get(self, evidence_id: EvidenceID | str) -> Evidence | None:
        return self._repo.retrieve(evidence_id)

    def get_by_mission(self, mission_id: MissionID) -> list[Evidence]:
        return self._repo.get_by_mission(mission_id)

    def count(self, mission_id: MissionID | None = None) -> int:
        if mission_id:
            return len(self._repo.get_by_mission(mission_id))
        return self._repo.count()

    def search(self, query: EvidenceQuery) -> list[Evidence]:
        return self._repo.search(query)

    def list(self, limit: int = 50, offset: int = 0) -> list[Evidence]:
        return self._repo.list(limit, offset)

    # ------------------------------------------------------------------
    # Lifecycle operations — these never rewrite epistemic status.
    # ------------------------------------------------------------------

    def transition_status(
        self,
        evidence_id: EvidenceID | str,
        target: EvidenceStatus,
        *,
        via_validation: bool = False,
    ) -> Evidence:
        """Apply a status transition under the deterministic transition rules."""
        evidence = self._require(evidence_id)
        if not can_transition_status(
            evidence.status, target, via_validation=via_validation
        ):
            hint = (
                " (needs an authorized validation workflow)"
                if target == EvidenceStatus.VALIDATED
                else ""
            )
            raise EvidenceRuleError(
                f"Invalid status transition: {evidence.status.value} -> "
                f"{target.value}{hint}"
            )
        evidence.status = target
        evidence.updated_at = time.time()
        if target == EvidenceStatus.VALIDATED:
            log.info(
                "evidence_validated",
                evidence_id=str(evidence.id),
                via_validation=via_validation,
            )
        self._repo.store(evidence)
        return evidence

    def adjust_confidence(
        self,
        evidence_id: EvidenceID | str,
        new_confidence: Confidence,
        *,
        reason: str,
    ) -> Evidence:
        """Change confidence with an audited, provenance-explained reason.

        Confidence is independent of status: raising confidence never changes
        status. Each change is appended to ``confidence_changes`` history.
        """
        evidence = self._require(evidence_id)
        if evidence.confidence != new_confidence:
            evidence.confidence_changes.append(
                ConfidenceChange(
                    previous=evidence.confidence,
                    new=new_confidence,
                    reason=reason,
                    changed_at=time.time(),
                )
            )
            evidence.confidence = new_confidence
            evidence.updated_at = time.time()
            self._repo.store(evidence)
        return evidence

    def archive(self, evidence_id: EvidenceID | str) -> Evidence:
        return self._set_lifecycle(evidence_id, EvidenceLifecycle.ARCHIVED)

    def supersede(
        self,
        old_id: EvidenceID | str,
        new_id: EvidenceID | str,
        *,
        note: str | None = None,
    ) -> Evidence:
        """Mark ``old_id`` as SUPERSEDED, linked by ``new_id SUPERSEDES old_id``."""
        with self._repo.transaction():
            old = self._require(old_id)
            new_ev = self._repo.retrieve(new_id)
            if new_ev is None:
                raise EvidenceRuleError(
                    f"Cannot supersede with unknown evidence {new_id}"
                )
            old.lifecycle = EvidenceLifecycle.SUPERSEDED
            old.updated_at = time.time()
            self._repo.store(old)
            self._repo.add_relationship(
                new_id, EvidenceRelation.SUPERSEDES, old_id, note=note
            )
        return old

    def invalidate(
        self,
        evidence_id: EvidenceID | str,
        *,
        reason: str | None = None,
        causing_evidence_id: EvidenceID | str | None = None,
    ) -> Evidence:
        """Mark evidence INVALIDATED without destroying its history."""
        with self._repo.transaction():
            evidence = self._require(evidence_id)
            evidence.lifecycle = EvidenceLifecycle.INVALIDATED
            evidence.updated_at = time.time()
            if reason:
                evidence.metadata["invalidated_reason"] = reason
            self._repo.store(evidence)
            if causing_evidence_id is not None:
                self._repo.add_relationship(
                    causing_evidence_id,
                    EvidenceRelation.INVALIDATES,
                    evidence_id,
                )
        return evidence

    def contradict(
        self,
        existing_id: EvidenceID | str,
        new_evidence: Evidence,
        *,
        supersede: bool = False,
    ) -> tuple[Evidence, Evidence]:
        """Record contradictory evidence without deleting the original.

        * ``supersede=False`` — both records stay ACTIVE; a
          ``new CONTRADICTS existing`` relationship is recorded and the system
          does not arbitrate correctness without explicit validation.
        * ``supersede=True`` — the existing record is marked SUPERSEDED and
          the relationship is ``SUPERSEDES``.
        """
        existing = self._require(existing_id)
        with self._repo.transaction():
            if supersede:
                self._repo.store(new_evidence)
                existing.lifecycle = EvidenceLifecycle.SUPERSEDED
                existing.updated_at = time.time()
                self._repo.store(existing)
                self._repo.add_relationship(
                    new_evidence.id,
                    EvidenceRelation.SUPERSEDES,
                    existing_id,
                )
            else:
                stored_new = self._add(new_evidence)
                self._repo.add_relationship(
                    stored_new.id,
                    EvidenceRelation.CONTRADICTS,
                    existing_id,
                )
        return existing, new_evidence

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def add_relationship(
        self,
        source_id: EvidenceID | str,
        relation_type: EvidenceRelation,
        target_id: EvidenceID | str,
        *,
        note: str | None = None,
    ) -> EvidenceRelationship:
        return self._repo.add_relationship(
            source_id, relation_type, target_id, note=note
        )

    def get_relationships(
        self, evidence_id: EvidenceID | str
    ) -> list[EvidenceRelationship]:
        return self._repo.get_relationships(evidence_id)

    def related_evidence(
        self,
        evidence_id: EvidenceID | str,
        relation_type: EvidenceRelation | None = None,
    ) -> list[EvidenceLink]:
        return self._repo.related_evidence(evidence_id, relation_type)

    # ------------------------------------------------------------------
    # Health / lifecycle
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        return self._repo.health_check()

    def close(self) -> None:
        self._repo.close()

    # ------------------------------------------------------------------
    # Internal helpers — callers already hold the repository transaction lock.
    # ------------------------------------------------------------------

    def _add(self, evidence: Evidence, *, via_validation: bool = False) -> Evidence:
        if evidence.status == EvidenceStatus.VALIDATED and not via_validation:
            raise EvidenceRuleError(
                "Only a validation workflow may create VALIDATED evidence; "
                "LLM claims must start as hypotheses."
            )
        evidence.dedup_key = evidence.dedup_key or compute_evidence_dedup_key(
            evidence.mission_id,
            evidence.target,
            evidence.source_capability,
            evidence.evidence_type,
            evidence_dedup_content(evidence),
        )
        existing = self._repo.get_by_dedup_key(evidence.dedup_key)
        if existing is not None:
            log.debug(
                "evidence_dedup_noop",
                evidence_id=str(existing.id),
                dedup_key=evidence.dedup_key,
            )
            return existing
        self._repo.store(evidence)
        log.info(
            "evidence_stored",
            evidence_id=str(evidence.id),
            mission_id=str(evidence.mission_id),
            type=evidence.evidence_type.value,
            status=evidence.status.value,
            lifecycle=evidence.lifecycle.value,
        )
        return evidence

    def _require(self, evidence_id: EvidenceID | str) -> Evidence:
        evidence = self._repo.retrieve(evidence_id)
        if evidence is None:
            raise EvidenceRuleError(f"Unknown evidence: {evidence_id}")
        return evidence

    def _set_lifecycle(
        self, evidence_id: EvidenceID | str, lifecycle: EvidenceLifecycle
    ) -> Evidence:
        with self._repo.transaction():
            evidence = self._require(evidence_id)
            evidence.lifecycle = lifecycle
            evidence.updated_at = time.time()
            self._repo.store(evidence)
        return evidence
