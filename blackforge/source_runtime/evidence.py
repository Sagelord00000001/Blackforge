from __future__ import annotations

import json

from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    ProvenanceType,
    SessionID,
)
from blackforge.evidence.models import Evidence, EvidenceRelation, Provenance
from blackforge.source_runtime.models import (
    CorrelatedIdentity,
    CorrelationOutcome,
    CorrelationResult,
    SourceRuntimeMode,
)
from blackforge.source_runtime.redaction import redact_source_runtime_raw


def source_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    record: dict,
    *,
    session_id: SessionID | None = None,
    confidence: Confidence = Confidence.MEDIUM,
) -> Evidence:
    """Evidence for the DECLARED (source) side.

    Stored as a ``SOURCE_ANALYSIS`` artifact so it cannot be confused with a
    live observation; the raw fixture document is redacted before persistence.
    """
    redacted = redact_source_runtime_raw(json.dumps(record, sort_keys=True, default=str))
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.SOURCE_ANALYSIS,
        status=EvidenceStatus.OBSERVED,
        confidence=confidence,
        raw_data=redacted,
        summary=f"{capability_id} declared source record for {target} (source side)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"source_runtime_side": "source", "correlation": True},
    )


def runtime_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    record: dict,
    *,
    session_id: SessionID | None = None,
    confidence: Confidence = Confidence.MEDIUM,
) -> Evidence:
    """Evidence for the OBSERVED (runtime) side.

    Independent from the source evidence: it reflects only the live/observed
    side and never replaces or re-authors the declared state.
    """
    redacted = redact_source_runtime_raw(json.dumps(record, sort_keys=True, default=str))
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.OBSERVATION,
        status=EvidenceStatus.OBSERVED,
        confidence=confidence,
        raw_data=redacted,
        summary=f"{capability_id} observed runtime record for {target} (runtime side)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"source_runtime_side": "runtime", "correlation": True},
    )


def correlation_confidence(
    source_conf: Confidence, runtime_conf: Confidence
) -> Confidence:
    """The correlation confidence can never exceed the weaker side.

    LOW + LOW never upgrades to HIGH; the comparison carries only the weaker
    side's confidence (conservative, deterministic floor).
    """
    if source_conf.to_score() <= runtime_conf.to_score():
        return source_conf
    return runtime_conf


def evidence_dedup_key_for(evidence: Evidence) -> str:
    """Idempotency key reused across runs so identical correlation dedups."""
    from blackforge.evidence.repository import (
        compute_evidence_dedup_key,
        evidence_dedup_content,
    )

    return compute_evidence_dedup_key(
        evidence.mission_id,
        evidence.target,
        evidence.source_capability,
        evidence.evidence_type,
        evidence_dedup_content(evidence),
    )


def existing_evidence_id(evidence_store, evidence: Evidence):
    """Return the stored id when an equivalent record already exists."""
    existing = evidence_store.repository.get_by_dedup_key(
        evidence_dedup_key_for(evidence)
    )
    return existing.id if existing is not None else None


def correlation_outcome_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    outcome: CorrelationOutcome,
    *,
    session_id: SessionID | None = None,
    mode: SourceRuntimeMode = SourceRuntimeMode.CONTROLLED,
    source_evidence_id: EvidenceID | None = None,
    runtime_evidence_id: EvidenceID | None = None,
) -> Evidence:
    """DERIVED evidence for one correlation outcome.

    The result is stored as a derived record (``DERIVED`` provenance) and
    references the independent source & runtime evidence it came from so the
    correlation remains traceable to both sides plus the rule that produced it.
    """
    payload = {
        "mode": mode.value,
        "result": outcome.result.value if outcome.result else None,
        "identity": outcome.identity.identity,
        "confidence": outcome.confidence.value if outcome.confidence else None,
        "source_evidence_id": str(source_evidence_id) if source_evidence_id else None,
        "runtime_evidence_id": str(runtime_evidence_id) if runtime_evidence_id else None,
        "comparisons": [
            {
                "property": c.property,
                "result": c.result.value if c.result else None,
                "source_value": c.source_value,
                "runtime_value": c.runtime_value,
                "rule_id": c.rule.rule_id if c.rule else None,
                "rule_version": c.rule.version if c.rule else None,
            }
            for c in outcome.comparisons
        ],
    }
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.VALIDATION_RESULT,
        status=EvidenceStatus.INFERRED,
        confidence=outcome.confidence,
        raw_data=json.dumps(payload, sort_keys=True, default=str),
        summary=(
            f"{capability_id} correlation result={outcome.result.value if outcome.result else '?'} "
            f"identity={outcome.identity.identity}"
        ),
        reference=outcome.identity.identity,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DERIVED,
            parent_evidence_id=source_evidence_id,
        ),
        metadata={
            "correlation": True,
            "result": outcome.result.value if outcome.result else None,
            "source_evidence_id": str(source_evidence_id) if source_evidence_id else None,
            "runtime_evidence_id": str(runtime_evidence_id) if runtime_evidence_id else None,
        },
    )


def link_correlation_evidence(
    evidence_store,
    correlation_id: EvidenceID,
    source_id: EvidenceID,
    runtime_id: EvidenceID,
    *,
    result: CorrelationResult,
    identity: CorrelatedIdentity,
) -> None:
    """Attach DERIVED_FROM edges from the correlation to both independent sides.

    The correlation evidence is derived from BOTH the source and the runtime
    evidence; neither side is mutated.
    """
    evidence_store.add_relationship(
        correlation_id,
        EvidenceRelation.DERIVED_FROM,
        source_id,
        note=f"correlation {result.value} derived from declared source {identity.identity}",
    )
    evidence_store.add_relationship(
        correlation_id,
        EvidenceRelation.DERIVED_FROM,
        runtime_id,
        note=f"correlation {result.value} derived from observed runtime {identity.identity}",
    )


__all__ = [
    "correlation_confidence",
    "correlation_outcome_evidence",
    "evidence_dedup_key_for",
    "existing_evidence_id",
    "link_correlation_evidence",
    "runtime_evidence",
    "source_evidence",
]
