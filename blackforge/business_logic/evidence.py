from __future__ import annotations

import json

from blackforge.business_logic.models import (
    BusinessLogicHypothesisObservation,
    BusinessLogicMode,
    BusinessLogicValidationObservation,
    BusinessObservationKind,
    BusinessRuleObservation,
    Observation,
    OwnershipObservation,
    RoleBoundaryObservation,
    StateObservation,
    StateTransitionObservation,
    ValidationResult,
    WorkflowConsistencyObservation,
    WorkflowObservation,
    WorkflowReplayObservation,
)
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    ProvenanceType,
    SessionID,
)
from blackforge.evidence.models import Evidence, Provenance

_DIRECT_KIND_VALUES = frozenset(
    {"workflow", "state", "state_transition", "workflow_replay"}
)
_DERIVED_KIND_VALUES = frozenset({"ownership", "role_boundary", "workflow_consistency"})
_HYPOTHESIS_KIND_VALUES = frozenset({"business_logic_hypothesis"})
_VALIDATION_KIND_VALUES = frozenset({"business_logic_validation"})


def observation_confidence(
    observation: Observation, mode: BusinessLogicMode
) -> Confidence:
    """Confidence policy for business logic observations.

    * Anything observed without an active probe (``PASSIVE``) is LOW.
    * Direct active observations of a workflow, state, transition, or replay
      step are HIGH.
    * Derived analysis (ownership, role boundaries, consistency) is MEDIUM.
    * Hypotheses are LOW (HYPOTHESIZED evidence) — never findings by
      themselves.
    * Validated outcomes are HIGH; ``INVALIDATED``/``UNVERIFIABLE`` outcomes
      never elevate confidence.
    """
    if mode == BusinessLogicMode.PASSIVE:
        return Confidence.LOW
    if observation.kind in _DIRECT_KIND_VALUES:
        return Confidence.HIGH
    if observation.kind in _DERIVED_KIND_VALUES:
        return Confidence.MEDIUM
    if observation.kind in _HYPOTHESIS_KIND_VALUES:
        return Confidence.LOW
    if observation.kind in _VALIDATION_KIND_VALUES:
        if (
            isinstance(observation, BusinessLogicValidationObservation)
            and observation.result == ValidationResult.VALIDATED
        ):
            return Confidence.HIGH
        return Confidence.LOW
    return Confidence.LOW


def observation_summary(observation: Observation) -> str:
    """One-line human summary for a business logic observation."""
    if isinstance(observation, WorkflowObservation):
        return (
            f"Workflow {observation.workflow} on {observation.host} "
            f"states={len(observation.state_names)} actions={len(observation.action_names)}"
        )
    if isinstance(observation, StateObservation):
        return (
            f"State {observation.state} in {observation.workflow} on "
            f"{observation.host} initial={observation.initial} terminal={observation.terminal}"
        )
    if isinstance(observation, StateTransitionObservation):
        return (
            f"Transition {observation.action}:{observation.source_state}->"
            f"{observation.target_state} in {observation.workflow} on "
            f"{observation.host} anomalous={observation.anomalous}"
        )
    if isinstance(observation, BusinessRuleObservation):
        return (
            f"Business rule {observation.rule} in {observation.workflow} on "
            f"{observation.host} enforcement={observation.enforcement}"
        )
    if isinstance(observation, OwnershipObservation):
        return (
            f"Ownership of {observation.resource} by {observation.owner} in "
            f"{observation.workflow} on {observation.host} controlled={observation.controlled}"
        )
    if isinstance(observation, RoleBoundaryObservation):
        return (
            f"Role boundary {observation.role}/{observation.action} on "
            f"{observation.resource} in {observation.workflow} on {observation.host} "
            f"allowed={observation.allowed} consistent={observation.consistent}"
        )
    if isinstance(observation, WorkflowConsistencyObservation):
        return (
            f"Workflow consistency {observation.invariant}={observation.status} "
            f"in {observation.workflow} on {observation.host}"
        )
    if isinstance(observation, WorkflowReplayObservation):
        return (
            f"Replay step {observation.action} from {observation.source_state} in "
            f"{observation.workflow} on {observation.host} "
            f"result={observation.result.value} safety={observation.safety_class.value}"
        )
    if isinstance(observation, BusinessLogicHypothesisObservation):
        return (
            f"Hypothesis {observation.hypothesis} in {observation.workflow} on "
            f"{observation.host} outcome={observation.outcome.value}"
        )
    if isinstance(observation, BusinessLogicValidationObservation):
        return (
            f"Validation of {observation.hypothesis} in {observation.workflow} on "
            f"{observation.host} result={observation.result.value}"
        )
    return f"Business logic observation {observation.kind} on {observation.host}"


def observation_reference(observation: Observation) -> str:
    """Default evidence reference for an observation (its URL)."""
    return observation.url


def artifact_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    raw_output: str,
    *,
    session_id: SessionID | None = None,
    mode: BusinessLogicMode = BusinessLogicMode.ACTIVE,
    summary: str | None = None,
) -> Evidence:
    """Raw mock output preserved as authoritative ARTIFACT evidence."""
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.ARTIFACT,
        status=EvidenceStatus.OBSERVED,
        confidence=Confidence.HIGH,
        raw_data=raw_output,
        summary=summary
        or f"{capability_id} raw output for {target} (mock business logic transport)",
        reference=target,
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={"business_logic": True, "mode": mode.value},
    )


def observation_evidence(
    mission_id: MissionID,
    target: str,
    capability_id: str,
    observation: Observation,
    *,
    session_id: SessionID | None = None,
    mode: BusinessLogicMode = BusinessLogicMode.ACTIVE,
) -> Evidence:
    """Typed OBSERVATION evidence derived from a normalized observation.

    Broken business rules and violated invariants are recorded as INFERRED,
    never OBSERVED — a modeled deviation is not presumed real until the
    validation step elevates it to VALIDATED.
    """
    status = _evidence_status_for(observation)
    return Evidence(
        mission_id=mission_id,
        session_id=session_id,
        source_capability=capability_id,
        target=target,
        evidence_type=EvidenceType.OBSERVATION,
        status=status,
        confidence=observation_confidence(observation, mode),
        raw_data=json.dumps(observation.model_dump(), sort_keys=True),
        summary=observation_summary(observation),
        reference=observation_reference(observation),
        provenance=Provenance(
            capability_id=capability_id,
            provenance_type=ProvenanceType.DIRECT,
        ),
        metadata={
            "business_logic": True,
            "mode": mode.value,
            "kind": observation.kind,
        },
    )


def evidence_dedup_key_for(evidence: Evidence) -> str:
    """Idempotency key reused across runs so identical observations dedup."""
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


def existing_evidence_id(evidence_store, evidence: Evidence) -> EvidenceID | None:
    """Return the stored id when an equivalent record already exists."""
    existing = evidence_store.repository.get_by_dedup_key(
        evidence_dedup_key_for(evidence)
    )
    return existing.id if existing is not None else None


def _evidence_status_for(observation: Observation) -> EvidenceStatus:
    if observation.kind in {
        BusinessObservationKind.BUSINESS_LOGIC_HYPOTHESIS.value,
    }:
        return EvidenceStatus.HYPOTHESIZED
    if isinstance(observation, BusinessLogicValidationObservation):
        if observation.result == ValidationResult.VALIDATED:
            return EvidenceStatus.VALIDATED
        return EvidenceStatus.INFERRED
    if isinstance(observation, BusinessRuleObservation):
        if observation.enforcement == "broken":
            return EvidenceStatus.INFERRED
        return EvidenceStatus.OBSERVED
    if isinstance(observation, WorkflowConsistencyObservation):
        if observation.status == "violated":
            return EvidenceStatus.INFERRED
        return EvidenceStatus.OBSERVED
    if isinstance(observation, StateTransitionObservation):
        if observation.anomalous:
            return EvidenceStatus.INFERRED
        return EvidenceStatus.OBSERVED
    return EvidenceStatus.OBSERVED
