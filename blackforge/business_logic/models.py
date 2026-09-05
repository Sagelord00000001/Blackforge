from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class BusinessLogicMode(str, Enum):
    """How business logic observation operates on a target.

    * ``PASSIVE`` — inference only: document/paper-model-derived analysis
      that never exercises the target's state machine.
    * ``ACTIVE`` — direct, deterministic observation against the (authorized)
      mock target: structural inventory, transition replay, ownership and
      role-boundary comparison using explicitly authorized test identities.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class BusinessLogicStatus(str, Enum):
    """Failure-aware outcomes for a business logic capability execution.

    Every run terminates in one of these states; negative outcomes (target
    unreachable, rate limited, no evidence) are recorded as structured
    results rather than silent failures. Failure states never become findings.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    LIMITED = "limited"
    NO_EVIDENCE = "no_evidence"
    REQUEST_FAILED = "request_failed"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"
    OUT_OF_SCOPE = "out_of_scope"
    MALFORMED_RESPONSE = "malformed_response"
    TIMEOUT = "timeout"
    FAILED = "failed"


class ReplaySafetyClass(str, Enum):
    """Safety classification gate for every replayable business action.

    * ``PASSIVE`` — the action only mutates a local mock counter (create,
      confirm). No side effects of interest.
    * ``BOUNDED`` — the action advances the (mock) state machine within the
      authorized first-party workflow. Replay is small, deterministic, and
      evidence-capturing.
    * ``PROHIBITED`` — the action is outside the replay envelope. Replay is
      rejected fail-closed; nothing that would cross an authorization, payment
      settlement, or destructive boundary is ever replayed.
    """

    PASSIVE = "passive"
    BOUNDED = "bounded"
    PROHIBITED = "prohibited"


class TransitionResult(str, Enum):
    """Outcome of a single replay step against the modeled state machine.

    * ``SUCCESS`` — the action applied and matched the modeled transition.
    * ``UNEXPECTED_TRANSITION`` — the observed target differs from the modeled
      target for this action/source pair (a recorded deviation, not an
      automatic finding).
    * ``MISSING_PREREQUISITE`` — the action exists but is not applicable from
      the current state under the modeled prerequisites.
    * ``TERMINAL`` — the current state is terminal; no further transitions.
    * ``REPEATED`` — the action re-applies to the same state (idempotent
      no-op) or re-enters an already-visited state.
    * ``UNKNOWN_ACTION`` — the action is not modeled.
    * ``MALFORMED`` — the observed state/transition data was malformed.
    """

    SUCCESS = "success"
    UNEXPECTED_TRANSITION = "unexpected_transition"
    MISSING_PREREQUISITE = "missing_prerequisite"
    TERMINAL = "terminal"
    REPEATED = "repeated"
    UNKNOWN_ACTION = "unknown_action"
    MALFORMED = "malformed"


class HypothesisOutcome(str, Enum):
    """Deterministic outcome of a business logic hypothesis.

    * ``SUPPORTED`` — the mock target's behavior supports the hypothesis.
    * ``REFUTED`` — the mock target's behavior contradicts the hypothesis.
    * ``INCONCLUSIVE`` — the observation was ambiguous (e.g. an indeterminate
      5xx/redirect), so no determination is made.
    """

    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class ValidationResult(str, Enum):
    """Outcome of validating a business logic hypothesis through replay.

    * ``VALIDATED`` — a bounded, deterministic replay confirmed the
      hypothesis's behavior; the supporting evidence was elevated to
      ``VALIDATED``.
    * ``INVALIDATED`` — the replay contradicted the hypothesis.
    * ``UNVERIFIABLE`` — the hypothesis could not be exercised safely (e.g.
      the required action is ``PROHIBITED``); no determination is made.
    """

    VALIDATED = "validated"
    INVALIDATED = "invalidated"
    UNVERIFIABLE = "unverifiable"


class BusinessObservationKind(str, Enum):
    """Typed kinds of business logic observations."""

    WORKFLOW = "workflow"
    STATE = "state"
    STATE_TRANSITION = "state_transition"
    BUSINESS_RULE = "business_rule"
    OWNERSHIP = "ownership"
    ROLE_BOUNDARY = "role_boundary"
    WORKFLOW_CONSISTENCY = "workflow_consistency"
    WORKFLOW_REPLAY = "workflow_replay"
    BUSINESS_LOGIC_HYPOTHESIS = "business_logic_hypothesis"
    BUSINESS_LOGIC_VALIDATION = "business_logic_validation"


class WorkflowObservation(BaseModel):
    """A business workflow discovered on the authorized target."""

    kind: Literal["workflow"] = "workflow"
    url: str
    host: str
    workflow: str
    application: str | None = None
    description: str | None = None
    state_names: list[str] = Field(default_factory=list)
    action_names: list[str] = Field(default_factory=list)
    note: str | None = None


class StateObservation(BaseModel):
    """A state in a modeled business workflow (structural, descriptive)."""

    kind: Literal["state"] = "state"
    url: str
    host: str
    workflow: str
    state: str
    initial: bool = False
    terminal: bool = False
    allowed_roles: list[str] = Field(default_factory=list)
    note: str | None = None


class StateTransitionObservation(BaseModel):
    """An observed transition edge for a workflow action.

    ``anomalous=True`` records an observed deviation from the modeled target
    (e.g. shipped before paid). It is an observation, never an automatic
    finding: classification happens only after hypothesis + validation.
    """

    kind: Literal["state_transition"] = "state_transition"
    url: str
    host: str
    workflow: str
    action: str
    source_state: str
    target_state: str
    direct: bool = True
    prerequisite: str | None = None
    resource: str | None = None
    anomalous: bool = False
    note: str | None = None


class BusinessRuleObservation(BaseModel):
    """A business rule (invariant) and its observed enforcement state.

    ``enforcement`` is one of ``enforced`` / ``broken`` / ``not_applicable``.
    A ``broken`` label records an observed deviation; it is recorded as
    inferred evidence and only becomes a validated classification after the
    evidence workflow elevates it.
    """

    kind: Literal["business_rule"] = "business_rule"
    url: str
    host: str
    workflow: str
    rule: str
    description: str | None = None
    enforcement: str = "not_applicable"
    observed: bool = False
    detail: str | None = None
    note: str | None = None


class OwnershipObservation(BaseModel):
    """Recorded ownership of a business resource by a controlled identity."""

    kind: Literal["ownership"] = "ownership"
    url: str
    host: str
    workflow: str
    resource: str
    owner: str
    owner_type: str = "identity"
    controlled: bool = False
    note: str | None = None


class RoleBoundaryObservation(BaseModel):
    """Whether a role's action on a resource matches the modeled boundary.

    ``allowed`` is the observed outcome; ``expected`` the modeled one.
    ``consistent`` is True only when they match.
    """

    kind: Literal["role_boundary"] = "role_boundary"
    url: str
    host: str
    workflow: str
    role: str
    action: str
    resource: str
    allowed: bool = False
    expected: bool | None = None
    consistent: bool | None = None
    note: str | None = None


class WorkflowConsistencyObservation(BaseModel):
    """Modeled-invariant consistency status for a workflow.

    ``violated`` records that the observed state machine contradicts the
    invariant; classification as a finding still requires the validation step.
    """

    kind: Literal["workflow_consistency"] = "workflow_consistency"
    url: str
    host: str
    workflow: str
    invariant: str
    status: str = "unknown"
    detail: str | None = None
    note: str | None = None


class WorkflowReplayObservation(BaseModel):
    """A single deterministic replay step outcome for a diagnosed workflow."""

    kind: Literal["workflow_replay"] = "workflow_replay"
    url: str
    host: str
    workflow: str
    action: str
    source_state: str
    target_state: str | None = None
    result: TransitionResult = TransitionResult.SUCCESS
    safety_class: ReplaySafetyClass = ReplaySafetyClass.BOUNDED
    sequence_length: int = 1
    note: str | None = None


class BusinessLogicHypothesisObservation(BaseModel):
    """A business-logic hypothesis and its deterministic mock outcome.

    Hypotheses are never findings. An INCONCLUSIVE or REFUTED outcome records
    that no exploit-relevant behavior was demonstrated.
    """

    kind: Literal["business_logic_hypothesis"] = "business_logic_hypothesis"
    url: str
    host: str
    workflow: str
    hypothesis: str
    outcome: HypothesisOutcome = HypothesisOutcome.INCONCLUSIVE
    detail: str | None = None
    note: str | None = None


class BusinessLogicValidationObservation(BaseModel):
    """A hypothesis elevated through deterministic, bounded replay.

    Only a validated outcome produces a ``VALIDATED`` evidence record;
    ``INVALIDATED`` and ``UNVERIFIABLE`` never do.
    """

    kind: Literal["business_logic_validation"] = "business_logic_validation"
    url: str
    host: str
    workflow: str
    hypothesis: str
    result: ValidationResult = ValidationResult.UNVERIFIABLE
    evidence_reference: str | None = None
    replay_observations: int = 0
    note: str | None = None


Observation = Annotated[
    WorkflowObservation
    | StateObservation
    | StateTransitionObservation
    | BusinessRuleObservation
    | OwnershipObservation
    | RoleBoundaryObservation
    | WorkflowConsistencyObservation
    | WorkflowReplayObservation
    | BusinessLogicHypothesisObservation
    | BusinessLogicValidationObservation,
    Field(discriminator="kind"),
]


class BusinessLogicRequest(BaseModel):
    """Authorized business logic observation request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    ``test_identities`` bounds ownership/role comparisons to authorized,
    explicitly listed identities — the surface never guesses or discovers
    identities autonomously.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    test_identities: list[str] = Field(default_factory=list)
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_sequence_length: int = Field(default=8, ge=1, le=32)


class BusinessLogicResult(BaseModel):
    """Structured, deterministic outcome of a business logic execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: BusinessLogicMode
    status: BusinessLogicStatus = BusinessLogicStatus.SUCCESS
    observations: list[Observation] = Field(default_factory=list)
    evidence_ids: list[EvidenceID] = Field(default_factory=list)
    raw_output: str | None = None
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0
    authorized: bool = True
    created_at: float = Field(default_factory=time.time)

    @property
    def observation_count(self) -> int:
        return len(self.observations)


# ---------------------------------------------------------------------------
# In-process workflow state machine (paper model) used by deterministic replay
# ---------------------------------------------------------------------------
class WorkflowTransition(BaseModel):
    """One declared transition edge of a workflow's paper model."""

    action: str
    source_state: str
    target_state: str
    prerequisites: list[str] = Field(default_factory=list)
    note: str | None = None


class WorkflowModel(BaseModel):
    """The declared (paper) business workflow for a host.

    ``transitions`` maps an action name to the transitions it can produce.
    This model is what deterministic replay runs against — never free text and
    never an arbitrary executor.
    """

    workflow: str
    host: str
    initial_state: str
    states: list[str] = Field(default_factory=list)
    terminal_states: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    transitions: dict[str, list[WorkflowTransition]] = Field(default_factory=dict)
    action_safety: dict[str, ReplaySafetyClass] = Field(default_factory=dict)

    def safety_for(self, action: str) -> ReplaySafetyClass:
        """Safety class for an action; unknown actions fail closed."""
        return self.action_safety.get(action, ReplaySafetyClass.PROHIBITED)


class WorkflowStepEvaluation(BaseModel):
    """Result of evaluating one transition step against the paper model."""

    action: str
    source_state: str
    target_state: str | None = None
    result: TransitionResult = TransitionResult.SUCCESS
    safety_class: ReplaySafetyClass = ReplaySafetyClass.BOUNDED
    sequence_length: int = 1
    note: str | None = None


class ReplaySimulator:
    """Deterministic, in-process evaluator for a :class:`WorkflowModel`.

    The simulator never executes anything outside the mock model: no HTTP,
    no credentials, no side effects. Its output feeds the
    ``controlled_workflow_replay`` capability where the engine has already
    enforced authorization and fail-closed safety gating.
    """

    def __init__(self, model: WorkflowModel) -> None:
        self._model = model

    @property
    def model(self) -> WorkflowModel:
        return self._model

    def step(
        self,
        action: str,
        current_state: str,
        *,
        observed_target: str | None = None,
        sequence_length: int = 1,
    ) -> WorkflowStepEvaluation:
        """Evaluate a single action from ``current_state``.

        ``observed_target`` lets the caller replay an observed outcome so an
        anomaly (e.g. a fixture that shipped before payment) is surfaced as
        ``UNEXPECTED_TRANSITION`` instead of silently matched.
        """
        model = self._model
        safety = model.safety_for(action)
        if action not in model.actions:
            return WorkflowStepEvaluation(
                action=action,
                source_state=current_state,
                result=TransitionResult.UNKNOWN_ACTION,
                safety_class=safety,
                sequence_length=sequence_length,
                note="action is not modeled",
            )
        if current_state not in model.states:
            return WorkflowStepEvaluation(
                action=action,
                source_state=current_state,
                result=TransitionResult.MALFORMED,
                safety_class=safety,
                sequence_length=sequence_length,
                note="current state is not modeled",
            )
        if current_state in model.terminal_states:
            return WorkflowStepEvaluation(
                action=action,
                source_state=current_state,
                result=TransitionResult.TERMINAL,
                safety_class=safety,
                sequence_length=sequence_length,
                note="state is terminal; no further transitions",
            )
        candidates = [
            t
            for t in model.transitions.get(action, [])
            if t.source_state == current_state
        ]
        if not candidates:
            return WorkflowStepEvaluation(
                action=action,
                source_state=current_state,
                result=TransitionResult.MISSING_PREREQUISITE,
                safety_class=safety,
                sequence_length=sequence_length,
                note=f"action {action} is not applicable from {current_state}",
            )
        transition = candidates[0]
        for prerequisite in transition.prerequisites:
            if current_state != prerequisite:
                return WorkflowStepEvaluation(
                    action=action,
                    source_state=current_state,
                    result=TransitionResult.MISSING_PREREQUISITE,
                    safety_class=safety,
                    sequence_length=sequence_length,
                    note=f"prerequisite {prerequisite} not met",
                )
        target = observed_target or transition.target_state
        if target == current_state:
            result = TransitionResult.REPEATED
            note = f"action {action} re-applied on {current_state} (no-op)"
        elif observed_target is not None and target != transition.target_state:
            result = TransitionResult.UNEXPECTED_TRANSITION
            note = (
                f"observed transition {current_state}->{observed_target} "
                f"differs from modeled {transition.target_state}"
            )
        else:
            result = TransitionResult.SUCCESS
            note = transition.note
        return WorkflowStepEvaluation(
            action=action,
            source_state=current_state,
            target_state=target,
            result=result,
            safety_class=safety,
            sequence_length=sequence_length,
            note=note,
        )

    def replay(
        self,
        actions: list[str],
        start_state: str,
        *,
        observed_targets: list[str | None] | None = None,
        max_sequence_length: int = 8,
    ) -> list[WorkflowStepEvaluation]:
        """Replay a bounded action sequence from ``start_state``.

        Raises ``ValueError`` when a sequence contains a ``PROHIBITED``
        action, so callers (and the engine, fail-closed) refuse it before any
        step runs.
        """
        bounded = list(actions[:max_sequence_length])
        state = start_state
        evaluations: list[WorkflowStepEvaluation] = []
        observed = observed_targets or []
        for index, action in enumerate(bounded):
            if self._model.safety_for(action) == ReplaySafetyClass.PROHIBITED:
                raise ValueError(
                    f"replay rejected: action {action} has safety class "
                    "PROHIBITED"
                )
            evaluation = self.step(
                action,
                state,
                observed_target=(
                    observed[index]
                    if index < len(observed) and observed[index] is not None
                    else None
                ),
                sequence_length=index + 1,
            )
            evaluations.append(evaluation)
            if evaluation.target_state is not None:
                state = evaluation.target_state
            if evaluation.result == TransitionResult.TERMINAL:
                break
        return evaluations
