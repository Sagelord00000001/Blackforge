from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from blackforge.business_logic.models import (
    BusinessLogicHypothesisObservation,
    BusinessLogicValidationObservation,
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
    MissionID,
    SessionID,
)
from blackforge.world_model.materializer import (
    EntityFact,
    RelationshipFact,
    WorldMaterializer,
)
from blackforge.world_model.models import (
    AssertionSpec,
    EntityType,
    EvidenceLinkRef,
    RelationshipType,
    WorldEntity,
)

if TYPE_CHECKING:
    from blackforge.world_model.store import WorldModelStore

_OBSERVED = [EvidenceStatus.OBSERVED]
_INFERRED = [EvidenceStatus.OBSERVED, EvidenceStatus.INFERRED]


def _ref(evidence_id: EvidenceID, **properties: str | None) -> EvidenceLinkRef:
    return EvidenceLinkRef(
        evidence_id=evidence_id,
        property_key=properties.get("property_key"),
        property_value=properties.get("property_value"),
    )


class BusinessMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class BusinessMaterializeReport(BaseModel):
    entries: list[BusinessMaterializeEntry] = Field(default_factory=list)
    relationships_created: int = 0
    relationships_corroborated: int = 0
    assertions_created: int = 0
    assertions_corroborated: int = 0

    @property
    def entities_created(self) -> int:
        return sum(1 for e in self.entries if e.action == "created")

    @property
    def entities_updated(self) -> int:
        return len(self.entries) - self.entities_created


class BusinessLogicWorldMaterializer:
    """Maps typed business logic observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text. The
    base namespaces by host; the chain is:

    * APPLICATION --HAS_WORKFLOW--> WORKFLOW (from workflow observations)
    * WORKFLOW --HAS_STATE--> BUSINESS_STATE (from state observations)
    * WORKFLOW --HAS_ACTION--> BUSINESS_ACTION and
      BUSINESS_STATE --TRANSITIONS_TO--> BUSINESS_STATE (from transitions)
    * RESOURCE --BELONGS_TO--> IDENTITY (from ownership observations, filtered
      to the explicitly authorized test identities)
    * ROLE --HAS_PERMISSION--> PERMISSION --APPLIES_TO--> RESOURCE (from role
      boundary observations)
    * Rules, consistency, replay, hypothesis, and validation outcomes become
      ASSERTIONS on the workflow entity so a re-run never churns entity
      versions.

    Broken rules, violated invariants, anomalous transitions, hypotheses, and
    unvalidated claims are recorded as INFERRED / HYPOTHESIZED assertions —
    they only become VALIDATED after the validation capability confirms them.
    """

    def __init__(self, store: WorldModelStore) -> None:
        self._store = store
        self._materializer = WorldMaterializer(store)

    @property
    def store(self) -> WorldModelStore:
        return self._store

    def materialize(
        self,
        mission_id: MissionID,
        observations: list[tuple[Observation, EvidenceID, Confidence]],
        *,
        session_id: SessionID | None = None,
    ) -> BusinessMaterializeReport:
        report = BusinessMaterializeReport()
        for observation, evidence_id, confidence in observations:
            self._materialize_one(
                mission_id,
                observation,
                evidence_id,
                confidence,
                report,
                session_id=session_id,
            )
        return report

    # ------------------------------------------------------------------
    # Per-kind mapping
    # ------------------------------------------------------------------
    def _materialize_one(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: BusinessMaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        if isinstance(observation, WorkflowObservation):
            self._materialize_workflow(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, StateObservation):
            self._materialize_state(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, StateTransitionObservation):
            self._materialize_transition(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, OwnershipObservation):
            self._materialize_ownership(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, RoleBoundaryObservation):
            self._materialize_role_boundary(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(
            observation,
            (
                BusinessRuleObservation,
                WorkflowConsistencyObservation,
                WorkflowReplayObservation,
                BusinessLogicHypothesisObservation,
                BusinessLogicValidationObservation,
            ),
        ):
            self._assert_on_workflow(
                mission_id, observation, evidence_id, confidence, report, session_id
            )

    # ------------------------------------------------------------------
    def _materialize_workflow(
        self, mission_id, obs: WorkflowObservation, evidence_id, confidence, report, session_id
    ) -> None:
        workflow, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.WORKFLOW,
                name=obs.workflow,
                namespace=obs.host,
                properties={
                    "workflow": obs.workflow,
                    "application": obs.application,
                    "source": "business_logic.workflow_discovery",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        application = self._ensure_application(
            mission_id, obs.host, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_WORKFLOW,
                source_entity_id=str(application.id),
                target_entity_id=str(workflow.id),
                note="application runs business workflow",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            BusinessMaterializeEntry(
                entity_type="workflow",
                name=workflow.name,
                namespace=workflow.namespace,
                entity_id=str(workflow.id),
                action=action,
            )
        )

    def _materialize_state(
        self, mission_id, obs: StateObservation, evidence_id, confidence, report, session_id
    ) -> None:
        state_entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.BUSINESS_STATE,
                name=obs.state,
                namespace=obs.host,
                properties={
                    "state": obs.state,
                    "workflow": obs.workflow,
                    "initial": obs.initial,
                    "terminal": obs.terminal,
                    "source": "business_logic.workflow_modeling",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        workflow = self._ensure_workflow(
            mission_id, obs.host, obs.workflow, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_STATE,
                source_entity_id=str(workflow.id),
                target_entity_id=str(state_entity.id),
                note="workflow includes state",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            BusinessMaterializeEntry(
                entity_type="business_state",
                name=state_entity.name,
                namespace=state_entity.namespace,
                entity_id=str(state_entity.id),
                action=action,
            )
        )

    def _materialize_transition(
        self,
        mission_id,
        obs: StateTransitionObservation,
        evidence_id,
        confidence,
        report,
        session_id,
    ) -> None:
        action_entity, action_name = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.BUSINESS_ACTION,
                name=obs.action,
                namespace=obs.host,
                properties={
                    "action": obs.action,
                    "workflow": obs.workflow,
                    "source": "business_logic.state_transition_analysis",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        workflow = self._ensure_workflow(
            mission_id, obs.host, obs.workflow, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_ACTION,
                source_entity_id=str(workflow.id),
                target_entity_id=str(action_entity.id),
                note="workflow declares action",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        if obs.resource:
            resource = self._ensure_resource(
                mission_id, obs.host, obs.resource, evidence_id, confidence, session_id
            )
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.OPERATES_ON,
                    source_entity_id=str(action_entity.id),
                    target_entity_id=str(resource.id),
                    note="action operates on resource",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        source_state = self._ensure_state(
            mission_id,
            obs.host,
            obs.workflow,
            obs.source_state,
            evidence_id,
            confidence,
            session_id,
        )
        target_state = self._ensure_state(
            mission_id,
            obs.host,
            obs.workflow,
            obs.target_state,
            evidence_id,
            confidence,
            session_id,
        )
        if source_state.id != target_state.id:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.TRANSITIONS_TO,
                    source_entity_id=str(source_state.id),
                    target_entity_id=str(target_state.id),
                    note=f"transition via {obs.action}",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        else:
            report.entries.append(
                BusinessMaterializeEntry(
                    entity_type="business_state",
                    name=source_state.name,
                    namespace=source_state.namespace,
                    entity_id=str(source_state.id),
                    action="self_loop",
                )
            )
        report.entries.append(
            BusinessMaterializeEntry(
                entity_type="business_action",
                name=action_entity.name,
                namespace=action_entity.namespace,
                entity_id=str(action_entity.id),
                action=action_name,
            )
        )
        if obs.anomalous:
            self._add_assertion(
                mission_id,
                workflow.id,
                f"transition_violation.{obs.source_state}->{obs.target_state}",
                f"via {obs.action}",
                obs,
                evidence_id,
                confidence,
                report,
                session_id,
                status=EvidenceStatus.INFERRED,
            )

    def _materialize_ownership(
        self, mission_id, obs: OwnershipObservation, evidence_id, confidence, report, session_id
    ) -> None:
        resource = self._ensure_resource(
            mission_id, obs.host, obs.resource, evidence_id, confidence, session_id
        )
        identity = self._ensure_identity(
            mission_id, obs.host, obs.owner, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.BELONGS_TO,
                source_entity_id=str(resource.id),
                target_entity_id=str(identity.id),
                note=f"resource owned by {obs.owner}",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    def _materialize_role_boundary(
        self, mission_id, obs: RoleBoundaryObservation, evidence_id, confidence, report, session_id
    ) -> None:
        role = self._ensure_role(
            mission_id, obs.host, obs.role, evidence_id, confidence, session_id
        )
        resource = self._ensure_resource(
            mission_id, obs.host, obs.resource, evidence_id, confidence, session_id
        )
        permission = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.PERMISSION,
                name=f"{obs.action}::{obs.resource}",
                namespace=obs.host,
                properties={
                    "permission": obs.action,
                    "resource": obs.resource,
                    "host": obs.host,
                    "source": "business_logic.role_boundary_analysis",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_PERMISSION,
                source_entity_id=str(role.id),
                target_entity_id=str(permission.id),
                note="role boundary grants permission per observed outcome",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.APPLIES_TO,
                source_entity_id=str(permission.id),
                target_entity_id=str(resource.id),
                note="permission applies to resource",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    # ------------------------------------------------------------------
    # Assertions
    # ------------------------------------------------------------------
    def _assert_on_workflow(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: BusinessMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        workflow = self._ensure_workflow(
            mission_id, observation.host, observation.workflow, evidence_id, confidence, session_id
        )
        for key, value, status in _assertion_pairs(observation):
            self._add_assertion(
                mission_id,
                workflow.id,
                key,
                value,
                observation,
                evidence_id,
                confidence,
                report,
                session_id,
                status=status,
            )

    def _add_assertion(
        self,
        mission_id: MissionID,
        entity_id,
        key: str,
        value: str,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: BusinessMaterializeReport,
        session_id: SessionID | None,
        *,
        status: EvidenceStatus = EvidenceStatus.OBSERVED,
    ) -> None:
        result = self._store.add_assertion(
            AssertionSpec(
                mission_id=mission_id,
                session_id=session_id,
                entity_id=entity_id,
                property_key=key,
                property_value=value,
                epistemic_status=status,
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            )
        )
        if result.action.value == "created":
            report.assertions_created += 1
        else:
            report.assertions_corroborated += 1

    def _link_report(
        self,
        mission_id: MissionID,
        fact: RelationshipFact,
        report: BusinessMaterializeReport | None,
        session_id: SessionID | None,
    ) -> None:
        result = self._materializer.materialize_relationship(mission_id, fact, session_id)
        if report is None:
            return
        if result.action.value == "created":
            report.relationships_created += 1
        else:
            report.relationships_corroborated += 1

    # ------------------------------------------------------------------
    # Shared entity helpers
    # ------------------------------------------------------------------
    def _ensure_application(
        self,
        mission_id: MissionID,
        host: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        existing = self._store.find_entity(mission_id, EntityType.APPLICATION, host)
        if existing is not None:
            return existing
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.APPLICATION,
                name=host,
                properties={"host": host, "source": "business_logic"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_workflow(
        self,
        mission_id: MissionID,
        host: str,
        workflow: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.WORKFLOW,
                name=workflow,
                namespace=host,
                properties={"workflow": workflow, "host": host, "source": "business_logic"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_state(
        self,
        mission_id: MissionID,
        host: str,
        workflow: str,
        state: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.BUSINESS_STATE,
                name=state,
                namespace=host,
                properties={
                    "state": state,
                    "workflow": workflow,
                    "host": host,
                    "source": "business_logic",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_identity(
        self,
        mission_id: MissionID,
        host: str,
        name: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.IDENTITY,
                name=name,
                namespace=host,
                properties={"host": host, "source": "business_logic"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_role(
        self,
        mission_id: MissionID,
        host: str,
        name: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ROLE,
                name=name,
                namespace=host,
                properties={"host": host, "source": "business_logic"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_resource(
        self,
        mission_id: MissionID,
        host: str,
        name: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.RESOURCE,
                name=name,
                namespace=host,
                properties={"host": host, "source": "business_logic"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _upsert_entity(
        self,
        mission_id: MissionID,
        fact: EntityFact,
        session_id: SessionID | None,
    ) -> tuple[WorldEntity, str]:
        result = self._materializer.materialize_entity(
            mission_id, fact, _OBSERVED, session_id
        )
        return result.entity, result.action.value


def _assertion_pairs(
    observation: Observation,
) -> list[tuple[str, str, EvidenceStatus]]:
    """Stable (key, value, status) assertion triples for analysis observations."""
    if isinstance(observation, BusinessRuleObservation):
        status = (
            EvidenceStatus.INFERRED
            if observation.enforcement == "broken"
            else EvidenceStatus.OBSERVED
        )
        return [
            (
                f"rule.{observation.rule}",
                (
                    f"enforcement={observation.enforcement} "
                    f"observed={str(observation.observed).lower()}"
                ),
                status,
            )
        ]
    if isinstance(observation, WorkflowConsistencyObservation):
        status = (
            EvidenceStatus.INFERRED
            if observation.status == "violated"
            else EvidenceStatus.OBSERVED
        )
        return [
            (
                f"invariant.{observation.invariant}",
                f"status={observation.status}",
                status,
            )
        ]
    if isinstance(observation, WorkflowReplayObservation):
        return [
            (
                f"replay.{observation.action}.{observation.source_state}",
                (
                    f"result={observation.result.value} "
                    f"target={observation.target_state or 'none'} "
                    f"safety={observation.safety_class.value}"
                ),
                EvidenceStatus.OBSERVED,
            )
        ]
    if isinstance(observation, BusinessLogicHypothesisObservation):
        return [
            (
                f"hypothesis.{observation.hypothesis}",
                f"outcome={observation.outcome.value}",
                EvidenceStatus.HYPOTHESIZED,
            )
        ]
    if isinstance(observation, BusinessLogicValidationObservation):
        status = (
            EvidenceStatus.VALIDATED
            if observation.result == ValidationResult.VALIDATED
            else EvidenceStatus.OBSERVED
        )
        return [
            (
                f"validation.{observation.hypothesis}",
                f"result={observation.result.value}",
                status,
            )
        ]
    return []
