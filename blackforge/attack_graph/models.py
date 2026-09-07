from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, Field

from blackforge.core.types import (
    AssessmentPlanID,
    AttackGraphEdgeID,
    AttackGraphNodeID,
    Confidence,
    EvidenceID,
    EvidenceStatus,
    GraphPathID,
    MissionID,
    RiskLevel,
    SessionID,
    WorldEntityID,
)

SURFACE_ENTITY_TYPES = frozenset(
    {
        "public_address",
        "edge_endpoint",
        "endpoint",
        "application",
        "api",
        "ingress",
    }
)


class GraphRelationship(str, Enum):
    """Typed, phase-14 derived relationships between graph nodes.

    These are deliberately NOT offensive semantics. ``POTENTIALLY_LEADS_TO``
    and ``REQUIRES_VALIDATION`` are hypotheses that a *future* assessment step
    must validate; a *potential* path is not an exploit path. No member
    expresses exploitation, compromise, escalation, or intrusion.
    """

    EXPOSES = "exposes"
    REQUIRES = "requires"
    DEPENDS_ON = "depends_on"
    REACHABLE_FROM = "reachable_from"
    PROVIDES_ACCESS_TO = "provides_access_to"
    CONSTRAINS = "constrains"
    BLOCKED_BY = "blocked_by"
    POTENTIALLY_LEADS_TO = "potentially_leads_to"
    REQUIRES_VALIDATION = "requires_validation"


class GraphState(str, Enum):
    """Epistemic state of a graph node or edge.

    ``GraphState`` extends the shared ``EvidenceStatus`` vocabulary with the
    states the attack-graph layer needs and can honestly derive: a derived
    edge is at best ``INFERRED``, a hypothesis is ``HYPOTHESIZED``, and a
    degraded or blocked relationship is explicitly flagged rather than
    silently dropped.
    """

    OBSERVED = "observed"
    INFERRED = "inferred"
    HYPOTHESIZED = "hypothesized"
    VALIDATED = "validated"
    BLOCKED = "blocked"
    CONTRADICTED = "contradicted"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class PathState(str, Enum):
    """Epistemic state of a derived graph path.

    A path is only ever a *relationship sequence*, never a proven attack.
    ``VALIDATED_PATH`` requires validated supporting evidence; everything
    else stays at or below ``INFERRED_PATH`` / ``HYPOTHESIZED_PATH``.
    """

    OBSERVED_PATH = "observed_path"
    INFERRED_PATH = "inferred_path"
    HYPOTHESIZED_PATH = "hypothesized_path"
    VALIDATED_PATH = "validated_path"
    BLOCKED_PATH = "blocked_path"
    CONTRADICTED_PATH = "contradicted_path"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class PrerequisiteState(str, Enum):
    """State of a single requirement attached to a derived edge."""

    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"
    CONTRADICTED = "contradicted"


class GraphLifecycle(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ARCHIVED = "archived"


class Prerequisite(BaseModel):
    """A deterministically evaluated requirement on a graph edge.

    ``required_evidence`` lists evidence types that would satisfy it;
    ``satisfied_by`` lists concrete evidence records when satisfied.
    """

    description: str
    state: PrerequisiteState = PrerequisiteState.UNKNOWN
    required_evidence: list[str] = Field(default_factory=list)
    satisfied_by: list[EvidenceID] = Field(default_factory=list)
    note: str | None = None


class GraphDerivation(BaseModel):
    """How a graph node/edge was derived — the audit trail back to source.

    Derivation is the key epistemic control: a derived record carries the
    exact world-model relationships, entities, and evidence it was built
    from, plus the deterministic rule_id. Nothing here is invented by an LLM.
    """

    rule_id: str | None = None
    source_relationship_ids: list[str] = Field(default_factory=list)
    source_entity_ids: list[str] = Field(default_factory=list)
    source_evidence_ids: list[EvidenceID] = Field(default_factory=list)
    note: str | None = None


class AttackGraphNode(BaseModel):
    """A node in the derived analytical graph, bound to a world entity.

    The node is a *view* of the canonical ``WorldEntity`` under a mission;
    it never replaces the world model record. ``dedup_key`` is
    ``<mission>:<graph>:<entity_id>`` — the reproducibility basis for the
    builder and the persistence layer.
    """

    id: AttackGraphNodeID = Field(default_factory=AttackGraphNodeID)
    mission_id: MissionID
    graph_id: str
    entity_id: WorldEntityID
    entity_type: str
    name: str
    state: GraphState = GraphState.INFERRED
    lifecycle: GraphLifecycle = GraphLifecycle.ACTIVE
    confidence: Confidence = Confidence.MEDIUM
    supporting_evidence: list[EvidenceID] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceID] = Field(default_factory=list)
    correlation_ids: list[str] = Field(default_factory=list)
    properties: dict = Field(default_factory=dict)
    derivation: GraphDerivation = Field(default_factory=GraphDerivation)
    dedup_key: str | None = None
    version: int = 1
    supersedes: AttackGraphNodeID | None = None
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)
    updated_at: float | None = None


class AttackGraphEdge(BaseModel):
    """A typed, directional, evidence-annotated relationship between nodes.

    The edge is always weaker than its sources: a derived edge never claims
    exploitation. ``prerequisites`` carry the evaluated requirements that an
    assessment step would need to satisfy before the relationship could
    become a validated path.
    """

    id: AttackGraphEdgeID = Field(default_factory=AttackGraphEdgeID)
    mission_id: MissionID
    graph_id: str
    source_node_id: AttackGraphNodeID
    target_node_id: AttackGraphNodeID
    source_entity_id: WorldEntityID
    target_entity_id: WorldEntityID
    relationship: GraphRelationship
    state: GraphState = GraphState.INFERRED
    lifecycle: GraphLifecycle = GraphLifecycle.ACTIVE
    confidence: Confidence = Confidence.MEDIUM
    supporting_evidence: list[EvidenceID] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceID] = Field(default_factory=list)
    prerequisites: list[Prerequisite] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    properties: dict = Field(default_factory=dict)
    derivation: GraphDerivation = Field(default_factory=GraphDerivation)
    dedup_key: str | None = None
    version: int = 1
    supersedes: AttackGraphEdgeID | None = None
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)
    updated_at: float | None = None


class GraphPath(BaseModel):
    """A bounded, cycle-safe sequence of nodes/edges between two nodes."""

    id: GraphPathID = Field(default_factory=GraphPathID)
    mission_id: MissionID
    graph_id: str
    start_entity_id: WorldEntityID
    end_entity_id: WorldEntityID
    state: PathState = PathState.HYPOTHESIZED_PATH
    node_ids: list[AttackGraphNodeID] = Field(default_factory=list)
    edge_ids: list[AttackGraphEdgeID] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    missing_prerequisites: list[Prerequisite] = Field(default_factory=list)
    supporting_evidence: list[EvidenceID] = Field(default_factory=list)
    assessment_priority: float = 0.0
    length: int = 0
    created_at: float = Field(default_factory=time.time)


class PlanStatus(str, Enum):
    PLAN_READY = "plan_ready"
    NO_ACTION_AVAILABLE = "no_action_available"
    NO_GAPS = "no_gaps"
    PLAN_CAPPED = "plan_capped"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    UNKNOWN_START = "unknown_start"


class PlanStepStatus(str, Enum):
    PENDING = "pending"
    DEFERRED = "deferred"
    CAPPED = "capped"


class ExpectedEvidence(BaseModel):
    """Evidence a planned capability is expected to produce for a gap."""

    evidence_type: str
    description: str
    target: str


class CandidateAction(BaseModel):
    """A single planned, in-scope, authorized capability invocation.

    ``capability_name`` always references a capability registered in the
    BLACKFORGE capability registry; the planner only selects — it never
    executes. Execution (when it happens) must go through the existing
    Scope → Authorization → Capability → guarded engine pipeline.
    """

    capability_name: str
    target: str
    gap: str
    risk_level: RiskLevel = RiskLevel.LOW
    rank: int = 0
    expected_evidence: list[ExpectedEvidence] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)


class PlanStep(BaseModel):
    """An ordered step inside an :class:`AssessmentPlan`."""

    step_id: str
    order: int
    action: CandidateAction
    status: PlanStepStatus = PlanStepStatus.PENDING


class AssessmentPlan(BaseModel):
    """A bounded, deterministic assessment plan produced by the planner.

    The plan is advisory and never executes anything by itself. It lists
    which *registered* capabilities could produce evidence for the
    highest-priority derived gaps. ``status == NO_ACTION_AVAILABLE`` is a
    legitimate, first-class outcome — the planner fails closed.
    """

    id: AssessmentPlanID = Field(default_factory=AssessmentPlanID)
    mission_id: MissionID
    session_id: SessionID | None = None
    graph_id: str
    status: PlanStatus = PlanStatus.PLAN_READY
    steps: list[PlanStep] = Field(default_factory=list)
    unmet_prerequisites: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    max_steps: int = 10
    max_candidates: int = 5
    max_graph_depth: int = 3
    created_at: float = Field(default_factory=time.time)
    note: str | None = None

    @property
    def capability_names(self) -> list[str]:
        """Registered capability names referenced by the plan, deterministically."""
        return [step.action.capability_name for step in self.steps]


def graph_node_dedup_key(mission_id: MissionID, graph_id: str, entity_id) -> str:
    return f"{str(mission_id)}:{graph_id}:{str(entity_id)}"


def graph_edge_dedup_key(
    mission_id: MissionID,
    graph_id: str,
    relationship: GraphRelationship,
    source_entity_id,
    target_entity_id,
) -> str:
    return (
        f"{str(mission_id)}:{graph_id}:{relationship.value}:"
        f"{str(source_entity_id)}:{str(target_entity_id)}"
    )


def evidence_status_to_graph_state(status: EvidenceStatus) -> GraphState:
    """Deterministic, non-elevating mapping from evidence to graph state."""
    return {
        EvidenceStatus.OBSERVED: GraphState.OBSERVED,
        EvidenceStatus.INFERRED: GraphState.INFERRED,
        EvidenceStatus.HYPOTHESIZED: GraphState.HYPOTHESIZED,
        EvidenceStatus.VALIDATED: GraphState.VALIDATED,
    }[status]


def graph_state_to_evidence_status(state: GraphState) -> EvidenceStatus:
    """Deterministic mapping used at the graph -> memory boundary (never up).

    ``VALIDATED`` graph state maps back to ``INFERRED`` evidence because the
    graph is always a derived view: the graph itself never validates, it only
    reflects validated *source* evidence, and memory must never outrank the
    evidence store.
    """
    return {
        GraphState.OBSERVED: EvidenceStatus.OBSERVED,
        GraphState.INFERRED: EvidenceStatus.INFERRED,
        GraphState.VALIDATED: EvidenceStatus.INFERRED,
        GraphState.CONTRADICTED: EvidenceStatus.HYPOTHESIZED,
        GraphState.BLOCKED: EvidenceStatus.HYPOTHESIZED,
        GraphState.INSUFFICIENT_EVIDENCE: EvidenceStatus.HYPOTHESIZED,
        GraphState.HYPOTHESIZED: EvidenceStatus.HYPOTHESIZED,
    }[state]
