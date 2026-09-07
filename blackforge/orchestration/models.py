"""Domain models for the Phase 14.1 mission orchestration layer.

These models sit between the mission, scope, authorization, capability,
evidence, world-model and attack-graph layers and the orchestration loop.
Nothing here performs transport; every model is a typed contract exchanged by
the planners, routers and the orchestrator. A plan step is an authorized,
evidence-gathering suggestion, never an exploitability claim.
"""

from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, Field

from blackforge.attack_graph.models import (
    GraphRelationship,  # noqa: TC001 - runtime refs for pydantic resolution
)
from blackforge.core.types import MissionID, RiskLevel, SessionID, TargetType
from blackforge.scope.models import (
    TargetScope,  # noqa: TC001 - runtime refs for pydantic resolution
)


class ScopeClassification(str, Enum):
    """How a discovered asset relates to the seed target."""

    IN_SCOPE = "in_scope"
    CANDIDATE = "candidate"
    OUT_OF_SCOPE = "out_of_scope"
    THIRD_PARTY = "third_party"
    UNKNOWN = "unknown"


class AdapterMode(str, Enum):
    """Whether a capability executes against real or mock transport."""

    MOCK_ONLY = "mock_only"
    REAL_CONTROLLED = "real_controlled"


class AssessmentProfile(str, Enum):
    """Caps a mission to an explicit, honest level of authorization."""

    AUTHORIZED_ASSESSMENT = "authorized_assessment"
    CONTROLLED_DEMONSTRATION = "controlled_demonstration"


class InvestigationStatus(str, Enum):
    """Lifecycle of a single planned investigation."""

    PLANNED = "planned"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    BLOCKED = "blocked"


class StopReason(str, Enum):
    """Deterministic reasons a mission run terminates."""

    MAX_STEPS = "max_steps"
    MAX_CAPABILITY_CALLS = "max_capability_calls"
    MAX_RUNTIME = "max_runtime"
    MAX_REPLANS = "max_replans"
    NO_ACTIONS_REMAIN = "no_actions_remain"
    EVIDENCE_SATURATION = "evidence_saturation"
    REPEATED_INVALID_PLANNER = "repeated_invalid_planner"
    DUPLICATE_EVICTION = "duplicate_eviction"
    CANCELLED = "cancelled"
    PLANNER_FAILED = "planner_failed"


class PlannerSource(str, Enum):
    """Which planner produced a decision."""

    MOCK = "mock"
    RULE = "rule"
    LLM = "llm"


class DecisionKind(str, Enum):
    """A planner decision is an investigation, a revalidation, or a stop."""

    INVESTIGATE = "investigate"
    REVALIDATE = "revalidate"
    COMPLETE = "complete"


class Priority(str, Enum):
    """Planner-assigned priority for an investigation step."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PlannerDecision(BaseModel):
    """A single, validated planner decision.

    This is the *only* thing an LLM is allowed to return. It names a
    registered capability and an in-scope target; it can never name a shell
    command, a URL to fetch, or an unregistered capability.
    """

    kind: DecisionKind = DecisionKind.INVESTIGATE
    capability: str
    target: str
    reason: str
    priority: Priority = Priority.MEDIUM
    source: PlannerSource = PlannerSource.RULE

    def require_registered(self, registry_names: set[str]) -> None:
        """Fail closed on anything that is not a registered capability."""
        if self.kind == DecisionKind.COMPLETE:
            return
        if not self.capability or self.capability not in registry_names:
            raise ValueError(f"unknown capability proposed: {self.capability!r}")
        if not self.target or not self.target.strip():
            raise ValueError("planner proposed an empty target")


class MissionPolicy(BaseModel):
    """Deterministic mission limits and gates (the stop conditions)."""

    max_steps: int = Field(default=10, ge=1, le=50)
    max_capability_calls: int = Field(default=25, ge=1, le=200)
    max_runtime_seconds: float = Field(default=300.0, ge=1.0, le=3600.0)
    max_replans: int = Field(default=3, ge=0, le=10)
    invalid_plan_limit: int = Field(default=3, ge=1, le=10)
    max_duplicate_evictions: int = Field(default=3, ge=1, le=10)
    use_subdomain_auto_include: bool = True
    allow_real_controlled: bool = False
    auto_approve_high_risk: bool = False


class MissionSetup(BaseModel):
    """What an authorized user supplies to create a mission."""

    mission_id: MissionID = Field(default_factory=MissionID)
    name: str
    objective: str
    seed_target: str
    profile: AssessmentProfile = AssessmentProfile.AUTHORIZED_ASSESSMENT
    policy: MissionPolicy = Field(default_factory=MissionPolicy)
    metadata: dict = Field(default_factory=dict)


class CapabilityViewRow(BaseModel):
    """One row of the mission-aware capability view."""

    capability: str
    name: str
    category: str | None = None
    mode: str | None = None
    risk_level: RiskLevel = RiskLevel.LOW
    target_types: list[TargetType] = Field(default_factory=list)
    adapter: AdapterMode = AdapterMode.MOCK_ONLY
    applicable: bool = False
    authorized: bool = False
    executed: bool = False
    executed_count: int = 0
    last_outcome: str | None = None


class CapabilityView(BaseModel):
    """Aggregated, mission-aware capability visibility for the console."""

    registered: int = 0
    applicable: int = 0
    authorized: int = 0
    real_controlled: int = 0
    rows: list[CapabilityViewRow] = Field(default_factory=list)


class CapabilityRouting(BaseModel):
    """What the planner is *allowed* to choose: the filtered capability ids."""

    applicable: list[str] = Field(default_factory=list)
    authorized: list[str] = Field(default_factory=list)
    real_controlled: list[str] = Field(default_factory=list)


class AssetSummary(BaseModel):
    """Discovered world-model entity as shown in the console."""

    entity_id: str
    entity_type: str
    name: str
    namespace: str | None = None
    classification: ScopeClassification = ScopeClassification.UNKNOWN
    authorized: bool = False
    confidence: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class EvidenceViewRow(BaseModel):
    """Redaction-safe evidence summary for the console."""

    evidence_id: str
    evidence_type: str
    status: str
    confidence: str
    source_capability: str
    target: str
    timestamp: float
    summary: str = ""
    redacted: bool = False


class GraphEdgeView(BaseModel):
    """One attack-graph edge for a simple visualization."""

    source: str
    target: str
    relationship: GraphRelationship
    state: str
    confidence: str
    certainty: float = 0.0
    evidence_ids: list[str] = Field(default_factory=list)


class GraphSummary(BaseModel):
    """Graph context handed to planners (never an exploitability claim)."""

    node_count: int = 0
    edge_count: int = 0
    open_path_count: int = 0
    uncertain_path_count: int = 0
    gaps: list[str] = Field(default_factory=list)
    edges: list[GraphEdgeView] = Field(default_factory=list)


class PlannerContext(BaseModel):
    """Structured context the planner reasons over."""

    mission_id: MissionID
    objective: str
    seed_target: str
    scope: TargetScope
    policy: MissionPolicy
    routing: CapabilityRouting
    world_entities: list[AssetSummary] = Field(default_factory=list)
    recent_evidence: list[EvidenceViewRow] = Field(default_factory=list)
    graph: GraphSummary = Field(default_factory=GraphSummary)
    previous_actions: list[str] = Field(default_factory=list)
    steps_used: int = 0
    steps_limit: int = 0
    capability_calls_used: int = 0
    capability_calls_limit: int = 0
    runtime_seconds_remaining: float = 0.0
    valid_llm: bool = False


class InstructionRecord(BaseModel):
    """An auditable record of one planner decision through its lifecycle."""

    mission_id: MissionID
    capability: str
    target: str
    reason: str
    source: PlannerSource = PlannerSource.RULE
    priority: Priority = Priority.MEDIUM
    status: InvestigationStatus = InvestigationStatus.PLANNED
    note: str | None = None
    planned_at: float = Field(default_factory=time.time)
    approved_at: float | None = None
    executed_at: float | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class ExecutionPhase(str, Enum):
    """Current phase of the orchestration loop."""

    PLANNING = "planning"
    EXECUTING = "executing"
    REPLANNING = "replanning"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class MissionRuntimeState(BaseModel):
    """In-memory execution state for a single mission."""

    mission_id: MissionID
    session_id: SessionID | None = None
    phase: ExecutionPhase = ExecutionPhase.PLANNING
    stop_reason: StopReason | None = None
    steps_completed: int = 0
    steps_remaining: int = 0
    capability_calls: int = 0
    replans: int = 0
    invalid_plans: int = 0
    duplicate_evictions: int = 0
    redundant_steps: int = 0
    started_at: float | None = None
    finished_at: float | None = None
    last_decision: PlannerDecision | None = None
    last_instruction: InstructionRecord | None = None
    instructions: list[InstructionRecord] = Field(default_factory=list)

    def active_instruction(self, capability: str, target: str) -> InstructionRecord | None:
        needle = (capability, target)
        for record in reversed(self.instructions):
            if (record.capability, record.target) == needle:
                return record
        return None


class MissionSummary(BaseModel):
    """A mission plus its live progress, for the console."""

    mission_id: MissionID
    name: str
    objective: str
    seed_target: str
    status: str
    profile: AssessmentProfile = AssessmentProfile.AUTHORIZED_ASSESSMENT
    policy: MissionPolicy = Field(default_factory=MissionPolicy)
    scope: TargetScope
    runtime: MissionRuntimeState


__all__ = [
    "AdapterMode",
    "AssetSummary",
    "AssessmentProfile",
    "CapabilityRouting",
    "CapabilityView",
    "CapabilityViewRow",
    "DecisionKind",
    "ExecutionPhase",
    "EvidenceViewRow",
    "GraphEdgeView",
    "GraphSummary",
    "InstructionRecord",
    "InvestigationStatus",
    "MissionPolicy",
    "MissionRuntimeState",
    "MissionSetup",
    "MissionSummary",
    "PlannerContext",
    "PlannerDecision",
    "PlannerSource",
    "Priority",
    "ScopeClassification",
    "StopReason",
]
