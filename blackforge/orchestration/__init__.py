"""Mission orchestration layer for the Blackforge Development Console.

Architecture contract (Phase 14.1):

* The planner *proposes* a single typed investigation.
* The deterministic :class:`MissionOrchestrator` *decides* whether it may
  execute, enforcing registration, authorization, scope and adapter gates
  before any transport runs.
* Evidence produced by an execution flows into memory, the world model and,
  through the attack-graph builder, back to the planner as structured,
  redaction-safe context.

Nothing in this package spawns a process or evaluates code.
"""

from blackforge.orchestration.adapters import (
    RealAdapterRegistry,
    RealObservation,
    RealObservationAdapter,
)
from blackforge.orchestration.models import (
    AdapterMode,
    AssessmentProfile,
    CapabilityRouting,
    CapabilityView,
    CapabilityViewRow,
    DecisionKind,
    EvidenceViewRow,
    ExecutionPhase,
    GraphEdgeView,
    GraphSummary,
    InstructionRecord,
    InvestigationStatus,
    MissionPolicy,
    MissionRuntimeState,
    MissionSetup,
    MissionSummary,
    PlannerContext,
    PlannerDecision,
    PlannerSource,
    Priority,
    ScopeClassification,
    StopReason,
)
from blackforge.orchestration.orchestrator import (
    DispatchOutcome,
    MissionOrchestrator,
    OrchestrationError,
)
from blackforge.orchestration.planner import (
    LLMPlanner,
    MockPlanner,
    PlannerBase,
    PlannerError,
    PlannerInvalidDecision,
    RuleBasedPlanner,
)
from blackforge.orchestration.routing import CapabilityRouter

__all__ = [
    "AdapterMode",
    "AssessmentProfile",
    "CapabilityRouter",
    "CapabilityRouting",
    "CapabilityView",
    "CapabilityViewRow",
    "DecisionKind",
    "DispatchOutcome",
    "EvidenceViewRow",
    "ExecutionPhase",
    "GraphEdgeView",
    "GraphSummary",
    "InstructionRecord",
    "InvestigationStatus",
    "LLMPlanner",
    "MissionOrchestrator",
    "MissionPolicy",
    "MissionRuntimeState",
    "MissionSetup",
    "MissionSummary",
    "MockPlanner",
    "OrchestrationError",
    "PlannerBase",
    "PlannerContext",
    "PlannerDecision",
    "PlannerError",
    "PlannerInvalidDecision",
    "PlannerSource",
    "Priority",
    "RealAdapterRegistry",
    "RealObservation",
    "RealObservationAdapter",
    "RuleBasedPlanner",
    "ScopeClassification",
    "StopReason",
]
