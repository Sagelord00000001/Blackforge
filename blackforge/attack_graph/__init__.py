"""Phase 14 — Attack Graph & Autonomous Planner Foundation.

Provides a derived, evidence-driven analytical graph over the BLACKFORGE
world model plus a bounded, deterministic, fail-closed assessment planner.

Safety contract (enforced across the module):

* The graph is a *relational view* — POTENTIAL PATH ≠ SUCCESSFUL ATTACK.
* Rules derive facts only from world-model relationships and evidence.
* The planner only selects registered capabilities through the existing
  Scope → Authorization → Capability pipeline; it never executes anything.
"""

from blackforge.attack_graph.actions import (
    EvidenceGap,
    candidate_actions,
    compute_gaps,
    saturation_reached,
)
from blackforge.attack_graph.builder import (
    AttackGraphBuilder,
    AttackGraphBuildRequest,
    AttackGraphBuildResult,
)
from blackforge.attack_graph.graph import AttackGraph
from blackforge.attack_graph.materializer import (
    AttackGraphMemoryMaterializer,
    MaterializeEntry,
    MaterializeReport,
)
from blackforge.attack_graph.models import (
    AssessmentPlan,
    AttackGraphEdge,
    AttackGraphNode,
    CandidateAction,
    ExpectedEvidence,
    GraphDerivation,
    GraphLifecycle,
    GraphPath,
    GraphRelationship,
    GraphState,
    PathState,
    PlanStatus,
    PlanStep,
    PlanStepStatus,
    Prerequisite,
    PrerequisiteState,
)
from blackforge.attack_graph.planner import (
    AssessmentMetadata,
    AssessmentPlanner,
    IdleBudgetTracker,
    PlanningRequest,
)
from blackforge.attack_graph.query import (
    AttackGraphQuery,
    PathOutcome,
    classify_path,
    missing_prerequisites,
    path_edges,
    path_nodes,
)
from blackforge.attack_graph.repository import (
    AttackGraphRepository,
    InMemoryAttackGraphRepository,
    SQLiteAttackGraphRepository,
)
from blackforge.attack_graph.rules import (
    DerivedEdgeSpec,
    GraphRule,
    GraphRuleContext,
    default_graph_rules,
    hypothesis_edges,
)
from blackforge.attack_graph.scoring import (
    AssessmentFactors,
    AssessmentScore,
    assess,
)
from blackforge.attack_graph.validation import (
    assert_safe_graph_relationship,
    graph_contains_offensive_semantics,
    validate_edge,
    validate_node_state,
    validate_path,
    validate_plan,
)

__all__ = [
    "AssessmentMetadata",
    "AssessmentPlan",
    "AssessmentPlanner",
    "AssessmentScore",
    "AssessmentFactors",
    "AttackGraph",
    "AttackGraphBuildRequest",
    "AttackGraphBuilder",
    "AttackGraphBuildResult",
    "AttackGraphEdge",
    "AttackGraphMemoryMaterializer",
    "AttackGraphNode",
    "AttackGraphQuery",
    "AttackGraphRepository",
    "CandidateAction",
    "DerivedEdgeSpec",
    "EvidenceGap",
    "ExpectedEvidence",
    "GraphDerivation",
    "GraphLifecycle",
    "GraphPath",
    "GraphRelationship",
    "GraphRule",
    "GraphRuleContext",
    "GraphState",
    "IdleBudgetTracker",
    "InMemoryAttackGraphRepository",
    "MaterializeEntry",
    "MaterializeReport",
    "PathOutcome",
    "PathState",
    "PlanStatus",
    "PlanStep",
    "PlanStepStatus",
    "PlanningRequest",
    "Prerequisite",
    "PrerequisiteState",
    "SQLiteAttackGraphRepository",
    "assess",
    "assert_safe_graph_relationship",
    "candidate_actions",
    "classify_path",
    "compute_gaps",
    "default_graph_rules",
    "graph_contains_offensive_semantics",
    "hypothesis_edges",
    "missing_prerequisites",
    "path_edges",
    "path_nodes",
    "saturation_reached",
    "validate_edge",
    "validate_node_state",
    "validate_path",
    "validate_plan",
]
