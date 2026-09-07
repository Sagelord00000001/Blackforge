"""Structural and epistemic validation for the attack-graph layer.

All validators are pure and deterministic; they raise
:class:`GraphValidationError` / :class:`PlanningError` (from
``blackforge.core.errors``) so callers fail closed. They never mutate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from blackforge.attack_graph.models import (
    GraphLifecycle,
    GraphRelationship,
    GraphState,
    PlanStatus,
)
from blackforge.core.errors import GraphValidationError, PlanningError

if TYPE_CHECKING:
    from blackforge.attack_graph.models import (
        AssessmentPlan,
        AttackGraphEdge,
        AttackGraphNode,
        GraphPath,
    )

# Graph relationships whose *state* may legitimately escalate past INFERRED.
_VALIDATABLE_RELATIONSHIPS = frozenset(
    {
        GraphRelationship.EXPOSES,
        GraphRelationship.POTENTIALLY_LEADS_TO,
        GraphRelationship.REQUIRES_VALIDATION,
    }
)

# Predicates the attack-graph layer must never emit.
_OFFENSIVE_RELATIONSHIPS = frozenset(
    {
        "exploits",
        "compromises",
        "intrudes",
        "cracks",
        "bypasses_auth",
        "exfiltrates",
        "escalates",
    }
)


def assert_safe_graph_relationship(relationship: GraphRelationship) -> None:
    """Fail closed on offensive graph predicates."""
    if relationship.value in _OFFENSIVE_RELATIONSHIPS:
        raise GraphValidationError(
            f"graph relationship '{relationship.value}' is offensive and unsupported"
        )


def validate_node_state(
    node: AttackGraphNode, supporting_validated: int = 0
) -> None:
    """A node may only be VALIDATED when its supporting evidence is validated."""
    if node.state == GraphState.VALIDATED and supporting_validated == 0:
        raise GraphValidationError(
            f"node {node.id} claims VALIDATED without validated supporting evidence"
        )
    if node.lifecycle == GraphLifecycle.ARCHIVED and node.state == GraphState.VALIDATED:
        raise GraphValidationError(
            f"archive node {node.id} may not carry a VALIDATED state"
        )


def validate_edge(
    edge: AttackGraphEdge,
    source_validated: bool = False,
    target_validated: bool = False,
) -> None:
    if edge.relationship in _VALIDATABLE_RELATIONSHIPS:
        if edge.state == GraphState.VALIDATED and not (source_validated and target_validated):
            raise GraphValidationError(
                f"validatable edge {edge.id} is VALIDATED without validated endpoints"
            )
    else:
        if edge.state == GraphState.VALIDATED:
            raise GraphValidationError(
                f"non-validatable edge {edge.id} must not carry VALIDATED state"
            )
    if edge.lifecycle == GraphLifecycle.ARCHIVED and edge.state == GraphState.VALIDATED:
        raise GraphValidationError(f"archived edge {edge.id} may not hold VALIDATED state")


def validate_path(path: GraphPath) -> None:
    if path.length <= 0:
        raise GraphValidationError(f"path {path.id} has zero length")
    if len(path.node_ids) != len(path.edge_ids) + 1:
        raise GraphValidationError(
            f"path {path.id} node/edge topology is inconsistent "
            f"({len(path.node_ids)} nodes vs {len(path.edge_ids)} edges)"
        )
    if path.state.value.endswith("_path") is False and path.state.value != "insufficient_evidence":
        raise GraphValidationError(f"path {path.id} has an invalid state {path.state}")


def validate_plan(plan: AssessmentPlan) -> None:
    if plan.max_steps <= 0 or plan.max_candidates <= 0:
        raise PlanningError("plan bounds must be positive")
    orders = [step.order for step in plan.steps]
    if orders != sorted(orders):
        raise PlanningError(f"plan {plan.id} steps are not sequentially ordered")
    duplicate_capabilities = _duplicates(
        [step.action.capability_name for step in plan.steps]
    )
    if duplicate_capabilities:
        raise PlanningError(
            f"plan {plan.id} repeats capabilities: {sorted(duplicate_capabilities)}"
        )
    if plan.status == PlanStatus.PLAN_READY and not plan.steps:
        raise PlanningError(f"plan {plan.id} is PLAN_READY without steps")


def graph_contains_offensive_semantics(relationships: list[str]) -> bool:
    """Probe a graph's relationship vocabulary for offensive semantics."""
    return bool(_OFFENSIVE_RELATIONSHIPS.intersection(relationships))


def _duplicates(items: list[str]) -> set[str]:
    seen: set[str] = set()
    dupes: set[str] = set()
    for item in items:
        if item in seen:
            dupes.add(item)
        seen.add(item)
    return dupes
