from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from pydantic import BaseModel, Field

from blackforge.attack_graph.models import (
    AttackGraphEdge,
    AttackGraphNode,
    GraphDerivation,
    GraphRelationship,
    GraphState,
    Prerequisite,
    PrerequisiteState,
)
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    MissionID,
    SessionID,
    WorldEntityID,
)
from blackforge.world_model.models import RelationshipType, WorldEntity, WorldRelationship

# Relationship-type families the graph can honestly derive from.
_EXPOSURE_RELATIONSHIPS = frozenset(
    {
        RelationshipType.EXPOSES,
        RelationshipType.SERVES,
        RelationshipType.PROXIES,
        RelationshipType.FRONTED_BY,
        RelationshipType.RUNS_SERVICE,
    }
)
_DEPENDENCY_RELATIONSHIPS = frozenset(
    {
        RelationshipType.DEPENDS_ON,
        RelationshipType.REQUIRES,
        RelationshipType.USES,
        RelationshipType.CALLS,
    }
)
_REACHABILITY_RELATIONSHIPS = frozenset(
    {RelationshipType.CONNECTS_TO, RelationshipType.ROUTES_TO}
)
_AUTHN_RELATIONSHIPS = frozenset({RelationshipType.AUTHENTICATES_TO})
_ACCESS_RELATIONSHIPS = frozenset(
    {RelationshipType.AUTHORIZED_FOR, RelationshipType.HAS_ROLE, RelationshipType.HAS_PERMISSION}
)
_CONSTRAINT_RELATIONSHIPS = frozenset(
    {RelationshipType.HAS_NETWORK_POLICY, RelationshipType.PROTECTS}
)
_SOURCE_RUNTIME_SUFFIXES = (":source", ":runtime")


class GraphRuleContext(BaseModel):
    """Immutable snapshot the deterministic rules read; nothing is executed."""

    mission_id: MissionID
    session_id: SessionID | None = None
    entities: dict[str, WorldEntity] = Field(default_factory=dict)
    relationships: list[WorldRelationship] = Field(default_factory=list)
    relationship_evidence: dict[str, list[EvidenceID]] = Field(default_factory=dict)


class DerivedEdgeSpec(BaseModel):
    """A relationship the rule engine derived from world-model sources."""

    source_entity_id: WorldEntityID
    target_entity_id: WorldEntityID
    relationship: GraphRelationship
    state: GraphState = GraphState.INFERRED
    confidence: Confidence = Confidence.MEDIUM
    prerequisites: list[Prerequisite] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    properties: dict = Field(default_factory=dict)
    derivation: GraphDerivation = Field(default_factory=GraphDerivation)


class GraphRule:
    """A versioned, deterministic derivation rule.

    Rules are pure: they read a :class:`GraphRuleContext` and return derived
    edge specs. They never execute anything and never introduce facts the
    world model does not already support.
    """

    def __init__(
        self,
        rule_id: str,
        description: str,
        derive: Callable[[GraphRuleContext], list[DerivedEdgeSpec]],
    ) -> None:
        self.rule_id = rule_id
        self.description = description
        self.derive = derive

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"GraphRule({self.rule_id})"


def _evidence_for(ctx: GraphRuleContext, rel: WorldRelationship) -> list[EvidenceID]:
    return list(ctx.relationship_evidence.get(str(rel.id), []))


def _derived(
    ctx: GraphRuleContext,
    rel: WorldRelationship,
    relationship: GraphRelationship,
    *,
    state: GraphState = GraphState.INFERRED,
    confidence: Confidence | None = None,
    prerequisites: list[Prerequisite] | None = None,
    constraints: list[str] | None = None,
    assumptions: list[str] | None = None,
    note: str | None = None,
) -> DerivedEdgeSpec:
    return DerivedEdgeSpec(
        source_entity_id=rel.source_entity_id,
        target_entity_id=rel.target_entity_id,
        relationship=relationship,
        state=state,
        confidence=confidence or rel.confidence,
        prerequisites=list(prerequisites or []),
        constraints=list(constraints or []),
        assumptions=list(assumptions or []),
        derivation=GraphDerivation(
            rule_id=rel.relationship_type.value,
            source_relationship_ids=[str(rel.id)],
            source_evidence_ids=_evidence_for(ctx, rel),
            note=note,
        ),
    )


def exposure_rule() -> GraphRule:
    """Descriptive exposure edges (EXPOSES, SERVES, PROXIES, ...)."""

    def derive(ctx: GraphRuleContext) -> list[DerivedEdgeSpec]:
        specs: list[DerivedEdgeSpec] = []
        for rel in ctx.relationships:
            if rel.relationship_type in _EXPOSURE_RELATIONSHIPS:
                specs.append(
                    _derived(ctx, rel, GraphRelationship.EXPOSES, note="descriptive exposure")
                )
        return specs

    return GraphRule(
        "ag_exposure",
        "Map world-model exposure relationships to descriptive EXPOSES edges.",
        derive,
    )


def dependency_rule() -> GraphRule:
    """Dependency edges (DEPENDS_ON, REQUIRES, USES, CALLS)."""

    def derive(ctx: GraphRuleContext) -> list[DerivedEdgeSpec]:
        specs: list[DerivedEdgeSpec] = []
        for rel in ctx.relationships:
            if rel.relationship_type in _DEPENDENCY_RELATIONSHIPS:
                specs.append(
                    _derived(ctx, rel, GraphRelationship.DEPENDS_ON, note="dependency")
                )
        return specs

    return GraphRule(
        "ag_dependency",
        "Map world-model dependency relationships to DEPENDS_ON edges.",
        derive,
    )


def reachability_rule() -> GraphRule:
    """Bidirectional REACHABLE_FROM edges derived from connectivity edges.

    Reachability is a purely descriptive statement ("A is reachable from B",
    "B is reachable from A") — it never asserts that any access is possible,
    only that a network-level connection exists in the model.
    """

    def derive(ctx: GraphRuleContext) -> list[DerivedEdgeSpec]:
        specs: list[DerivedEdgeSpec] = []
        for rel in ctx.relationships:
            if rel.relationship_type not in _REACHABILITY_RELATIONSHIPS:
                continue
            base = rel
            for source, target in (
                (rel.source_entity_id, rel.target_entity_id),
                (rel.target_entity_id, rel.source_entity_id),
            ):
                specs.append(
                    DerivedEdgeSpec(
                        source_entity_id=source,
                        target_entity_id=target,
                        relationship=GraphRelationship.REACHABLE_FROM,
                        state=GraphState.INFERRED,
                        confidence=rel.confidence,
                        derivation=GraphDerivation(
                            rule_id="ag_reachability",
                            source_relationship_ids=[str(base.id)],
                            source_evidence_ids=_evidence_for(ctx, base),
                            note="descriptive network reachability",
                        ),
                    )
                )
        return specs

    return GraphRule(
        "ag_reachability",
        "Derive symmetric REACHABLE_FROM edges from CONNECTS_TO / ROUTES_TO.",
        derive,
    )


def access_rule() -> GraphRule:
    """Authentication/authorization surface edges.

    ``AUTHENTICATES_TO`` becomes ``REQUIRES_VALIDATION``: the identity
    relationship exists but must be validated by an assessment step. RBAC
    edges become ``PROVIDES_ACCESS_TO`` — a descriptive access grant, never a
    compromise claim.
    """

    def derive(ctx: GraphRuleContext) -> list[DerivedEdgeSpec]:
        specs: list[DerivedEdgeSpec] = []
        for rel in ctx.relationships:
            if rel.relationship_type in _AUTHN_RELATIONSHIPS:
                specs.append(
                    _derived(
                        ctx,
                        rel,
                        GraphRelationship.REQUIRES_VALIDATION,
                        assumptions=["identity relationship requires assessment validation"],
                        note="authentication surface",
                    )
                )
            elif rel.relationship_type in _ACCESS_RELATIONSHIPS:
                specs.append(
                    _derived(
                        ctx,
                        rel,
                        GraphRelationship.PROVIDES_ACCESS_TO,
                        note="described access grant",
                    )
                )
        return specs

    return GraphRule(
        "ag_access",
        "Derive REQUIRES_VALIDATION / PROVIDES_ACCESS_TO from auth authz edges.",
        derive,
    )


def constraint_rule() -> GraphRule:
    """Policy/control constraints as CONSTRAINS edges."""

    def derive(ctx: GraphRuleContext) -> list[DerivedEdgeSpec]:
        specs: list[DerivedEdgeSpec] = []
        for rel in ctx.relationships:
            if rel.relationship_type in _CONSTRAINT_RELATIONSHIPS:
                specs.append(
                    _derived(ctx, rel, GraphRelationship.CONSTRAINS, note="control constraint")
                )
        return specs

    return GraphRule(
        "ag_constraint",
        "Map network-policy/protection relationships to CONSTRAINS edges.",
        derive,
    )


def _main_component_name(name: str) -> str:
    for suffix in _SOURCE_RUNTIME_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def correlation_discrepancy_rule() -> GraphRule:
    """Surface Phase-13 source/runtime discrepancies as validation needs.

    A ``DIFFERS_FROM`` relationship between a ``:source`` / ``:runtime``
    sibling pair (a declared vs observed mismatch) on a component that is also
    exposed downgrades the exposure to ``REQUIRES_VALIDATION``: the runtime
    behavior is not trusted until an assessment step validates it. State stays
    INFERRED (derived from observed world edges) and never implies a
    vulnerability.
    """

    def derive(ctx: GraphRuleContext) -> list[DerivedEdgeSpec]:
        differs = [
            rel
            for rel in ctx.relationships
            if rel.relationship_type == RelationshipType.DIFFERS_FROM
        ]
        entities = {str(e.id): e for e in ctx.entities.values()}

        def component(rel: WorldRelationship) -> str:
            src = entities.get(str(rel.source_entity_id))
            return _main_component_name(src.name) if src else ""

        def component_id(rel: WorldRelationship) -> str | None:
            comp = component(rel)
            for entity in ctx.entities.values():
                if entity.name == comp:
                    return str(entity.id)
            return None

        specs: list[DerivedEdgeSpec] = []
        seen_mains: set[str] = set()
        for rel in differs:
            main_id = component_id(rel)
            if main_id is None or main_id in seen_mains:
                continue
            seen_mains.add(main_id)
            exposed_target = _exposed_target_id(ctx, main_id)
            if exposed_target is None:
                continue
            conf = rel.confidence.to_score() if rel.confidence else 0.0
            state = (
                GraphState.INFERRED
                if conf >= Confidence.MEDIUM.to_score()
                else GraphState.HYPOTHESIZED
            )
            prereqs = [
                Prerequisite(
                    description="declared-vs-runtime discrepancy is validated",
                    state=PrerequisiteState.UNKNOWN,
                    required_evidence=["validation_result"],
                    note=f"source/runtime discrepancy on {component(rel)}",
                )
            ]
            specs.append(
                DerivedEdgeSpec(
                    source_entity_id=WorldEntityID(main_id),
                    target_entity_id=exposed_target,
                    relationship=GraphRelationship.REQUIRES_VALIDATION,
                    state=state,
                    confidence=rel.confidence,
                    prerequisites=prereqs,
                    assumptions=[
                        "declared and runtime state differ; behavior requires validation"
                    ],
                    derivation=GraphDerivation(
                        rule_id="ag_correlation_discrepancy",
                        source_relationship_ids=[str(rel.id)],
                        source_evidence_ids=_evidence_for(ctx, rel),
                        note="source/runtime discrepancy on exposed component",
                    ),
                )
            )
        return specs

    return GraphRule(
        "ag_correlation_discrepancy",
        "Exposed component with source/runtime discrepancy requires validation.",
        derive,
    )


def _exposed_target_id(ctx: GraphRuleContext, entity_id: str) -> WorldEntityID | None:
    for rel in ctx.relationships:
        if rel.relationship_type not in _EXPOSURE_RELATIONSHIPS and rel.relationship_type not in (
            RelationshipType.HOSTS,
            RelationshipType.RUNS,
        ):
            continue
        if str(rel.source_entity_id) == entity_id:
            return rel.target_entity_id
        if str(rel.target_entity_id) == entity_id:
            return rel.source_entity_id
    return None


def hypothesis_edges(
    nodes: list[AttackGraphNode],
    edges: list[AttackGraphEdge],
) -> list[DerivedEdgeSpec]:
    """Post-pass: connect exposed fronts to auth-requiring surfaces.

    A node is an assessment surface when it is both the target of an exposure
    edge and the target of a ``REQUIRES_VALIDATION`` edge. For each such node
    the rule adds a clearly-labeled ``POTENTIALLY_LEADS_TO`` hypothesis from
    the exposed front to the surface. Everything here is HYPOTHESIZED/LOW —
    a potential relationship, not a claim of exploitability.
    """
    exposure_in: dict[str, list[str]] = {}
    validation_edges: dict[str, list[str]] = {}
    access_in: dict[str, bool] = {}
    for edge in edges:
        tgt = str(edge.target_node_id)
        if edge.relationship == GraphRelationship.EXPOSES:
            exposure_in.setdefault(tgt, []).append(str(edge.source_node_id))
        elif edge.relationship == GraphRelationship.REQUIRES_VALIDATION:
            validation_edges.setdefault(tgt, []).append(str(edge.source_node_id))
        elif edge.relationship == GraphRelationship.PROVIDES_ACCESS_TO:
            access_in[tgt] = True

    node_by_id = {str(n.id): n for n in nodes}
    specs: list[DerivedEdgeSpec] = []
    for surface_node_id, _fronts in validation_edges.items():
        fronts = exposure_in.get(surface_node_id)
        if not fronts:
            continue
        surface = node_by_id[surface_node_id]
        auth_prereq = Prerequisite(
            description=f"validated authentication for {surface.name}",
            state=(
                PrerequisiteState.SATISFIED
                if access_in.get(surface_node_id)
                else PrerequisiteState.UNKNOWN
            ),
            required_evidence=["validation_result"],
        )
        for front in fronts:
            front_node = node_by_id[front]
            prereqs = [
                auth_prereq,
                Prerequisite(
                    description=f"discrepancy on {surface.name} evaluated",
                    state=PrerequisiteState.UNKNOWN,
                    required_evidence=["validation_result"],
                ),
            ]
            specs.append(
                DerivedEdgeSpec(
                    source_entity_id=front_node.entity_id,
                    target_entity_id=surface.entity_id,
                    relationship=GraphRelationship.POTENTIALLY_LEADS_TO,
                    state=GraphState.HYPOTHESIZED,
                    confidence=Confidence.LOW,
                    prerequisites=prereqs,
                    assumptions=[
                        "potential relationship only; not exploitation",
                        "an assessment step must validate before any stronger claim",
                    ],
                    derivation=GraphDerivation(
                        rule_id="ag_hypothesis",
                        source_entity_ids=[str(front_node.entity_id)],
                        note="exposed front connected to auth-requiring surface",
                    ),
                )
            )
    return specs


def default_graph_rules() -> list[GraphRule]:
    """Deterministic default rule set used by the builder."""
    return [
        exposure_rule(),
        dependency_rule(),
        reachability_rule(),
        access_rule(),
        constraint_rule(),
        correlation_discrepancy_rule(),
    ]
