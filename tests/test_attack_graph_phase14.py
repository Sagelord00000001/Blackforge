from __future__ import annotations

import re
from pathlib import Path

import pytest

from blackforge.attack_graph import (
    AssessmentPlan,
    AssessmentPlanner,
    AttackGraph,
    AttackGraphBuilder,
    AttackGraphBuildRequest,
    AttackGraphEdge,
    AttackGraphMemoryMaterializer,
    AttackGraphNode,
    AttackGraphQuery,
    CandidateAction,
    EvidenceGap,
    ExpectedEvidence,
    GraphDerivation,
    GraphLifecycle,
    GraphPath,
    GraphRelationship,
    GraphState,
    InMemoryAttackGraphRepository,
    MaterializeEntry,
    PathOutcome,
    PathState,
    PlanningRequest,
    PlanStatus,
    PlanStep,
    Prerequisite,
    PrerequisiteState,
    SQLiteAttackGraphRepository,
    assert_safe_graph_relationship,
    assess,
    candidate_actions,
    classify_path,
    compute_gaps,
    graph_contains_offensive_semantics,
    missing_prerequisites,
    path_edges,
    path_nodes,
    saturation_reached,
    validate_edge,
    validate_node_state,
    validate_path,
    validate_plan,
)
from blackforge.attack_graph.models import (
    evidence_status_to_graph_state,
    graph_edge_dedup_key,
    graph_node_dedup_key,
    graph_state_to_evidence_status,
)
from blackforge.attack_graph.query import (
    graph_contains_offensive_semantics as query_offensive_semantics,
)
from blackforge.attack_graph.rules import (
    GraphRuleContext,
    correlation_discrepancy_rule,
    default_graph_rules,
    exposure_rule,
)
from blackforge.authorization import AuthorizationBoundary
from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import GraphValidationError, PlanningError, WorldRuleError
from blackforge.core.types import (
    Confidence,
    EvidenceStatus,
    EvidenceType,
    RiskLevel,
    TargetType,
    WorldEntityID,
)
from blackforge.evidence.models import Evidence, Provenance
from blackforge.evidence.repository import InMemoryEvidenceRepository
from blackforge.evidence.store import EvidenceStore
from blackforge.memory.manager import MemoryManager
from blackforge.runtime.bootstrap import bootstrap
from blackforge.scope.models import Target, TargetScope
from blackforge.world_model.models import (
    EntitySpec,
    EntityType,
    EvidenceLinkRef,
    RelationshipSpec,
    RelationshipType,
    WorldEntity,
)
from blackforge.world_model.query import RelationshipQuery, WorldQuery
from blackforge.world_model.repository import InMemoryWorldRepository
from blackforge.world_model.store import WorldModelStore

MID = "mission_p14"
SID = "session_p14"
TARGET = "https://api.aelionix.io/"

_PKG_ROOT = Path(__file__).resolve().parents[1] / "blackforge" / "attack_graph"

_OFFENSIVE_WORDS = frozenset(
    {"exploits", "compromises", "intrudes", "cracks", "breaks", "bypasses",
     "exfiltrates", "escalates"}
)


class _StubCapability(Capability):
    def __init__(
        self,
        name: str,
        evidence_types_produced: list[str] | None = None,
    ) -> None:
        self._meta = CapabilityMeta(
            name=name,
            evidence_types_produced=list(
                evidence_types_produced or ["validation_result"]
            ),
        )

    def meta(self) -> CapabilityMeta:
        return self._meta

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        return CapabilityResult(success=True, output={"ok": True})


# ---------------------------------------------------------------------- #
# Fixtures
# ---------------------------------------------------------------------- #
def _store_pair():
    world = WorldModelStore(repository=InMemoryWorldRepository())
    evstore = EvidenceStore(repository=InMemoryEvidenceRepository())
    return world, evstore


def _evidence(evstore: EvidenceStore, target: str = "api.aelionix.io") -> Evidence:
    return evstore.add(
        Evidence(
            mission_id=MID,
            source_capability="http_probe",
            target=target,
            evidence_type=EvidenceType.OBSERVATION,
            status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            summary="probe observation",
            provenance=Provenance(capability_id="http_probe"),
        )
    )


def _exposed_app_fixture():
    """An exposed application behind an edge endpoint (SERVES -> EXPOSES)."""
    world, evstore = _store_pair()
    ev = _evidence(evstore)
    front = world.add_entity(
        EntitySpec(
            mission_id=MID,
            entity_type=EntityType.EDGE_ENDPOINT,
            name="edge-fe",
            epistemic_status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    ).entity
    app = world.add_entity(
        EntitySpec(
            mission_id=MID,
            entity_type=EntityType.APPLICATION,
            name="payments-app",
            properties={"url": TARGET},
            epistemic_status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    ).entity
    world.add_relationship(
        RelationshipSpec(
            mission_id=MID,
            relationship_type=RelationshipType.SERVES,
            source_entity_id=front.id,
            target_entity_id=app.id,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    )
    return world, evstore, front, app, ev


def _correlation_fixture():
    """A component with a declared-vs-runtime discrepancy on an exposed app."""
    world, evstore = _store_pair()
    ev = _evidence(evstore)
    main = world.add_entity(
        EntitySpec(
            mission_id=MID,
            entity_type=EntityType.APPLICATION,
            name="api-svc",
            epistemic_status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    ).entity
    app = world.add_entity(
        EntitySpec(
            mission_id=MID,
            entity_type=EntityType.APPLICATION,
            name="payments-app",
            properties={"url": TARGET},
            epistemic_status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    ).entity
    front = world.add_entity(
        EntitySpec(
            mission_id=MID,
            entity_type=EntityType.EDGE_ENDPOINT,
            name="edge-fe",
            epistemic_status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    ).entity
    source = world.add_entity(
        EntitySpec(
            mission_id=MID,
            entity_type=EntityType.SOURCE_COMPONENT,
            name="api-svc:source",
            epistemic_status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    ).entity
    runtime = world.add_entity(
        EntitySpec(
            mission_id=MID,
            entity_type=EntityType.SOURCE_COMPONENT,
            name="api-svc:runtime",
            epistemic_status=EvidenceStatus.OBSERVED,
            confidence=Confidence.HIGH,
            evidence=[EvidenceLinkRef(evidence_id=ev.id)],
        )
    ).entity
    world.add_relationship(
        RelationshipSpec(
            mission_id=MID,
            relationship_type=RelationshipType.DIFFERS_FROM,
            source_entity_id=source.id,
            target_entity_id=runtime.id,
            confidence=Confidence.HIGH,
        )
    )
    world.add_relationship(
        RelationshipSpec(
            mission_id=MID,
            relationship_type=RelationshipType.SERVES,
            source_entity_id=front.id,
            target_entity_id=app.id,
            confidence=Confidence.HIGH,
        )
    )
    world.add_relationship(
        RelationshipSpec(
            mission_id=MID,
            relationship_type=RelationshipType.SERVES,
            source_entity_id=main.id,
            target_entity_id=app.id,
            confidence=Confidence.HIGH,
        )
    )
    return world


def _build_graph(world=None, *, include_hypothesis: bool = True) -> AttackGraph:
    world = world or _exposed_app_fixture()[0]
    builder = AttackGraphBuilder(world_model=world)
    result = builder.build(
        AttackGraphBuildRequest(
            mission_id=MID,
            session_id=SID,
            include_hypothesis_edges=include_hypothesis,
        )
    )
    return result.graph


def _manual_graph(entities, edge_specs) -> AttackGraph:
    graph = AttackGraph(MID)
    nodes = {}
    for ent_id, etype, state in entities:
        node = graph.add_node(
            AttackGraphNode(
                mission_id=MID,
                graph_id=graph.graph_id,
                entity_id=WorldEntityID(ent_id),
                entity_type=etype,
                name=ent_id,
                state=state,
            )
        )
        nodes[str(node.entity_id)] = node
    for src, tgt, relationship, state in edge_specs:
        graph.add_edge(
            AttackGraphEdge(
                mission_id=MID,
                graph_id=graph.graph_id,
                source_node_id=nodes[src].id,
                target_node_id=nodes[tgt].id,
                source_entity_id=nodes[src].entity_id,
                target_entity_id=nodes[tgt].entity_id,
                relationship=relationship,
                state=state,
            )
        )
    return graph


def _registry(names=("app_probe", "backend_probe", "http_probe")) -> CapabilityRegistry:
    reg = CapabilityRegistry()
    for name in names:
        reg.register(_StubCapability(name))
    return reg


def _scope(
    targets: list[Target] | None = None,
    caps: list[str] | None = None,
    max_risk: RiskLevel = RiskLevel.HIGH,
) -> TargetScope:
    return TargetScope(
        mission_id=MID,
        allowed_targets=targets or [Target(value=TARGET, target_type=TargetType.URL)],
        allowed_capabilities=caps or [],
        max_risk_level=max_risk,
    )


def _planner(
    registry: CapabilityRegistry | None = None,
    repository: InMemoryAttackGraphRepository | None = None,
    builder: AttackGraphBuilder | None = None,
    auth: AuthorizationBoundary | None = None,
) -> AssessmentPlanner:
    return AssessmentPlanner(
        repository=repository,
        builder=builder,
        registry=registry or _registry(),
        authorization=auth,
    )


def _request(
    graph: AttackGraph | None = None,
    *,
    scope: TargetScope | None = None,
    mission_id: str = MID,
    **kwargs,
) -> PlanningRequest:
    kwargs.setdefault("session_id", SID)
    return PlanningRequest(
        mission_id=mission_id,
        scope=scope or _scope(),
        graph=graph,
        **kwargs,
    )


def _first_path(graph: AttackGraph) -> GraphPath:
    return AttackGraphQuery(graph).open_paths()[0]


# ---------------------------------------------------------------------- #
# Models
# ---------------------------------------------------------------------- #
class TestModels:
    def test_graph_relationship_enum_is_descriptive(self) -> None:
        values = {m.value for m in GraphRelationship}
        assert values == {
            "exposes",
            "requires",
            "depends_on",
            "reachable_from",
            "provides_access_to",
            "constrains",
            "blocked_by",
            "potentially_leads_to",
            "requires_validation",
        }
        assert values.isdisjoint(_OFFENSIVE_WORDS)

    def test_graph_state_and_path_state_values(self) -> None:
        assert sorted(GraphState.INSUFFICIENT_EVIDENCE.value) == sorted(
            "insufficient_evidence"
        )
        assert PathState.VALIDATED_PATH.value.endswith("_path")
        assert PathState.INSUFFICIENT_EVIDENCE.value == "insufficient_evidence"

    def test_unfiltered_state_mappings_never_elevate(self) -> None:
        assert (
            evidence_status_to_graph_state(EvidenceStatus.OBSERVED)
            == GraphState.OBSERVED
        )
        assert (
            evidence_status_to_graph_state(EvidenceStatus.INFERRED)
            == GraphState.INFERRED
        )
        assert (
            evidence_status_to_graph_state(EvidenceStatus.HYPOTHESIZED)
            == GraphState.HYPOTHESIZED
        )
        assert (
            evidence_status_to_graph_state(EvidenceStatus.VALIDATED)
            == GraphState.VALIDATED
        )

    def test_graph_state_maps_back_down_never_up(self) -> None:
        assert graph_state_to_evidence_status(GraphState.VALIDATED) == (
            EvidenceStatus.INFERRED
        )
        assert graph_state_to_evidence_status(GraphState.OBSERVED) == (
            EvidenceStatus.OBSERVED
        )
        assert graph_state_to_evidence_status(GraphState.INFERRED) == (
            EvidenceStatus.INFERRED
        )
        assert graph_state_to_evidence_status(GraphState.HYPOTHESIZED) == (
            EvidenceStatus.HYPOTHESIZED
        )
        assert graph_state_to_evidence_status(GraphState.CONTRADICTED) == (
            EvidenceStatus.HYPOTHESIZED
        )
        assert graph_state_to_evidence_status(GraphState.BLOCKED) == (
            EvidenceStatus.HYPOTHESIZED
        )

    def test_prerequisite_defaults(self) -> None:
        prereq = Prerequisite(description="d")
        assert prereq.state == PrerequisiteState.UNKNOWN
        assert prereq.required_evidence == []
        assert prereq.satisfied_by == []

    def test_graph_derivation_provenance(self) -> None:
        deriv = GraphDerivation(
            rule_id="r",
            source_relationship_ids=["rel-1"],
            source_evidence_ids=["ev-1"],
            note="n",
        )
        assert deriv.rule_id == "r"
        assert deriv.source_relationship_ids == ["rel-1"]
        assert deriv.source_evidence_ids == ["ev-1"]

    def test_attack_graph_node_defaults(self) -> None:
        node = AttackGraphNode(
            mission_id=MID,
            graph_id="graph-x",
            entity_id=WorldEntityID("e-1"),
            entity_type="application",
            name="app",
        )
        assert node.state == GraphState.INFERRED
        assert node.lifecycle == GraphLifecycle.ACTIVE
        assert node.confidence == Confidence.MEDIUM
        assert node.version == 1
        assert node.dedup_key is None

    def test_attack_graph_edge_defaults(self) -> None:
        node = AttackGraphNode(
            mission_id=MID,
            graph_id="g",
            entity_id=WorldEntityID("a"),
            entity_type="endpoint",
            name="a",
        )
        edge = AttackGraphEdge(
            mission_id=MID,
            graph_id="g",
            source_node_id=node.id,
            target_node_id=node.id,
            source_entity_id=WorldEntityID("a"),
            target_entity_id=WorldEntityID("b"),
            relationship=GraphRelationship.EXPOSES,
        )
        assert edge.state == GraphState.INFERRED
        assert edge.prerequisites == []
        assert edge.version == 1

    def test_dedup_keys_are_deterministic(self) -> None:
        key = graph_node_dedup_key(MID, "graph-1", "e-1")
        assert key == f"{MID}:graph-1:e-1"
        ekey = graph_edge_dedup_key(
            MID, "graph-1", GraphRelationship.EXPOSES, "a", "b"
        )
        assert ekey == f"{MID}:graph-1:exposes:a:b"

    def test_assessment_plan_capability_names(self) -> None:
        plan = AssessmentPlan(
            mission_id=MID,
            graph_id="g",
            steps=[
                PlanStep(
                    step_id="s1",
                    order=1,
                    action=CandidateAction(capability_name="app_probe", target="t", gap="g"),
                ),
                PlanStep(
                    step_id="s2",
                    order=2,
                    action=CandidateAction(capability_name="http_probe", target="t", gap="g"),
                ),
            ],
        )
        assert plan.capability_names == ["app_probe", "http_probe"]
        assert plan.status == PlanStatus.PLAN_READY

    def test_expected_evidence_and_candidate_action_fields(self) -> None:
        action = CandidateAction(
            capability_name="app_probe",
            target="t",
            gap="g",
            expected_evidence=[
                ExpectedEvidence(evidence_type="validation_result", description="d", target="t")
            ],
            rationale=["r"],
        )
        assert action.rank == 0
        assert action.risk_level == RiskLevel.LOW

    def test_graph_path_defaults(self) -> None:
        path = GraphPath(mission_id=MID, graph_id="g", start_entity_id="a", end_entity_id="b")
        assert path.state == PathState.HYPOTHESIZED_PATH
        assert path.length == 0
        assert path.assessment_priority == 0.0


# ---------------------------------------------------------------------- #
# AttackGraph
# ---------------------------------------------------------------------- #
class TestGraph:
    def _base_node(self, graph: AttackGraph, ent_id: str = "e-1") -> AttackGraphNode:
        return AttackGraphNode(
            mission_id=MID,
            graph_id=graph.graph_id,
            entity_id=WorldEntityID(ent_id),
            entity_type="application",
            name="app",
        )

    def test_add_node_sets_dedup_key(self) -> None:
        graph = AttackGraph(MID)
        node = self._base_node(graph)
        added = graph.add_node(node)
        assert added.dedup_key == graph_node_dedup_key(MID, graph.graph_id, "e-1")
        assert graph.node_count == 1

    def test_add_node_mission_mismatch_raises(self) -> None:
        graph = AttackGraph(MID)
        node = self._base_node(graph)
        node.mission_id = "other"
        with pytest.raises(ValueError):
            graph.add_node(node)

    def test_add_node_corroborates_identical_state(self) -> None:
        graph = AttackGraph(MID)
        first = graph.add_node(self._base_node(graph))
        second = graph.add_node(self._base_node(graph))
        assert first.id == second.id
        assert graph.node_count == 1
        assert graph.archived_nodes() == []

    def test_add_node_supersedes_different_state(self) -> None:
        graph = AttackGraph(MID)
        first = graph.add_node(self._base_node(graph, "e-1"))
        changed = self._base_node(graph, "e-1")
        changed.state = GraphState.HYPOTHESIZED
        second = graph.add_node(changed)
        assert second.supersedes == first.id
        assert second.version == 2
        assert graph.node_count == 1
        archived = graph.archived_nodes()
        assert len(archived) == 1
        assert archived[0].lifecycle == GraphLifecycle.SUPERSEDED

    def test_add_edge_unknown_node_raises(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        edge = AttackGraphEdge(
            mission_id=MID,
            graph_id=graph.graph_id,
            source_node_id=a.id,
            target_node_id="agn-missing",
            source_entity_id=WorldEntityID("a"),
            target_entity_id=WorldEntityID("zzz"),
            relationship=GraphRelationship.EXPOSES,
        )
        with pytest.raises(ValueError):
            graph.add_edge(edge)

    def test_add_edge_self_loop_raises(self) -> None:
        graph = AttackGraph(MID)
        node = graph.add_node(self._base_node(graph, "a"))
        edge = AttackGraphEdge(
            mission_id=MID,
            graph_id=graph.graph_id,
            source_node_id=node.id,
            target_node_id=node.id,
            source_entity_id=WorldEntityID("a"),
            target_entity_id=WorldEntityID("a"),
            relationship=GraphRelationship.EXPOSES,
        )
        with pytest.raises(ValueError):
            graph.add_edge(edge)

    def test_add_edge_dedup(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        b = graph.add_node(self._base_node(graph, "b"))

        def _edge() -> AttackGraphEdge:
            return AttackGraphEdge(
                mission_id=MID,
                graph_id=graph.graph_id,
                source_node_id=a.id,
                target_node_id=b.id,
                source_entity_id=a.entity_id,
                target_entity_id=b.entity_id,
                relationship=GraphRelationship.EXPOSES,
            )

        first = graph.add_edge(_edge())
        second = graph.add_edge(_edge())
        assert first.id == second.id
        assert graph.edge_count == 1

    def test_add_edge_supersedes_on_state_change(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        b = graph.add_node(self._base_node(graph, "b"))
        edge = AttackGraphEdge(
            mission_id=MID,
            graph_id=graph.graph_id,
            source_node_id=a.id,
            target_node_id=b.id,
            source_entity_id=a.entity_id,
            target_entity_id=b.entity_id,
            relationship=GraphRelationship.EXPOSES,
            state=GraphState.INFERRED,
        )
        first = graph.add_edge(edge)
        edge2 = edge.model_copy()
        edge2.state = GraphState.OBSERVED
        second = graph.add_edge(edge2)
        assert second.supersedes == first.id
        assert second.version == 2
        assert len(graph.archived_edges()) == 1

    def test_read_helpers(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        graph.add_node(self._base_node(graph, "b"))
        assert graph.node_for_entity("a").id == a.id
        assert graph.get_node(a.id) is not None
        assert graph.get_edge("missing") is None
        assert graph.nodes() == sorted(graph.nodes(), key=lambda n: str(n.id))

    def test_out_in_edges_and_neighbors(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        b = graph.add_node(self._base_node(graph, "b"))
        edge = AttackGraphEdge(
            mission_id=MID,
            graph_id=graph.graph_id,
            source_node_id=a.id,
            target_node_id=b.id,
            source_entity_id=a.entity_id,
            target_entity_id=b.entity_id,
            relationship=GraphRelationship.EXPOSES,
        )
        graph.add_edge(edge)
        assert [e.id for e in graph.out_edges(a.id)] == [edge.id]
        assert [e.id for e in graph.in_edges(b.id)] == [edge.id]
        neighbors = graph.neighbors(a.id, direction="out")
        assert [(e, n) for e, n in neighbors] == [(edge, b)]
        assert graph.neighbors(a.id, direction="in") == []
        assert graph.neighbors(
            a.id, relationship_types=[GraphRelationship.REQUIRES]
        ) == []

    def test_neighbors_limit(self) -> None:
        graph = AttackGraph(MID)
        source = graph.add_node(self._base_node(graph, "s"))
        for i in range(5):
            node = graph.add_node(self._base_node(graph, f"n{i}"))
            graph.add_edge(
                AttackGraphEdge(
                    mission_id=MID,
                    graph_id=graph.graph_id,
                    source_node_id=source.id,
                    target_node_id=node.id,
                    source_entity_id=source.entity_id,
                    target_entity_id=node.entity_id,
                    relationship=GraphRelationship.DEPENDS_ON,
                )
            )
        assert len(graph.neighbors(source.id, limit=3)) == 3

    def test_exposure_surfaces(self) -> None:
        graph = AttackGraph(MID)
        front = graph.add_node(self._base_node(graph, "front"))
        app = graph.add_node(self._base_node(graph, "app"))
        graph.add_edge(
            AttackGraphEdge(
                mission_id=MID,
                graph_id=graph.graph_id,
                source_node_id=front.id,
                target_node_id=app.id,
                source_entity_id=front.entity_id,
                target_entity_id=app.entity_id,
                relationship=GraphRelationship.EXPOSES,
            )
        )
        assert [n.entity_id for n in graph.exposure_surfaces()] == [WorldEntityID("app")]

    def test_hypothesis_edges_filter(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        b = graph.add_node(self._base_node(graph, "b"))
        for rel in (GraphRelationship.EXPOSES, GraphRelationship.POTENTIALLY_LEADS_TO):
            graph.add_edge(
                AttackGraphEdge(
                    mission_id=MID,
                    graph_id=graph.graph_id,
                    source_node_id=a.id,
                    target_node_id=b.id,
                    source_entity_id=a.entity_id,
                    target_entity_id=b.entity_id,
                    relationship=rel,
                )
            )
        assert len(graph.hypothesis_edges()) == 1

    def test_has_cycle(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        b = graph.add_node(self._base_node(graph, "b"))
        for rel in (GraphRelationship.DEPENDS_ON, GraphRelationship.REQUIRES):
            graph.add_edge(
                AttackGraphEdge(
                    mission_id=MID,
                    graph_id=graph.graph_id,
                    source_node_id=(
                        a.id if rel is GraphRelationship.DEPENDS_ON else b.id
                    ),
                    target_node_id=(
                        b.id if rel is GraphRelationship.DEPENDS_ON else a.id
                    ),
                    source_entity_id=(
                        a.entity_id if rel is GraphRelationship.DEPENDS_ON else b.entity_id
                    ),
                    target_entity_id=(
                        b.entity_id if rel is GraphRelationship.DEPENDS_ON else a.entity_id
                    ),
                    relationship=rel,
                )
            )
        assert graph.has_cycle("a") is True
        assert graph.has_cycle("nope") is False

    def test_find_paths_bounds_and_unknown_start(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        b = graph.add_node(self._base_node(graph, "b"))
        graph.add_edge(
            AttackGraphEdge(
                mission_id=MID,
                graph_id=graph.graph_id,
                source_node_id=a.id,
                target_node_id=b.id,
                source_entity_id=a.entity_id,
                target_entity_id=b.entity_id,
                relationship=GraphRelationship.EXPOSES,
            )
        )
        assert graph.find_paths("missing") == []
        found = graph.find_paths("a", max_depth=99, max_paths=-5)
        assert len(found) == 1
        assert found[0].length == 1

    def test_find_paths_max_paths_cap(self) -> None:
        graph = AttackGraph(MID)
        front = graph.add_node(self._base_node(graph, "front"))
        for i in range(3):
            node = graph.add_node(self._base_node(graph, f"app{i}"))
            graph.add_edge(
                AttackGraphEdge(
                    mission_id=MID,
                    graph_id=graph.graph_id,
                    source_node_id=front.id,
                    target_node_id=node.id,
                    source_entity_id=front.entity_id,
                    target_entity_id=node.entity_id,
                    relationship=GraphRelationship.EXPOSES,
                )
            )
        assert len(graph.find_paths("front", max_paths=2)) == 2

    def test_path_confidence_is_weakest(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(
            AttackGraphNode(
                mission_id=MID,
                graph_id=graph.graph_id,
                entity_id=WorldEntityID("a"),
                entity_type="endpoint",
                name="a",
            )
        )
        b = graph.add_node(
            AttackGraphNode(
                mission_id=MID,
                graph_id=graph.graph_id,
                entity_id=WorldEntityID("b"),
                entity_type="application",
                name="b",
            )
        )
        graph.add_edge(
            AttackGraphEdge(
                mission_id=MID,
                graph_id=graph.graph_id,
                source_node_id=a.id,
                target_node_id=b.id,
                source_entity_id=a.entity_id,
                target_entity_id=b.entity_id,
                relationship=GraphRelationship.EXPOSES,
                confidence=Confidence.LOW,
                supporting_evidence=["ev-1", "ev-2"],
            )
        )
        path = graph.find_paths("a", max_depth=2)[0]
        assert path.confidence == Confidence.LOW
        assert path.supporting_evidence == ["ev-1", "ev-2"]

    def test_to_dict_from_dict_roundtrip(self) -> None:
        graph = AttackGraph(MID)
        a = graph.add_node(self._base_node(graph, "a"))
        b = graph.add_node(self._base_node(graph, "b"))
        graph.add_edge(
            AttackGraphEdge(
                mission_id=MID,
                graph_id=graph.graph_id,
                source_node_id=a.id,
                target_node_id=b.id,
                source_entity_id=a.entity_id,
                target_entity_id=b.entity_id,
                relationship=GraphRelationship.EXPOSES,
            )
        )
        restored = AttackGraph.from_dict(graph.to_dict())
        assert restored.graph_id == graph.graph_id
        assert restored.node_count == graph.node_count
        assert restored.edge_count == graph.edge_count
        assert restored.node_for_entity("a") is not None
        assert len(restored.edges()) == 1


# ---------------------------------------------------------------------- #
# Rules
# ---------------------------------------------------------------------- #
class TestRules:
    def _ctx(self, relationships, entities=None, evidence=None) -> None:
        from blackforge.attack_graph.rules import GraphRuleContext

        return GraphRuleContext(
            mission_id=MID,
            session_id=SID,
            entities=entities or {},
            relationships=relationships,
            relationship_evidence=evidence or {},
        )

    def _entities(self, *ids):
        by_id = {}
        for ent_id, name in ids:
            by_id[ent_id] = WorldEntity(_make_world_entity(ent_id, name))
        return by_id

    def test_exposure_rule_maps_exposure_family(self) -> None:
        specs = exposure_rule().derive(self._ctx([]))
        assert specs == []

    def test_exposure_rule_via_builder_covers_relationships(self) -> None:
        world, _evstore, _front, app, _ev = _exposed_app_fixture()
        graph = _build_graph(world)
        edges = [e for e in graph.edges() if e.relationship == GraphRelationship.EXPOSES]
        assert len(edges) == 1
        assert edges[0].state == GraphState.INFERRED
        assert edges[0].derivation.rule_id == "serves"

    def test_dependency_rule_maps_dependency_family(self) -> None:
        world, _evstore, _front, _app, _ev = _exposed_app_fixture()
        app = _app
        front = _front
        world.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.DEPENDS_ON,
                source_entity_id=app.id,
                target_entity_id=front.id,
            )
        )
        graph = _build_graph(world)
        kinds = {e.relationship for e in graph.edges()}
        assert GraphRelationship.DEPENDS_ON in kinds

    def test_reachability_rule_is_symmetric(self) -> None:
        world, _evstore, one, two, _ev = _exposed_app_fixture()
        world.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.CONNECTS_TO,
                source_entity_id=one.id,
                target_entity_id=two.id,
            )
        )
        graph = _build_graph(world)
        reach = [
            (str(e.source_entity_id), str(e.target_entity_id))
            for e in graph.edges()
            if e.relationship == GraphRelationship.REACHABLE_FROM
        ]
        assert (str(one.id), str(two.id)) in reach
        assert (str(two.id), str(one.id)) in reach

    def test_access_rule_maps_authn_and_rbac(self) -> None:
        world, _evstore, front, app, _ev = _exposed_app_fixture()
        ident = world.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.IDENTITY,
                name="svc-acct",
                epistemic_status=EvidenceStatus.INFERRED,
            )
        ).entity
        world.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.AUTHENTICATES_TO,
                source_entity_id=ident.id,
                target_entity_id=app.id,
            )
        )
        world.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.AUTHORIZED_FOR,
                source_entity_id=ident.id,
                target_entity_id=app.id,
            )
        )
        graph = _build_graph(world)
        kinds = {e.relationship for e in graph.edges()}
        assert GraphRelationship.REQUIRES_VALIDATION in kinds
        assert GraphRelationship.PROVIDES_ACCESS_TO in kinds

    def test_constraint_rule_maps_policies(self) -> None:
        world, _evstore, front, app, _ev = _exposed_app_fixture()
        world.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.PROTECTS,
                source_entity_id=front.id,
                target_entity_id=app.id,
            )
        )
        graph = _build_graph(world)
        assert any(
            e.relationship == GraphRelationship.CONSTRAINS for e in graph.edges()
        )

    def test_declared_as_derives_no_edges(self) -> None:
        world, _evstore, front, app, _ev = _exposed_app_fixture()
        world.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.DECLARED_AS,
                source_entity_id=front.id,
                target_entity_id=app.id,
            )
        )
        graph = _build_graph(world)
        assert len(graph.edges()) == 1  # only the SERVES exposure edge

    def test_default_rule_order_and_ids(self) -> None:
        rules = default_graph_rules()
        assert [r.rule_id for r in rules] == [
            "ag_exposure",
            "ag_dependency",
            "ag_reachability",
            "ag_access",
            "ag_constraint",
            "ag_correlation_discrepancy",
        ]

    def test_correlation_discrepancy_rule_dedups_and_requires_exposure(self) -> None:
        world = _correlation_fixture()
        graph = _build_graph(world)
        req_val = [
            e
            for e in graph.edges()
            if e.relationship == GraphRelationship.REQUIRES_VALIDATION
        ]
        assert len(req_val) == 1
        edge = req_val[0]
        assert edge.prerequisites[0].description == (
            "declared-vs-runtime discrepancy is validated"
        )
        assert edge.derivation.rule_id == "ag_correlation_discrepancy"

    def test_hypothesis_edges_require_exposure_and_validation(self) -> None:
        world = _correlation_fixture()
        graph = _build_graph(world)
        hyp = [
            e
            for e in graph.edges()
            if e.relationship == GraphRelationship.POTENTIALLY_LEADS_TO
        ]
        targets = {str(e.target_entity_id) for e in hyp}
        exposed = [n for n in graph.nodes() if n.name == "payments-app"]
        assert len(hyp) == 2
        assert targets == {str(exposed[0].entity_id)}
        assert all(e.state == GraphState.HYPOTHESIZED for e in hyp)
        assert all(e.confidence == Confidence.LOW for e in hyp)
        for edge in hyp:
            assert edge.derivation.rule_id == "ag_hypothesis"
            assumptions = edge.assumptions
            assert any("potential relationship" in a for a in assumptions)
            assert any("not exploitation" in a for a in assumptions)

    def test_hypothesis_prerequisite_satisfied_when_access_present(self) -> None:
        more = _correlation_fixture()
        ident = more.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.IDENTITY,
                name="acct",
                epistemic_status=EvidenceStatus.INFERRED,
            )
        ).entity
        app = [
            e for e in more.list_entities(WorldQuery(mission_id=MID)) if e.name == "payments-app"
        ][0]
        more.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.AUTHORIZED_FOR,
                source_entity_id=ident.id,
                target_entity_id=app.id,
            )
        )
        graph = _build_graph(more)
        hyp = [
            e
            for e in graph.edges()
            if e.relationship == GraphRelationship.POTENTIALLY_LEADS_TO
        ][0]
        states = {p.state.value for p in hyp.prerequisites}
        assert "satisfied" in states

    def test_rule_purity_direct_derive_no_mutation(self) -> None:
        world = _correlation_fixture()
        entities = {
            str(e.id): e for e in world.list_entities(WorldQuery(mission_id=MID))
        }
        rels = list(world.list_relationships(RelationshipQuery(mission_id=MID)))
        ctx = GraphRuleContext(
            mission_id=MID,
            session_id=SID,
            entities=entities,
            relationships=rels,
            relationship_evidence={},
        )
        specs = correlation_discrepancy_rule().derive(ctx)
        assert len(specs) == 1
        assert specs[0].relationship == GraphRelationship.REQUIRES_VALIDATION


def _make_world_entity(ent_id: str, name: str):
    from blackforge.world_model.models import WorldEntity, WorldLifecycle

    return WorldEntity(
        id=ent_id,
        mission_id=MID,
        entity_type=EntityType.APPLICATION,
        name=name,
        canonical_key=name,
        dedup_key=name,
        lifecycle=WorldLifecycle.ACTIVE,
        epistemic_status=EvidenceStatus.OBSERVED,
        confidence=Confidence.HIGH,
    )


# ---------------------------------------------------------------------- #
# Builder
# ---------------------------------------------------------------------- #
class TestBuilder:
    def test_builder_mirrors_entities(self) -> None:
        world, _ev, front, app, _ = _exposed_app_fixture()
        result = AttackGraphBuilder(world_model=world).build(
            AttackGraphBuildRequest(mission_id=MID, session_id=SID)
        )
        graph = result.graph
        assert graph.node_count == 2
        assert result.node_count == 2
        for node in graph.nodes():
            assert node.derivation.rule_id == "ag_entity_mirror"
            assert node.derivation.source_entity_ids == [str(node.entity_id)]
        assert graph.node_for_entity(str(front.id)).state == GraphState.OBSERVED
        assert graph.node_for_entity(str(app.id)).confidence == Confidence.HIGH

    def test_builder_mission_isolation(self) -> None:
        world, _ev, front, app, _ = _exposed_app_fixture()
        graph = _build_graph(world)
        assert all(n.mission_id == MID for n in graph.nodes())
        assert all(e.mission_id == MID for e in graph.edges())

    def test_builder_evidence_provenance_on_edges(self) -> None:
        world, _evstore, _front, _app, ev = _exposed_app_fixture()
        graph = _build_graph(world)
        edge = graph.edges()[0]
        assert str(ev.id) in edge.supporting_evidence
        assert str(ev.id) in edge.derivation.source_evidence_ids

    def test_builder_result_accounting(self) -> None:
        world = _correlation_fixture()
        result = AttackGraphBuilder(world_model=world).build(
            AttackGraphBuildRequest(mission_id=MID, session_id=SID)
        )
        assert result.derived_edge_count == sum(r.derived for r in result.rules)
        assert result.hypothesis_edge_count >= 1
        assert result.edge_count == (
            result.derived_edge_count + result.hypothesis_edge_count
        )
        assert result.elapsed_ms >= 0.0
        assert [r.rule_id for r in result.rules] == [
            r.rule_id for r in default_graph_rules()
        ]

    def test_builder_hypothesis_toggle(self) -> None:
        world = _correlation_fixture()
        with_hyp = _build_graph(world, include_hypothesis=True)
        without_hyp = _build_graph(world, include_hypothesis=False)
        assert len(with_hyp.hypothesis_edges()) >= 1
        assert without_hyp.hypothesis_edges() == []

    def test_builder_truncation_warnings(self) -> None:
        world, _ev, _f, _a, _ = _exposed_app_fixture()
        result = AttackGraphBuilder(world_model=world).build(
            AttackGraphBuildRequest(mission_id=MID, session_id=SID, max_nodes=1, max_edges=1)
        )
        assert any("truncated" in w for w in result.warnings)

    def test_builder_deterministic_and_corroborating(self) -> None:
        world, _ev, _f, _a, _ = _exposed_app_fixture()
        builder = AttackGraphBuilder(world_model=world)
        first = builder.build(AttackGraphBuildRequest(mission_id=MID, session_id=SID))
        second = builder.build(AttackGraphBuildRequest(mission_id=MID, session_id=SID))
        assert first.node_count == second.node_count
        assert first.edge_count == second.edge_count
        second_graph = second.graph
        assert second_graph.node_count == first.graph.node_count
        assert second_graph.edge_count == first.graph.edge_count
        assert second_graph.archived_nodes() == []
        assert second_graph.archived_edges() == []

    def test_builder_without_world_model_returns_empty(self) -> None:
        result = AttackGraphBuilder().build(
            AttackGraphBuildRequest(mission_id=MID, session_id=SID)
        )
        assert result.graph.node_count == 0
        assert result.graph.edge_count == 0
        assert any("no world model" in w for w in result.warnings)

    def test_builder_node_states_follow_evidence_status(self) -> None:
        world, evstore = _store_pair()
        ev = _evidence(evstore)
        hip = world.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.APPLICATION,
                name="hi-app",
                epistemic_status=EvidenceStatus.HYPOTHESIZED,
            )
        ).entity
        obs = world.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.EDGE_ENDPOINT,
                name="obs-edge",
                epistemic_status=EvidenceStatus.OBSERVED,
                confidence=Confidence.HIGH,
                evidence=[EvidenceLinkRef(evidence_id=ev.id)],
            )
        ).entity
        graph = _build_graph(world)
        assert graph.node_for_entity(str(hip.id)).state == GraphState.HYPOTHESIZED
        assert graph.node_for_entity(str(obs.id)).state == GraphState.OBSERVED

    def test_builder_no_self_loop_edges(self) -> None:
        world, _ev, front, app, _ev2 = _exposed_app_fixture()
        with pytest.raises(WorldRuleError):
            world.add_relationship(
                RelationshipSpec(
                    mission_id=MID,
                    relationship_type=RelationshipType.DEPENDS_ON,
                    source_entity_id=app.id,
                    target_entity_id=app.id,
                )
            )
        graph = _build_graph(world)
        assert all(e.source_entity_id != e.target_entity_id for e in graph.edges())
        assert all(
            e.source_entity_id != e.target_entity_id
            for e in world.list_relationships(RelationshipQuery(mission_id=MID))
        )


# ---------------------------------------------------------------------- #
# Query
# ---------------------------------------------------------------------- #
class TestQuery:
    def test_path_helpers(self) -> None:
        graph = _build_graph()
        path = _first_path(graph)
        assert len(path_nodes(graph, path)) >= 2
        assert len(path_edges(graph, path)) == path.length

    def test_classify_inferred_path_default(self) -> None:
        graph = _build_graph()
        path = _first_path(graph)
        assert classify_path(graph, path) == PathState.INFERRED_PATH

    def test_classify_observed_path(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("b", "application", GraphState.OBSERVED),
            ],
            [
                ("a", "b", GraphRelationship.EXPOSES, GraphState.OBSERVED),
            ],
        )
        path = _first_path(graph)
        assert classify_path(graph, path) == PathState.OBSERVED_PATH

    def test_classify_validated_path(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.VALIDATED),
                ("b", "application", GraphState.VALIDATED),
            ],
            [
                ("a", "b", GraphRelationship.EXPOSES, GraphState.VALIDATED),
            ],
        )
        path = _first_path(graph)
        assert classify_path(graph, path) == PathState.VALIDATED_PATH

    def test_classify_hypothesized_path_via_relationship(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("b", "application", GraphState.OBSERVED),
            ],
            [
                ("a", "b", GraphRelationship.POTENTIALLY_LEADS_TO, GraphState.INFERRED),
            ],
        )
        path = _first_path(graph)
        assert classify_path(graph, path) == PathState.HYPOTHESIZED_PATH

    def test_classify_blocked_path(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("b", "application", GraphState.BLOCKED),
            ],
            [
                ("a", "b", GraphRelationship.EXPOSES, GraphState.INFERRED),
            ],
        )
        path = _first_path(graph)
        assert classify_path(graph, path) == PathState.BLOCKED_PATH

    def test_classify_contradicted_path(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("b", "application", GraphState.OBSERVED),
            ],
            [
                ("a", "b", GraphRelationship.EXPOSES, GraphState.CONTRADICTED),
            ],
        )
        path = _first_path(graph)
        assert classify_path(graph, path) == PathState.CONTRADICTED_PATH

    def test_classify_insufficient_evidence(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.INSUFFICIENT_EVIDENCE),
                ("b", "application", GraphState.INFERRED),
            ],
            [
                ("a", "b", GraphRelationship.EXPOSES, GraphState.INFERRED),
            ],
        )
        path = _first_path(graph)
        assert classify_path(graph, path) == PathState.INSUFFICIENT_EVIDENCE

    def test_missing_prerequisites_deduplicated(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("mid", "application", GraphState.OBSERVED),
                ("b", "application", GraphState.OBSERVED),
            ],
            [
                ("a", "mid", GraphRelationship.DEPENDS_ON, GraphState.INFERRED),
                ("mid", "b", GraphRelationship.DEPENDS_ON, GraphState.INFERRED),
            ],
        )
        for edge in graph.edges():
            edge.prerequisites = [
                Prerequisite(
                    description="shared prereq",
                    state=PrerequisiteState.UNKNOWN,
                    required_evidence=["validation_result"],
                )
            ]
        path = graph.find_paths("a", max_depth=3, surfaces_only=False)[0]
        assert path.length == 2
        missing = missing_prerequisites(graph, path)
        descriptions = [p.description for p in missing]
        assert descriptions.count("shared prereq") == 1
        assert descriptions == sorted(descriptions)

    def test_evaluate_path_outcome_fields(self) -> None:
        graph = _build_graph()
        query = AttackGraphQuery(graph)
        outcome = query.evaluate(_first_path(graph))
        assert isinstance(outcome, PathOutcome)
        assert outcome.state == PathState.INFERRED_PATH
        assert outcome.length >= 1
        assert outcome.start_entity_id != outcome.end_entity_id

    def test_query_open_paths_dedup(self) -> None:
        graph = _build_graph()
        paths = AttackGraphQuery(graph).open_paths(max_depth=4, max_paths=50)
        keys = {"-".join(str(i) for i in p.node_ids) for p in paths}
        assert len(keys) == len(paths)

    def test_query_filtered_path_collections(self) -> None:
        graph = _build_graph()
        query = AttackGraphQuery(graph)
        assert query.blocked_paths() == []
        assert query.contradicted_paths() == []
        assert query.insufficient_paths() == []
        assert len(query.uncertain_paths(limit=2)) <= 2

    def test_query_offensive_semantics_probe(self) -> None:
        graph = _build_graph()
        assert query_offensive_semantics(graph) is False

    def test_query_viable_starts_restricted(self) -> None:
        graph = _build_graph()
        starts = query_viable_starts(graph)
        assert all(
            n.entity_type
            in {"public_address", "edge_endpoint", "endpoint", "application", "ingress"}
            for n in starts
        )


def query_viable_starts(graph: AttackGraph):
    query = AttackGraphQuery(graph)
    return query._viable_starts()


# ---------------------------------------------------------------------- #
# Scoring
# ---------------------------------------------------------------------- #
class TestScoring:
    def test_assess_explainable_and_capped(self) -> None:
        score = assess(
            path_depth=3,
            is_blocked=False,
            near_saturation=False,
            exposed_ratio=1.0,
            focus_matches=True,
            has_contradiction=True,
            corroboration=5,
            derived_confidence=1.0,
        )
        assert score.value <= 1.0
        assert score.level in {"LOW", "MODERATE", "ELEVATED", "HIGH"}
        assert score.explanation

    def test_assess_max_inputs_high_level(self) -> None:
        score = assess(3, False, False, 1.0, True, True, 2, 1.0)
        assert score.level == "HIGH"

    def test_assess_min_inputs_low(self) -> None:
        score = assess(1, False, True, 0.0, False, False, 0, 0.0)
        assert score.level == "LOW"

    def test_assess_near_saturation_reduces_exposure(self) -> None:
        saturated = assess(3, False, True, 1.0, True, True, 2, 1.0)
        fresh = assess(3, False, False, 1.0, True, True, 2, 1.0)
        assert saturated.value < fresh.value

    def test_assess_focus_mismatch_lowers_score(self) -> None:
        aligned = assess(1, False, False, 1.0, True, False, 0, 0.5)
        misaligned = assess(1, False, False, 1.0, False, False, 0, 0.5)
        assert misaligned.value < aligned.value

    def test_assess_contradiction_credit(self) -> None:
        with_contra = assess(1, False, False, 1.0, True, True, 0, 0.5)
        without = assess(1, False, False, 1.0, True, False, 0, 0.5)
        assert with_contra.value > without.value

    def test_assess_corroboration_capped_at_two(self) -> None:
        two = assess(1, False, False, 1.0, True, False, 2, 0.5)
        ten = assess(1, False, False, 1.0, True, False, 10, 0.5)
        assert two.value == ten.value

    def test_assess_blocked_factor_recorded(self) -> None:
        score = assess(1, True, False, 1.0, True, False, 0, 0.5)
        assert score.factors.blocked == 1.0

    def test_assess_explain_join(self) -> None:
        score = assess(1, False, False, 1.0, True, False, 0, 0.5)
        assert score.explain() == "; ".join(score.explanation)

    def test_assess_deterministic(self) -> None:
        kwargs = dict(
            path_depth=2,
            is_blocked=False,
            near_saturation=False,
            exposed_ratio=1.0,
            focus_matches=True,
            has_contradiction=False,
            corroboration=1,
            derived_confidence=0.8,
        )
        assert assess(**kwargs) == assess(**kwargs)


# ---------------------------------------------------------------------- #
# Actions
# ---------------------------------------------------------------------- #
class TestActions:
    def test_compute_gaps_one_per_edge(self) -> None:
        graph = _build_graph()
        path = _first_path(graph)
        gaps = compute_gaps(graph, [path])
        assert len(gaps) == path.length
        gap = gaps[0]
        assert isinstance(gap, EvidenceGap)
        assert gap.path_id == str(path.id)
        assert gap.edge_id == str(path.edge_ids[0])
        assert gap.evidence_kind == "validation_result"

    def test_compute_gaps_evidence_kind_mapping(self) -> None:
        graph = _build_graph()
        path = _first_path(graph)
        edge = graph.edges()[0]
        edge.prerequisites = [
            Prerequisite(
                description="validated authentication for app",
                state=PrerequisiteState.UNKNOWN,
            )
        ]
        gap = compute_gaps(graph, [path])[0]
        assert gap.evidence_kind == "auth_missing_or_weak"

    def test_candidate_actions_matches_registered(self) -> None:
        gaps = [EvidenceGap(path_id="p", edge_id="e", predicate="exposes", description="d")]
        metas = [m for m in _registry().list_meta()]
        actions = candidate_actions(gaps, metas, target_value="t", target_label="l")
        names = {a.capability_name for a, _g in actions}
        assert names == {"app_probe", "backend_probe", "http_probe"}
        for action, _gap in actions:
            assert isinstance(action, CandidateAction)
            assert action.target == "t"

    def test_candidate_actions_coverage_always_considered(self) -> None:
        reg = _registry(names=("app_probe",))
        gaps = [EvidenceGap(path_id="p", edge_id="e", predicate="x", description="d")]
        actions = candidate_actions(
            gaps, reg.list_meta(), target_value="t", target_label="l"
        )
        assert len(actions) == 1
        action, _gap = actions[0]
        assert action.capability_name == "app_probe"
        assert action.expected_evidence[0].evidence_type == "validation_result"

    def test_candidate_actions_dedup_per_capability(self) -> None:
        gaps = [
            EvidenceGap(path_id="p1", edge_id="e1", predicate="a", description="d1"),
            EvidenceGap(path_id="p2", edge_id="e2", predicate="b", description="d2"),
        ]
        metas = [m for m in _registry().list_meta()]
        actions = candidate_actions(gaps, metas, target_value="t", target_label="l")
        names = [a.capability_name for a, _g in actions]
        assert len(names) == len(set(names))

    def test_candidate_actions_sorted_deterministically(self) -> None:
        gaps = [EvidenceGap(path_id="p", edge_id="e", predicate="x", description="d")]
        metas = [m for m in _registry().list_meta()]
        first = candidate_actions(gaps, metas, target_value="t", target_label="l")
        second = candidate_actions(gaps, metas, target_value="t", target_label="l")
        assert [a.capability_name for a, _g in first] == [
            a.capability_name for a, _g in second
        ]

    def test_candidate_actions_ignore_unregistered(self) -> None:
        gaps = [
            EvidenceGap(path_id="p", edge_id="e", predicate="x", description="d"),
        ]
        metas = [m for m in _registry(names=("nope",)).list_meta()]
        actions = candidate_actions(gaps, metas, target_value="t", target_label="l")
        assert all(a.capability_name != "injected" for a, _g in actions)

    def test_saturation_reached(self) -> None:
        assert saturation_reached(0) is True
        assert saturation_reached(-1) is True
        assert saturation_reached(1) is False


# ---------------------------------------------------------------------- #
# Planner
# ---------------------------------------------------------------------- #
class TestPlanner:
    def test_requires_registry(self) -> None:
        planner = AssessmentPlanner(registry=None)
        graph = _build_graph()
        with pytest.raises(PlanningError):
            planner.plan(_request(graph))

    def test_no_graph_raises(self) -> None:
        planner = _planner(builder=None, repository=None)
        with pytest.raises(PlanningError):
            planner.plan(_request())

    def test_insufficient_scope_fails_closed(self) -> None:
        planner = _planner()
        scope = _scope(
            targets=[Target(value="elsewhere.example", target_type=TargetType.APPLICATION)]
        )
        plan = planner.plan(_request(_build_graph(), scope=scope))
        assert plan.status == PlanStatus.INSUFFICIENT_SCOPE
        assert plan.steps == []
        assert any("outside the authorized scope" in w for w in plan.warnings)

    def test_empty_graph_no_action_available(self) -> None:
        planner = _planner()
        scope = _scope(targets=[Target(value="", target_type=TargetType.APPLICATION)])
        plan = planner.plan(_request(AttackGraph(MID), scope=scope))
        assert plan.status == PlanStatus.NO_ACTION_AVAILABLE

    def test_no_paths_no_gaps(self) -> None:
        planner = _planner()
        solo = _manual_graph([("solo", "application", GraphState.INFERRED)], [])
        scope = _scope(targets=[Target(value="solo", target_type=TargetType.APPLICATION)])
        plan = planner.plan(_request(solo, scope=scope))
        assert plan.status == PlanStatus.NO_GAPS

    def test_full_flow_plan_ready(self) -> None:
        repo = InMemoryAttackGraphRepository()
        planner = _planner(repository=repo)
        plan = planner.plan(_request(_build_graph()))
        assert plan.status == PlanStatus.PLAN_READY
        assert len(plan.steps) == 3
        assert plan.capability_names == sorted(plan.capability_names)
        assert plan.note == "assessment plan (advisory; never executes anything)"
        assert len(repo.plans_for_mission(MID)) == 1

    def test_plan_uses_repository_for_storage(self) -> None:
        repo = InMemoryAttackGraphRepository()
        planner = _planner(repository=repo)
        plan = planner.plan(_request(_build_graph()))
        assert repo.get_plan(str(plan.id)).id == plan.id

    def test_plan_max_steps_caps_candidates(self) -> None:
        planner = _planner()
        plan = planner.plan(_request(_build_graph(), max_steps=2))
        assert len(plan.steps) == 2
        assert plan.max_steps == 2
        assert any("capped at 2" in w for w in plan.warnings)
        assert plan.status == PlanStatus.PLAN_READY

    def test_plan_budget_saturation_plan_capped(self) -> None:
        planner = _planner()
        plan = planner.plan(
            _request(_build_graph(), ide_budget_hours=0.2, max_steps=5)
        )
        assert plan.status == PlanStatus.PLAN_CAPPED
        assert len(plan.steps) >= 1
        assert any("saturated" in w for w in plan.warnings)

    def test_plan_denied_capability_excluded(self) -> None:
        planner = _planner(auth=AuthorizationBoundary(mode="strict"))
        scope = _scope(
            caps=["only_allowed_cap"]
        )
        plan = planner.plan(_request(_build_graph(), scope=scope))
        assert plan.status == PlanStatus.NO_ACTION_AVAILABLE
        assert any("not authorized" in w for w in plan.warnings)

    def test_plan_deterministic_ordering(self) -> None:
        graph = _build_graph()
        first = _planner().plan(_request(graph))
        second = _planner().plan(_request(graph))
        assert [s.action.capability_name for s in first.steps] == [
            s.action.capability_name for s in second.steps
        ]
        assert [s.action.target for s in first.steps] == [TARGET] * len(first.steps)

    def test_focus_resolution(self) -> None:
        _world, _ev, _front, app, _ = _exposed_app_fixture()
        graph = _build_graph(_world)
        planner = _planner()
        plan = planner.plan(_request(graph, focus=str(app.id)))
        assert plan.steps and all(s.action.target == TARGET for s in plan.steps)
        assert plan.warnings == []

    def test_unknown_focus_falls_back(self) -> None:
        planner = _planner()
        plan = planner.plan(_request(_build_graph(), focus="missing-target"))
        assert plan.status == PlanStatus.PLAN_READY
        assert any("not in the world model" in w for w in plan.warnings)

    def test_resolve_graph_prefers_request(self) -> None:
        provided = _build_graph()
        planner = _planner(builder=AttackGraphBuilder(world_model=None))
        plan = planner.plan(_request(provided))
        assert plan.graph_id == provided.graph_id

    def test_resolve_graph_uses_builder_when_no_request_graph(self) -> None:
        world, _ev, _f, _a, _ = _exposed_app_fixture()
        planner = _planner(builder=AttackGraphBuilder(world_model=world))
        plan = planner.plan(_request())
        assert plan.graph_id is not None

    def test_resolve_graph_uses_repository_when_no_builder(self) -> None:
        repo = InMemoryAttackGraphRepository()
        graph = _build_graph()
        repo.save_graph(graph)
        planner = _planner(repository=repo, builder=None)
        plan = planner.plan(_request())
        assert plan.graph_id == graph.graph_id

    def test_replan_no_action_available_returns_prior(self) -> None:
        planner = _planner(registry=_registry(), auth=AuthorizationBoundary(mode="strict"))
        scope = _scope(caps=["none"])
        prior = planner.plan(_request(_build_graph(), scope=scope))
        assert prior.status == PlanStatus.NO_ACTION_AVAILABLE
        assert planner.replan(_request(_build_graph()), prior) is prior

    def test_replan_progresses_and_annotates(self) -> None:
        planner = _planner(registry=_registry(), repository=InMemoryAttackGraphRepository())
        graph = _build_graph()
        prior = planner.plan(_request(graph, max_replans=3))
        assert prior.status == PlanStatus.PLAN_READY
        renewed = planner.replan(
            _request(graph, max_replans=3),
            prior,
            newly_answered_kinds=["validation_result"],
        )
        assert str(renewed.id) != str(prior.id)
        assert renewed.note.startswith("replan 1 of 3")
        assert any("acknowledged answered evidence" in w for w in renewed.warnings)

    def test_replan_limit_raises(self) -> None:
        planner = _planner(registry=_registry(), repository=InMemoryAttackGraphRepository())
        graph = _build_graph()
        prior = planner.plan(_request(graph, max_replans=1))
        planner.replan(_request(graph, max_replans=1), prior)
        with pytest.raises(PlanningError):
            planner.replan(_request(graph, max_replans=1), prior)

    def test_replan_drops_answered_evidence_types(self) -> None:
        planner = _planner(registry=_registry(), repository=InMemoryAttackGraphRepository())
        graph = _build_graph()
        prior = planner.plan(_request(graph, max_replans=3))
        renewed = planner.replan(_request(graph, max_replans=3), prior)
        assert renewed.status == PlanStatus.NO_ACTION_AVAILABLE
        assert renewed.steps == []

    def test_plan_step_ids_and_retained_bounds(self) -> None:
        planner = _planner()
        plan = planner.plan(_request(_build_graph(), max_candidates=3, max_steps=4))
        assert plan.steps[0].step_id == f"{MID}-step-1"
        assert [s.order for s in plan.steps] == list(range(1, len(plan.steps) + 1))
        assert plan.max_candidates == 3
        assert plan.max_graph_depth == 3

    def test_idle_budget_tracker(self) -> None:
        from blackforge.attack_graph.planner import IdleBudgetTracker

        tracker = IdleBudgetTracker(budget_hours=2.0)
        assert tracker.saturated is False
        tracker.spend("app_probe")
        assert tracker.spent_hours > 0.0
        assert tracker.remaining < 2.0
        twin = IdleBudgetTracker(budget_hours=2.0)
        for name in ("app_probe", "http_probe", "backend_probe"):
            twin.spend(name)
        assert twin.spent_hours > tracker.spent_hours
        assert twin.remaining < tracker.remaining


# ---------------------------------------------------------------------- #
# Repository
# ---------------------------------------------------------------------- #
class TestRepository:
    def test_in_memory_save_get(self) -> None:
        repo = InMemoryAttackGraphRepository()
        graph = _build_graph()
        assert repo.save_graph(graph) == graph.graph_id
        assert repo.get_graph(graph.graph_id).graph_id == graph.graph_id
        assert repo.health_check() is True
        assert repo.get_latest_graph(MID).graph_id == graph.graph_id

    def test_in_memory_get_latest_by_mission(self) -> None:
        repo = InMemoryAttackGraphRepository()
        other = AttackGraph("mission_other")
        repo.save_graph(other)
        assert repo.get_latest_graph("mission_other").graph_id == other.graph_id
        assert repo.get_latest_graph(MID) is None

    def test_in_memory_plans_newest_first(self) -> None:
        repo = InMemoryAttackGraphRepository()
        a = AssessmentPlan(mission_id=MID, graph_id="g1")
        b = AssessmentPlan(mission_id=MID, graph_id="g2")
        repo.store_plan(a)
        repo.store_plan(b)
        plans = repo.plans_for_mission(MID)
        assert {str(p.id) for p in plans} == {str(a.id), str(b.id)}
        assert repository_order_descending(plans)
        assert repo.get_plan("missing") is None

    def test_sqlite_roundtrip_basic_fields(self, tmp_path) -> None:
        repo = SQLiteAttackGraphRepository(str(tmp_path / "ag.db"))
        graph = _build_graph()
        repo.save_graph(graph)
        loaded = repo.get_graph(graph.graph_id)
        assert loaded.node_count == graph.node_count
        assert loaded.edge_count == graph.edge_count
        loaded_edge = loaded.edges()[0]
        assert loaded_edge.relationship == GraphRelationship.EXPOSES
        assert loaded_edge.state == GraphState.INFERRED
        loaded_node = loaded.nodes()[0]
        assert loaded_node.entity_type
        repo.close()

    def test_sqlite_rich_fields_not_persisted(self, tmp_path) -> None:
        repo = SQLiteAttackGraphRepository(str(tmp_path / "ag.db"))
        graph = _build_graph(_correlation_fixture())
        repo.save_graph(graph)
        loaded = repo.get_graph(graph.graph_id)
        for edge in loaded.edges():
            assert edge.derivation.rule_id is None
        repo.close()

    def test_sqlite_supersede_preserves_history(self, tmp_path) -> None:
        import time as _time

        repo = SQLiteAttackGraphRepository(str(tmp_path / "ag.db"))
        graph = AttackGraph(MID)
        graph.add_node(
            AttackGraphNode(
                mission_id=MID,
                graph_id=graph.graph_id,
                entity_id=WorldEntityID("ent-1"),
                entity_type="application",
                name="app",
                state=GraphState.OBSERVED,
            )
        )
        repo.save_graph(graph)
        successor = AttackGraph(MID, graph_id=graph.graph_id)
        successor.add_node(
            AttackGraphNode(
                mission_id=MID,
                graph_id=successor.graph_id,
                entity_id=WorldEntityID("ent-1"),
                entity_type="application",
                name="app",
                state=GraphState.INFERRED,
                created_at=_time.time() + 1,
            )
        )
        repo.save_graph(successor)
        loaded = repo.get_graph(graph.graph_id)
        assert len(loaded.archived_nodes()) == 1
        assert len(loaded.nodes()) == 1
        assert loaded.nodes()[0].state == GraphState.INFERRED
        repo.close()

    def test_sqlite_corroborate_does_not_duplicate(self, tmp_path) -> None:
        repo = SQLiteAttackGraphRepository(str(tmp_path / "ag.db"))
        graph = _build_graph()
        repo.save_graph(graph)
        repo.save_graph(graph)
        from sqlite3 import connect as _connect

        conn = _connect(str(tmp_path / "ag.db"))
        count = conn.execute(
            "SELECT COUNT(*) FROM attack_graph_nodes WHERE graph_id = ?",
            (graph.graph_id,),
        ).fetchone()[0]
        conn.close()
        assert count == graph.node_count
        repo.close()

    def test_sqlite_get_latest_graph(self, tmp_path) -> None:
        repo = SQLiteAttackGraphRepository(str(tmp_path / "ag.db"))
        graph = _build_graph()
        repo.save_graph(graph)
        assert repo.get_latest_graph(MID).graph_id == graph.graph_id
        repo.close()

    def test_sqlite_plan_roundtrip_full_payload(self, tmp_path) -> None:
        repo = SQLiteAttackGraphRepository(str(tmp_path / "ag.db"))
        planner = _planner(repository=repo)
        plan = planner.plan(_request(_build_graph()))
        loaded = repo.get_plan(str(plan.id))
        assert loaded.status == plan.status
        assert len(loaded.steps) == len(plan.steps)
        assert [a.action.capability_name for a in loaded.steps] == [
            a.action.capability_name for a in plan.steps
        ]
        repo.close()

    def test_sqlite_plans_for_mission(self, tmp_path) -> None:
        repo = SQLiteAttackGraphRepository(str(tmp_path / "ag.db"))
        repo.store_plan(AssessmentPlan(mission_id=MID, graph_id="g1"))
        repo.store_plan(AssessmentPlan(mission_id=MID, graph_id="g2"))
        assert len(repo.plans_for_mission(MID)) == 2
        assert repo.plans_for_mission("other") == []
        assert repo.health_check() is True
        repo.close()
        repo.close()  # idempotent


def repository_order_descending(plans) -> bool:
    stamps = [p.created_at for p in plans]
    return all(stamps[i] >= stamps[i + 1] for i in range(len(stamps) - 1))


# ---------------------------------------------------------------------- #
# Materializer
# ---------------------------------------------------------------------- #
class TestMaterializer:
    def test_no_memory_manager_skips(self) -> None:
        materializer = AttackGraphMemoryMaterializer(memory=None)
        report = materializer.materialize(
            _build_graph(),
            MaterializeEntry(node_entity_ids=("x",)),
            MID,
            SID,
        )
        assert report.skipped == 1
        assert report.wrote == 0
        assert any("no memory manager" in w for w in report.warnings)

    def test_no_matching_nodes_skips(self) -> None:
        materializer = AttackGraphMemoryMaterializer(memory=MemoryManager())
        report = materializer.materialize(
            _build_graph(),
            MaterializeEntry(node_entity_ids=("nope",)),
            MID,
            SID,
        )
        assert report.skipped == 1
        assert any("no matching nodes" in w for w in report.warnings)

    def test_materialize_writes_record(self) -> None:
        graph = _build_graph()
        memory = MemoryManager()
        materializer = AttackGraphMemoryMaterializer(memory=memory)
        entry = MaterializeEntry(
            node_entity_ids=tuple(str(n.entity_id) for n in graph.nodes()),
            include_evidence=True,
        )
        report = materializer.materialize(graph, entry, MID, SID)
        assert report.wrote == 1
        assert report.skipped == 0
        loaded = memory.retrieve(report.memory_ids[0])
        assert loaded.memory_type.value == "knowledge"
        assert loaded.key.startswith("attack_graph:")
        assert loaded.status == EvidenceStatus.OBSERVED
        assert loaded.source.value == "capability_execution"
        assert loaded.tags == ["attack_graph", graph.graph_id]
        assert loaded.metadata["graph_id"] == graph.graph_id

    def test_materialize_never_elevates_hypothetical(self) -> None:
        world = _store_pair()[0]
        app = world.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.APPLICATION,
                name="hi-app",
                properties={"url": TARGET},
                epistemic_status=EvidenceStatus.HYPOTHESIZED,
            )
        ).entity
        graph = _build_graph(world)
        memory = MemoryManager()
        report = AttackGraphMemoryMaterializer(memory=memory).materialize(
            graph,
            MaterializeEntry(node_entity_ids=(str(app.id),)),
            MID,
            SID,
        )
        loaded = memory.retrieve(report.memory_ids[0])
        assert loaded.status == EvidenceStatus.HYPOTHESIZED
        assert loaded.source.value == "llm_inference"

    def test_materialize_validated_maps_down_never_up(self) -> None:
        world, evstore = _store_pair()
        ev = _evidence(evstore)
        app = world.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.APPLICATION,
                name="val-app",
                properties={"url": TARGET},
                epistemic_status=EvidenceStatus.VALIDATED,
                confidence=Confidence.HIGH,
                evidence=[EvidenceLinkRef(evidence_id=ev.id)],
            )
        ).entity
        graph = _build_graph(world)
        memory = MemoryManager()
        report = AttackGraphMemoryMaterializer(memory=memory).materialize(
            graph, MaterializeEntry(node_entity_ids=(str(app.id),)), MID, SID
        )
        loaded = memory.retrieve(report.memory_ids[0])
        assert loaded.status in {EvidenceStatus.OBSERVED, EvidenceStatus.INFERRED}
        assert loaded.status is not EvidenceStatus.VALIDATED
        assert graph_state_to_evidence_status(GraphState.VALIDATED) == (
            EvidenceStatus.INFERRED
        )

    def test_materialize_health_check(self) -> None:
        assert AttackGraphMemoryMaterializer(memory=None).health_check() is True
        assert AttackGraphMemoryMaterializer(memory=MemoryManager()).health_check() is True

    def test_materialize_deterministic(self) -> None:
        graph = _build_graph()
        entity_ids = tuple(str(n.entity_id) for n in graph.nodes())
        memory = MemoryManager()
        entry = MaterializeEntry(node_entity_ids=entity_ids)
        first = AttackGraphMemoryMaterializer(memory=memory).materialize(
            graph, entry, MID, SID
        )
        second = AttackGraphMemoryMaterializer(memory=memory).materialize(
            graph, entry, MID, SID
        )
        assert first.wrote == 1
        assert second.wrote == 1


# ---------------------------------------------------------------------- #
# Validation
# ---------------------------------------------------------------------- #
class TestValidation:
    def test_assert_safe_relationship_passes(self) -> None:
        assert_safe_graph_relationship(GraphRelationship.EXPOSES)

    def test_validate_node_requires_validated_evidence(self) -> None:
        node = AttackGraphNode(
            mission_id=MID,
            graph_id="g",
            entity_id=WorldEntityID("e"),
            entity_type="application",
            name="app",
            state=GraphState.VALIDATED,
        )
        with pytest.raises(GraphValidationError):
            validate_node_state(node, supporting_validated=0)
        validate_node_state(node, supporting_validated=1)

    def test_validate_node_archived_not_validated(self) -> None:
        node = AttackGraphNode(
            mission_id=MID,
            graph_id="g",
            entity_id=WorldEntityID("e"),
            entity_type="application",
            name="app",
            state=GraphState.VALIDATED,
            lifecycle=GraphLifecycle.ARCHIVED,
        )
        with pytest.raises(GraphValidationError):
            validate_node_state(node, supporting_validated=1)

    def test_validate_edge_non_validatable_cannot_be_validated(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("b", "application", GraphState.OBSERVED),
            ],
            [("a", "b", GraphRelationship.DEPENDS_ON, GraphState.VALIDATED)],
        )
        edge = graph.edges()[0]
        with pytest.raises(GraphValidationError):
            validate_edge(edge)

    def test_validate_edge_validatable_requires_validated_endpoints(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("b", "application", GraphState.OBSERVED),
            ],
            [("a", "b", GraphRelationship.EXPOSES, GraphState.VALIDATED)],
        )
        edge = graph.edges()[0]
        with pytest.raises(GraphValidationError):
            validate_edge(edge)
        src = graph.node_for_entity("a")
        tgt = graph.node_for_entity("b")
        validate_edge(edge, source_validated=True, target_validated=True)
        assert src is not None and tgt is not None

    def test_validate_edge_archived_not_validated(self) -> None:
        graph = _manual_graph(
            [
                ("a", "endpoint", GraphState.OBSERVED),
                ("b", "application", GraphState.OBSERVED),
            ],
            [("a", "b", GraphRelationship.EXPOSES, GraphState.VALIDATED)],
        )
        edge = graph.edges()[0]
        edge.lifecycle = GraphLifecycle.ARCHIVED
        with pytest.raises(GraphValidationError):
            validate_edge(edge, source_validated=True, target_validated=True)

    def test_validate_path_topology(self) -> None:
        good = GraphPath(mission_id=MID, graph_id="g", start_entity_id="a", end_entity_id="b")
        good.node_ids = [0, 0]
        good.edge_ids = [0]
        good.length = 1
        validate_path(good)
        bad = good.model_copy()
        bad.length = 0
        with pytest.raises(GraphValidationError):
            validate_path(bad)

    def test_validate_path_inconsistent_topology(self) -> None:
        path = GraphPath(mission_id=MID, graph_id="g", start_entity_id="a", end_entity_id="b")
        path.node_ids = [0]
        path.edge_ids = [0, 1]
        path.length = 1
        with pytest.raises(GraphValidationError):
            validate_path(path)

    def test_validate_plan_structure(self) -> None:
        plan = AssessmentPlan(
            mission_id=MID,
            graph_id="g",
            steps=[
                PlanStep(
                    step_id="s1",
                    order=1,
                    action=CandidateAction(capability_name="app_probe", target="t", gap="g"),
                ),
                PlanStep(
                    step_id="s2",
                    order=2,
                    action=CandidateAction(capability_name="http_probe", target="t", gap="g"),
                ),
            ],
        )
        validate_plan(plan)

    def test_validate_plan_rejects_unordered(self) -> None:
        plan = AssessmentPlan(
            mission_id=MID,
            graph_id="g",
            status=PlanStatus.PLAN_READY,
            steps=[
                PlanStep(
                    step_id="s1",
                    order=2,
                    action=CandidateAction(capability_name="app_probe", target="t", gap="g"),
                ),
                PlanStep(
                    step_id="s2",
                    order=1,
                    action=CandidateAction(capability_name="http_probe", target="t", gap="g"),
                ),
            ],
        )
        with pytest.raises(PlanningError):
            validate_plan(plan)

    def test_validate_plan_rejects_duplicate_capabilities(self) -> None:
        plan = AssessmentPlan(
            mission_id=MID,
            graph_id="g",
            steps=[
                PlanStep(
                    step_id="s1",
                    order=1,
                    action=CandidateAction(capability_name="app_probe", target="t", gap="g"),
                ),
                PlanStep(
                    step_id="s2",
                    order=2,
                    action=CandidateAction(capability_name="app_probe", target="t", gap="g"),
                ),
            ],
        )
        with pytest.raises(PlanningError):
            validate_plan(plan)

    def test_validate_plan_rejects_ready_without_steps(self) -> None:
        plan = AssessmentPlan(
            mission_id=MID,
            graph_id="g",
            status=PlanStatus.PLAN_READY,
            steps=[],
        )
        with pytest.raises(PlanningError):
            validate_plan(plan)

    def test_validate_plan_rejects_zero_bounds(self) -> None:
        plan = AssessmentPlan(
            mission_id=MID,
            graph_id="g",
            max_steps=0,
        )
        with pytest.raises(PlanningError):
            validate_plan(plan)

    def test_offensive_semantics_probe(self) -> None:
        assert graph_contains_offensive_semantics(["exploits", "exposes"]) is True
        assert graph_contains_offensive_semantics(["exposes", "requires"]) is False
        assert graph_contains_offensive_semantics([]) is False


# ---------------------------------------------------------------------- #
# Bootstrap integration
# ---------------------------------------------------------------------- #
class TestBootstrap:
    def test_attack_graph_verify_keys(self) -> None:
        app = bootstrap()
        checks = app.verify()
        assert checks["attack_graph_ready"] is True
        assert checks["planner_ready"] is True
        assert app.attack_graph_builder is not None
        assert app.attack_graph_repository is not None
        assert app.attack_graph_planner is not None
        assert app.healthy() is True

    def test_bootstrap_registry_size_preserved(self) -> None:
        app = bootstrap()
        caps = app.capability_registry.list_capabilities()
        assert len(caps) == 105
        assert len(set(caps)) == 105
        metas = app.capability_registry.list_meta()
        assert sorted(caps) == sorted(m.name for m in metas)

    def test_bootstrap_planner_persists_plans(self) -> None:
        app = bootstrap()
        world = app.world_model
        ev = app.evidence_store.add(
            Evidence(
                mission_id=MID,
                source_capability="http_probe",
                target="api.aelionix.io",
                evidence_type=EvidenceType.OBSERVATION,
                provenance=Provenance(capability_id="http_probe"),
            )
        )
        front = world.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.EDGE_ENDPOINT,
                name="edge-fe",
                epistemic_status=EvidenceStatus.OBSERVED,
                evidence=[EvidenceLinkRef(evidence_id=ev.id)],
            )
        ).entity
        app_entity = world.add_entity(
            EntitySpec(
                mission_id=MID,
                entity_type=EntityType.APPLICATION,
                name="payments-app",
                properties={"url": TARGET},
                epistemic_status=EvidenceStatus.OBSERVED,
                evidence=[EvidenceLinkRef(evidence_id=ev.id)],
            )
        ).entity
        world.add_relationship(
            RelationshipSpec(
                mission_id=MID,
                relationship_type=RelationshipType.SERVES,
                source_entity_id=front.id,
                target_entity_id=app_entity.id,
                evidence=[EvidenceLinkRef(evidence_id=ev.id)],
            )
        )
        graph = app.attack_graph_builder.build(
            AttackGraphBuildRequest(mission_id=MID, session_id=SID)
        ).graph
        plan = app.attack_graph_planner.plan(
            PlanningRequest(
                mission_id=MID,
                session_id=SID,
                scope=_scope(),
                graph=graph,
            )
        )
        assert plan.status == PlanStatus.NO_ACTION_AVAILABLE
        assert app.attack_graph_repository.get_plan(str(plan.id)) is not None

    def test_bootstrap_builder_uses_app_world_model(self) -> None:
        app = bootstrap()
        world = app.world_model
        ev = app.evidence_store.add(
            Evidence(
                mission_id="mission_other",
                source_capability="mock_discovery",
                target="t",
                evidence_type=EvidenceType.OBSERVATION,
                provenance=Provenance(capability_id="mock_discovery"),
            )
        )
        world.add_entity(
            EntitySpec(
                mission_id="mission_other",
                entity_type=EntityType.APPLICATION,
                name="headless",
                epistemic_status=EvidenceStatus.OBSERVED,
                evidence=[EvidenceLinkRef(evidence_id=ev.id)],
            )
        )
        graph = app.attack_graph_builder.build(
            AttackGraphBuildRequest(mission_id="mission_other")
        ).graph
        assert graph.node_count == 1


# ---------------------------------------------------------------------- #
# Security scan of the attack-graph package
# ---------------------------------------------------------------------- #
class TestSecurityScan:
    @pytest.mark.parametrize(
        "token",
        [
            "os.system",
            "subprocess",
            "socket",
            "requests.",
            "httpx",
            "pickle",
            "__import__(",
        ],
    )
    def test_no_banned_import_tokens(self, token) -> None:
        for source in _pkg_sources():
            assert token not in source

    @pytest.mark.parametrize("token", [r"\beval\s*\(", r"\bexec\s*\("])
    def test_no_eval_or_exec(self, token) -> None:
        for source in _pkg_sources():
            assert not re.search(token, source)

    def test_no_offensive_relationship_semantics(self) -> None:
        for source in _pkg_sources():
            lowered = source.lower()
            cleaned = re.sub(
                r"_offensive_(relationships|words)\s*=.*?\)",
                "",
                lowered,
                flags=re.S,
            )
            assert "exploits" not in cleaned
            assert "compromises" not in cleaned
            assert "bypasses_auth" not in cleaned
        missing = _OFFENSIVE_WORDS - {m.value for m in GraphRelationship}
        assert missing == set(
            {"exploits", "compromises", "intrudes", "cracks", "breaks", "bypasses",
             "exfiltrates", "escalates"}
        )

    def test_planner_never_executes(self) -> None:
        planner_source = (_PKG_ROOT / "planner.py").read_text()
        assert "capability.execute" not in planner_source
        assert "run(" not in planner_source
        assert "os." not in planner_source


def _pkg_sources():
    return [p.read_text() for p in _PKG_ROOT.glob("*.py")]
