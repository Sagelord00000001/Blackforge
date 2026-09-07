from __future__ import annotations

import time
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from blackforge.attack_graph.graph import AttackGraph
from blackforge.attack_graph.models import (
    AttackGraphEdge,
    AttackGraphNode,
    GraphDerivation,
    GraphLifecycle,
    evidence_status_to_graph_state,
)
from blackforge.attack_graph.rules import (
    DerivedEdgeSpec,
    GraphRule,
    GraphRuleContext,
    default_graph_rules,
    hypothesis_edges,
)
from blackforge.core.logging import get_logger
from blackforge.core.types import (
    EvidenceID,
    MissionID,
    SessionID,
)
from blackforge.world_model.models import (  # noqa: TC001  # pydantic/config boundary
    WorldEntity,
    WorldRelationship,
)
from blackforge.world_model.query import RelationshipQuery, WorldQuery

log = get_logger("attack_graph.builder")

if TYPE_CHECKING:
    from blackforge.evidence.store import EvidenceStore
    from blackforge.world_model.store import WorldModelStore

_MAX_GRAPH_NODES = 1000
_MAX_GRAPH_EDGES = 5000


class AttackGraphBuildRequest(BaseModel):
    """Inputs for a deterministic graph build over a mission's world model."""

    mission_id: MissionID
    session_id: SessionID | None = None
    max_nodes: int = Field(default=_MAX_GRAPH_NODES, ge=1, le=_MAX_GRAPH_NODES)
    max_edges: int = Field(default=_MAX_GRAPH_EDGES, ge=1, le=_MAX_GRAPH_EDGES)
    include_hypothesis_edges: bool = True


class RuleApplication(BaseModel):
    rule_id: str
    derived: int = 0
    description: str


class AttackGraphBuildResult(BaseModel):
    """Outcome of a graph build, including full derivation accounting."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    graph: AttackGraph
    node_count: int = 0
    edge_count: int = 0
    derived_edge_count: int = 0
    hypothesis_edge_count: int = 0
    rules: list[RuleApplication] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    started_at: float = Field(default_factory=time.time)
    ended_at: float | None = None
    elapsed_ms: float = 0.0


class AttackGraphBuilder:
    """Derives a mission-scoped analytical graph from the world model.

    The builder is read-only over the world model and evidence store: it
    never mutates them, never executes capabilities, and never accepts LLM
    hypothesis input. Every node/edge is either a direct view of a world
    entity or a rule-derived relationship with full provenance.
    """

    def __init__(
        self,
        world_model: WorldModelStore | None = None,
        evidence_store: EvidenceStore | None = None,
        rules: list[GraphRule] | None = None,
    ) -> None:
        self.world_model = world_model
        self.evidence_store = evidence_store
        self.rules = rules or default_graph_rules()

    def build(self, request: AttackGraphBuildRequest) -> AttackGraphBuildResult:
        started = time.time()
        result = AttackGraphBuildResult(graph=AttackGraph(request.mission_id))
        if self.world_model is None:
            result.warnings.append("no world model available; empty graph returned")
            result.elapsed_ms = (time.time() - started) * 1000.0
            return result

        graph = result.graph
        max_nodes = request.max_nodes
        max_edges = request.max_edges

        entities = self.world_model.list_entities(
            WorldQuery(mission_id=request.mission_id, limit=1000)
        )
        relationships = self.world_model.list_relationships(
            RelationshipQuery(mission_id=request.mission_id, limit=1000)
        )
        if len(entities) > max_nodes:
            entities = entities[:max_nodes]
            result.warnings.append(f"entity list truncated to {max_nodes}")
        if len(relationships) > max_edges:
            relationships = relationships[:max_edges]
            result.warnings.append(f"relationship list truncated to {max_edges}")

        entity_by_id: dict[str, WorldEntity] = {str(e.id): e for e in entities}
        evidence_map = self._relationship_evidence(relationships)

        for entity in entities:
            graph.add_node(self._build_node(graph, request, entity))

        context = GraphRuleContext(
            mission_id=request.mission_id,
            session_id=request.session_id,
            entities=entity_by_id,
            relationships=relationships,
            relationship_evidence=evidence_map,
        )

        for rule in self.rules:
            specs = rule.derive(context)
            derived = 0
            for spec in specs:
                edge = self._build_edge(graph, request, spec)
                if edge is not None and graph.add_edge(edge) is not None:
                    derived += 1
            result.rules.append(
                RuleApplication(rule_id=rule.rule_id, derived=derived, description=rule.description)
            )

        result.derived_edge_count = sum(r.derived for r in result.rules)

        if request.include_hypothesis_edges:
            hypothesis = hypothesis_edges(graph.nodes(), graph.edges())
            hypothesis_count = 0
            for spec in hypothesis:
                edge = self._build_edge(graph, request, spec)
                if edge is not None and graph.add_edge(edge) is not None:
                    hypothesis_count += 1
            result.hypothesis_edge_count = hypothesis_count

        result.node_count = graph.node_count
        result.edge_count = graph.edge_count
        result.ended_at = time.time()
        result.elapsed_ms = (result.ended_at - started) * 1000.0
        log.info(
            "attack_graph_built",
            mission_id=str(request.mission_id),
            graph_id=graph.graph_id,
            nodes=result.node_count,
            edges=result.edge_count,
            derived=result.derived_edge_count,
            hypothesis=result.hypothesis_edge_count,
        )
        return result

    # ------------------------------------------------------------------ #
    def _build_node(
        self, graph: AttackGraph, request: AttackGraphBuildRequest, entity: WorldEntity
    ) -> AttackGraphNode:
        state = evidence_status_to_graph_state(entity.epistemic_status)
        return AttackGraphNode(
            mission_id=request.mission_id,
            graph_id=graph.graph_id,
            entity_id=entity.id,
            entity_type=entity.entity_type.value,
            name=entity.name,
            state=state,
            lifecycle=(
                GraphLifecycle.ACTIVE
                if entity.lifecycle.value == "active"
                else GraphLifecycle.ARCHIVED
            ),
            confidence=entity.confidence,
            supporting_evidence=self._evidence_ids_for_entity(entity),
            properties=dict(entity.properties),
            derivation=GraphDerivation(
                rule_id="ag_entity_mirror",
                source_entity_ids=[str(entity.id)],
                note="direct view of the canonical world entity",
            ),
        )

    def _build_edge(
        self,
        graph: AttackGraph,
        request: AttackGraphBuildRequest,
        spec: DerivedEdgeSpec,
    ) -> AttackGraphEdge | None:
        source_node = graph.node_for_entity(spec.source_entity_id)
        target_node = graph.node_for_entity(spec.target_entity_id)
        if source_node is None or target_node is None:
            return None
        if source_node.entity_id == target_node.entity_id:
            return None
        return AttackGraphEdge(
            mission_id=request.mission_id,
            graph_id=graph.graph_id,
            source_node_id=source_node.id,
            target_node_id=target_node.id,
            source_entity_id=source_node.entity_id,
            target_entity_id=target_node.entity_id,
            relationship=spec.relationship,
            state=spec.state,
            lifecycle=GraphLifecycle.ACTIVE,
            confidence=spec.confidence,
            prerequisites=list(spec.prerequisites),
            constraints=list(spec.constraints),
            assumptions=list(spec.assumptions),
            properties=dict(spec.properties),
            derivation=spec.derivation,
            supporting_evidence=list(spec.derivation.source_evidence_ids),
        )

    def _evidence_ids_for_entity(self, entity: WorldEntity) -> list[EvidenceID]:
        if self.world_model is None:
            return []
        links = self.world_model.evidence_for_entity(str(entity.id))
        return [
            EvidenceID(str(link.get("evidence_id", "")))
            for link in links
            if link.get("evidence_id")
        ]

    def _relationship_evidence(
        self, relationships: list[WorldRelationship]
    ) -> dict[str, list[EvidenceID]]:
        if self.world_model is None:
            return {}
        mapping: dict[str, list[EvidenceID]] = {}
        for rel in relationships:
            links = self.world_model.evidence_for_relationship(str(rel.id))
            ids = [
                EvidenceID(str(link.get("evidence_id", "")))
                for link in links
                if link.get("evidence_id")
            ]
            if ids:
                mapping[str(rel.id)] = ids
        return mapping
