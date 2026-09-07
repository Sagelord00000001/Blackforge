from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

from blackforge.attack_graph.models import (
    AttackGraphEdge,
    AttackGraphNode,
    GraphPath,
    GraphRelationship,
    GraphState,
    PathState,
    Prerequisite,
    PrerequisiteState,
)

if TYPE_CHECKING:
    from blackforge.attack_graph.graph import AttackGraph
    from blackforge.core.types import WorldEntityID


def path_edges(graph: AttackGraph, path: GraphPath) -> list[AttackGraphEdge]:
    return [edge for edge in (graph.get_edge(i) for i in path.edge_ids) if edge is not None]


def path_nodes(graph: AttackGraph, path: GraphPath) -> list[AttackGraphNode]:
    return [node for node in (graph.get_node(i) for i in path.node_ids) if node is not None]


def classify_path(graph: AttackGraph, path: GraphPath) -> PathState:
    """Deterministic epistemic classification of a derived path.

    Classification never upgrades: everything derived is at best
    ``INFERRED_PATH``; ``VALIDATED_PATH`` requires all edges and nodes to be
    validated, which the derived graph reaches only when the sources were
    validated. Contradictions and blocks outrank plain uncertainty.
    """
    nodes = path_nodes(graph, path)
    edges = path_edges(graph, path)

    for node in nodes:
        if node.state == GraphState.CONTRADICTED:
            return PathState.CONTRADICTED_PATH
    for edge in edges:
        if edge.state == GraphState.CONTRADICTED or edge.contradicting_evidence:
            return PathState.CONTRADICTED_PATH
    if _has_blocked_flag(nodes, edges):
        return PathState.BLOCKED_PATH

    if any(n.state == GraphState.INSUFFICIENT_EVIDENCE for n in nodes) or any(
        e.state == GraphState.INSUFFICIENT_EVIDENCE for e in edges
    ):
        return PathState.INSUFFICIENT_EVIDENCE

    validated = bool(edges) and all(
        e.state == GraphState.VALIDATED for e in edges
    ) and all(n.state == GraphState.VALIDATED for n in nodes)
    if validated:
        return PathState.VALIDATED_PATH

    observed = bool(edges) and all(e.state == GraphState.OBSERVED for e in edges)
    if observed:
        return PathState.OBSERVED_PATH

    if any(e.state == GraphState.HYPOTHESIZED for e in edges) or any(
        e.relationship
        in (GraphRelationship.POTENTIALLY_LEADS_TO, GraphRelationship.REQUIRES_VALIDATION)
        for e in edges
    ):
        return PathState.HYPOTHESIZED_PATH

    return PathState.INFERRED_PATH


def _has_blocked_flag(nodes: list[AttackGraphNode], edges: list[AttackGraphEdge]) -> bool:
    if any(n.state == GraphState.BLOCKED for n in nodes):
        return True
    if any(e.state == GraphState.BLOCKED for e in edges):
        return True
    for edge in edges:
        for prereq in edge.prerequisites:
            if prereq.state in ("blocked", "unsatisfied", "contradicted"):
                return True
    return False


def missing_prerequisites(
    graph: AttackGraph, path: GraphPath
) -> list[Prerequisite]:
    """Prerequisites that still need evidence, deduplicated by description."""
    seen: dict[str, Prerequisite] = {}
    for edge in path_edges(graph, path):
        for prereq in edge.prerequisites:
            if prereq.state in {
                PrerequisiteState.UNKNOWN,
                PrerequisiteState.UNSATISFIED,
                PrerequisiteState.BLOCKED,
                PrerequisiteState.CONTRADICTED,
            }:
                seen.setdefault(prereq.description, prereq)
    return [seen[key] for key in sorted(seen)]


def graph_contains_offensive_semantics(graph: AttackGraph) -> bool:
    """Sanity probe: the derived graph never carries offensive predicates."""
    return any(edge.relationship.value in _OFFENSIVE_WORDS for edge in graph.edges())


_OFFENSIVE_WORDS = frozenset(
    {"exploits", "compromises", "intrudes", "cracks", "breaks",
     "overrides", "bypasses", "exfiltrates"}
)


class PathOutcome(BaseModel):
    path_id: str
    state: PathState
    start_entity_id: str
    end_entity_id: str
    length: int
    missing: list[str]


class AttackGraphQuery:
    """Read-side decision support over a derived graph (bounded, pure)."""

    def __init__(self, graph: AttackGraph) -> None:
        self.graph = graph

    def classify(self, path: GraphPath) -> PathState:
        return classify_path(self.graph, path)

    def evaluate(self, path: GraphPath) -> PathOutcome:
        state = self.classify(path)
        missing = [p.description for p in missing_prerequisites(self.graph, path)]
        return PathOutcome(
            path_id=str(path.id),
            state=state,
            start_entity_id=str(path.start_entity_id),
            end_entity_id=str(path.end_entity_id),
            length=path.length,
            missing=missing,
        )

    def paths_for_start(
        self,
        start_entity_id: WorldEntityID | str,
        max_depth: int = 3,
        max_paths: int = 20,
    ) -> list[GraphPath]:
        return self.graph.find_paths(
            start_entity_id, max_depth=max_depth, max_paths=max_paths, surfaces_only=True
        )

    def open_paths(self, max_depth: int = 3, max_paths: int = 100) -> list[GraphPath]:
        """Diverse, bounded path sample across all viable starts."""
        front_nodes = self._viable_starts()
        collected: list[GraphPath] = []
        seen: set[str] = set()
        for node in front_nodes:
            paths = self.graph.find_paths(
                node.entity_id, max_depth=max_depth, max_paths=max_paths, surfaces_only=True
            )
            for path in paths:
                key = "-".join(str(i) for i in path.node_ids)
                if key in seen:
                    continue
                seen.add(key)
                collected.append(path)
                if len(collected) >= max_paths:
                    return collected
        return collected

    def blocked_paths(self) -> list[PathOutcome]:
        return [
            self.evaluate(p)
            for p in _all_paths(self.graph)
            if self.classify(p) == PathState.BLOCKED_PATH
        ]

    def contradicted_paths(self) -> list[PathOutcome]:
        return [
            self.evaluate(p)
            for p in _all_paths(self.graph)
            if self.classify(p) == PathState.CONTRADICTED_PATH
        ]

    def insufficient_paths(self) -> list[PathOutcome]:
        return [
            self.evaluate(p)
            for p in _all_paths(self.graph)
            if self.classify(p) == PathState.INSUFFICIENT_EVIDENCE
        ]

    def uncertain_paths(self, limit: int = 20) -> list[PathOutcome]:
        """Highest-uncertainty paths: the planner's starting point."""
        paths = self.open_paths(max_depth=3, max_paths=200)[:limit]
        return [self.evaluate(p) for p in paths]

    def _viable_starts(self) -> list[AttackGraphNode]:
        starts: list[AttackGraphNode] = []
        for node in self.graph.nodes():
            if (
                node.entity_type
                in {"public_address", "edge_endpoint", "endpoint", "application", "ingress"}
                and any(
                    e.relationship
                    in (GraphRelationship.EXPOSES, GraphRelationship.POTENTIALLY_LEADS_TO)
                    for e in self.graph.out_edges(node.id)
                )
            ):
                starts.append(node)
        return starts


def _all_paths(graph: AttackGraph, max_paths: int = 150) -> list[GraphPath]:
    seen: set[str] = set()
    paths: list[GraphPath] = []
    for node in graph.exposure_surfaces():
        for incoming in graph.in_edges(node.id):
            if incoming.relationship not in (
                GraphRelationship.EXPOSES,
                GraphRelationship.POTENTIALLY_LEADS_TO,
                GraphRelationship.REQUIRES_VALIDATION,
            ):
                continue
            reverse_paths = graph.find_paths(
                incoming.source_entity_id, max_depth=3, max_paths=max_paths, surfaces_only=False
            )
            for path in reverse_paths:
                key = "-".join(str(i) for i in path.node_ids)
                if key in seen:
                    continue
                seen.add(key)
                paths.append(path)
                if len(paths) >= max_paths:
                    return paths
    return paths
