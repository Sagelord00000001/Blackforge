from __future__ import annotations

import uuid

from blackforge.attack_graph.models import (
    AttackGraphEdge,
    AttackGraphNode,
    GraphLifecycle,
    GraphPath,
    GraphRelationship,
    PathState,
    graph_edge_dedup_key,
    graph_node_dedup_key,
)
from blackforge.core.logging import get_logger
from blackforge.core.types import (
    AttackGraphEdgeID,
    AttackGraphNodeID,
    Confidence,
    MissionID,
    WorldEntityID,
)

log = get_logger("attack_graph.graph")

# Edge kinds the traversal may expand along in the natural (out) direction.
_TRAVERSABLE = frozenset(
    {
        GraphRelationship.EXPOSES,
        GraphRelationship.REQUIRES,
        GraphRelationship.DEPENDS_ON,
        GraphRelationship.REACHABLE_FROM,
        GraphRelationship.PROVIDES_ACCESS_TO,
        GraphRelationship.POTENTIALLY_LEADS_TO,
        GraphRelationship.REQUIRES_VALIDATION,
    }
)

# Edge kinds that render a node a potential assessment surface.
_SURFACE_EDGES = frozenset(
    {
        GraphRelationship.EXPOSES,
        GraphRelationship.POTENTIALLY_LEADS_TO,
        GraphRelationship.REQUIRES_VALIDATION,
    }
)


class AttackGraph:
    """An in-memory, mission-scoped derived analytical graph.

    The graph is deliberately *not* a second world model: every node binds to
    a canonical :class:`WorldEntity` and every derivation is traceable. All
    traversal is bounded (depth-capped, cycle-safe, result-limited), and edges
    are deduplicated on a deterministic key so rebuilds corroborate rather
    than duplicate.
    """

    def __init__(
        self,
        mission_id: MissionID,
        graph_id: str | None = None,
    ) -> None:
        self.mission_id = mission_id
        self.graph_id = graph_id or f"graph_{uuid.uuid4().hex[:12]}"
        self._nodes: dict[str, AttackGraphNode] = {}
        self._edges: dict[str, AttackGraphEdge] = {}
        self._archived_nodes: dict[str, AttackGraphNode] = {}
        self._archived_edges: dict[str, AttackGraphEdge] = {}
        self._node_by_entity: dict[str, AttackGraphNode] = {}
        self._edges_by_dedup: dict[str, AttackGraphEdge] = {}

    # ------------------------------------------------------------------ #
    # Structure
    # ------------------------------------------------------------------ #
    def add_node(self, node: AttackGraphNode) -> AttackGraphNode:
        """Insert a node, deduplicating on the canonical entity handle.

        A repeated node with an equivalent state corroborates (refreshes
        ``last_seen``); a materially different state supersedes the previous
        node so history is never silently destroyed.
        """
        if node.mission_id != self.mission_id:
            raise ValueError("node mission does not match graph mission")
        key = str(node.entity_id)
        existing = self._node_by_entity.get(key)
        if existing is None:
            node.dedup_key = node.dedup_key or graph_node_dedup_key(
                node.mission_id, node.graph_id, node.entity_id
            )
            self._nodes[str(node.id)] = node
            self._node_by_entity[key] = node
            return node
        if existing.state == node.state and existing.confidence == node.confidence:
            existing.last_seen = node.created_at
            existing.updated_at = node.created_at
            for eid in node.supporting_evidence:
                if eid not in existing.supporting_evidence:
                    existing.supporting_evidence.append(eid)
            return existing
        return self._supersede_node(existing, node)

    def _supersede_node(self, previous: AttackGraphNode, node: AttackGraphNode) -> AttackGraphNode:
        node.version = previous.version + 1
        node.supersedes = previous.id
        node.dedup_key = node.dedup_key or graph_node_dedup_key(
            node.mission_id, node.graph_id, node.entity_id
        )
        previous.lifecycle = GraphLifecycle.SUPERSEDED
        previous.updated_at = node.created_at
        self._archived_nodes[str(previous.id)] = previous
        self._nodes.pop(str(previous.id), None)
        self._nodes[str(node.id)] = node
        self._node_by_entity[str(node.entity_id)] = node
        log.info(
            "attack_graph_node_superseded",
            node_id=str(node.id),
            previous=str(previous.id),
        )
        return node

    def add_edge(self, edge: AttackGraphEdge) -> AttackGraphEdge:
        """Insert an edge with deterministic dedup by its relationship pair."""
        if edge.mission_id != self.mission_id:
            raise ValueError("edge mission does not match graph mission")
        if edge.source_node_id not in self._nodes or edge.target_node_id not in self._nodes:
            raise ValueError("edge references unknown node")
        if edge.source_entity_id == edge.target_entity_id:
            raise ValueError("self-loop graph edges are not supported")
        key = graph_edge_dedup_key(
            edge.mission_id,
            edge.graph_id,
            edge.relationship,
            edge.source_entity_id,
            edge.target_entity_id,
        )
        existing = self._edges_by_dedup.get(key)
        if existing is None:
            edge.dedup_key = edge.dedup_key or key
            self._edges[str(edge.id)] = edge
            self._edges_by_dedup[key] = edge
            return edge
        if existing.state == edge.state and existing.confidence == edge.confidence:
            existing.last_seen = edge.created_at
            existing.updated_at = edge.created_at
            for eid in edge.supporting_evidence:
                if eid not in existing.supporting_evidence:
                    existing.supporting_evidence.append(eid)
            for prereq in edge.prerequisites:
                if prereq not in existing.prerequisites:
                    existing.prerequisites.append(prereq)
            return existing
        return self._supersede_edge(existing, edge)

    def _supersede_edge(self, previous: AttackGraphEdge, edge: AttackGraphEdge) -> AttackGraphEdge:
        edge.version = previous.version + 1
        edge.supersedes = previous.id
        edge.dedup_key = edge.dedup_key or graph_edge_dedup_key(
            edge.mission_id,
            edge.graph_id,
            edge.relationship,
            edge.source_entity_id,
            edge.target_entity_id,
        )
        previous.lifecycle = GraphLifecycle.SUPERSEDED
        previous.updated_at = edge.created_at
        self._archived_edges[str(previous.id)] = previous
        self._edges.pop(str(previous.id), None)
        self._edges[str(edge.id)] = edge
        self._edges_by_dedup[edge.dedup_key] = edge
        return edge

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def get_node(self, node_id: AttackGraphNodeID | str) -> AttackGraphNode | None:
        return self._nodes.get(str(node_id))

    def node_for_entity(self, entity_id: WorldEntityID | str) -> AttackGraphNode | None:
        return self._node_by_entity.get(str(entity_id))

    def get_edge(self, edge_id: AttackGraphEdgeID | str) -> AttackGraphEdge | None:
        return self._edges.get(str(edge_id))

    def nodes(self) -> list[AttackGraphNode]:
        return sorted(self._nodes.values(), key=lambda n: str(n.id))

    def edges(self) -> list[AttackGraphEdge]:
        return sorted(self._edges.values(), key=lambda e: str(e.id))

    def archived_nodes(self) -> list[AttackGraphNode]:
        return sorted(self._archived_nodes.values(), key=lambda n: str(n.id))

    def archived_edges(self) -> list[AttackGraphEdge]:
        return sorted(self._archived_edges.values(), key=lambda e: str(e.id))

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def out_edges(self, node_id: AttackGraphNodeID | str) -> list[AttackGraphEdge]:
        key = str(node_id)
        return sorted(
            (e for e in self._edges.values() if str(e.source_node_id) == key),
            key=lambda e: str(e.id),
        )

    def in_edges(self, node_id: AttackGraphNodeID | str) -> list[AttackGraphEdge]:
        key = str(node_id)
        return sorted(
            (e for e in self._edges.values() if str(e.target_node_id) == key),
            key=lambda e: str(e.id),
        )

    def neighbors(
        self,
        node_id: AttackGraphNodeID | str,
        direction: str = "both",
        relationship_types: list[GraphRelationship] | None = None,
        limit: int = 100,
    ) -> list[tuple[AttackGraphEdge, AttackGraphNode]]:
        """Bounded one-hop neighborhood; never traverses freely."""
        key = str(node_id)
        allowed = set(relationship_types) if relationship_types else None
        result: list[tuple[AttackGraphEdge, AttackGraphNode]] = []
        for edge in self._edges.values():
            if allowed is not None and edge.relationship not in allowed:
                continue
            out = str(edge.source_node_id) == key
            incoming = str(edge.target_node_id) == key
            if not (out or incoming):
                continue
            if direction == "out" and not out:
                continue
            if direction == "in" and not incoming:
                continue
            neighbor = self._nodes.get(
                str(edge.target_node_id) if out else str(edge.source_node_id)
            )
            if neighbor is None:
                continue
            result.append((edge, neighbor))
            if len(result) >= limit:
                break
        result.sort(key=lambda pair: (pair[0].relationship.value, str(pair[1].id)))
        return result

    def exposure_surfaces(self) -> list[AttackGraphNode]:
        """Nodes that own an inbound exposure/potential/validation edge."""
        surface_ids = {
            str(e.target_node_id) for e in self._edges.values() if e.relationship in _SURFACE_EDGES
        }
        return sorted(
            (n for n in self._nodes.values() if str(n.id) in surface_ids),
            key=lambda n: str(n.id),
        )

    def hypothesis_edges(self) -> list[AttackGraphEdge]:
        return [
            e
            for e in self._edges.values()
            if e.relationship == GraphRelationship.POTENTIALLY_LEADS_TO
        ]

    def has_cycle(self, start_entity_id: WorldEntityID | str) -> bool:
        """Self-contained cycle probe over traversable edges (bounded)."""
        start = self.node_for_entity(start_entity_id)
        if start is None:
            return False
        visited: set[str] = set()
        stack: list[str] = [str(start.id)]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for edge in self.out_edges(current):
                if edge.relationship not in _TRAVERSABLE:
                    continue
                target = str(edge.target_node_id)
                if target == str(start.id):
                    return True
                if target not in visited:
                    stack.append(target)
        return False

    # ------------------------------------------------------------------ #
    # Bounded path derivation
    # ------------------------------------------------------------------ #
    def find_paths(
        self,
        start_entity_id: WorldEntityID | str,
        max_depth: int = 3,
        max_paths: int = 20,
        surfaces_only: bool = True,
    ) -> list[GraphPath]:
        """Deterministic, cycle-safe, bounded simple-path derivation.

        Starts at the node for ``start_entity_id`` and follows traversable
        out-edges up to ``max_depth`` hops. When ``surfaces_only`` is set, a
        branch stops expanding once it reaches a node that carries an inbound
        exposure/potential/validation edge (an assessment surface). Depth and
        result counts are strictly capped.
        """
        start = self.node_for_entity(start_entity_id)
        if start is None:
            return []
        max_depth = max(1, min(int(max_depth), 6))
        max_paths = max(1, min(int(max_paths), 200))

        surface_ids = {str(n.id) for n in self.exposure_surfaces()}
        paths: list[GraphPath] = []

        def _walk(node_ids: list[str], edge_ids: list[str], depth: int) -> None:
            if len(paths) >= max_paths:
                return
            current = node_ids[-1]
            if surfaces_only and depth > 1 and current in surface_ids:
                paths.append(self._build_path(node_ids, edge_ids))
                return
            if depth >= max_depth:
                paths.append(self._build_path(node_ids, edge_ids))
                return
            for edge in self.out_edges(current):
                if edge.relationship not in _TRAVERSABLE:
                    continue
                target = str(edge.target_node_id)
                if target in node_ids:
                    continue
                node_ids.append(target)
                edge_ids.append(str(edge.id))
                _walk(node_ids, edge_ids, depth + 1)
                node_ids.pop()
                edge_ids.pop()

        _walk([str(start.id)], [], 1)
        return paths

    def _build_path(self, node_ids: list[str], edge_ids: list[str]) -> GraphPath:
        nodes = [self._nodes[nid] for nid in node_ids if nid in self._nodes]
        edges = [self._edges[eid] for eid in edge_ids if eid in self._edges]
        supporting: list[str] = []
        for edge in edges:
            for eid in edge.supporting_evidence:
                if eid not in supporting:
                    supporting.append(eid)
        confidence = self._aggregate_confidence(edges)
        return GraphPath(
            mission_id=self.mission_id,
            graph_id=self.graph_id,
            start_entity_id=nodes[0].entity_id,
            end_entity_id=nodes[-1].entity_id,
            state=PathState.HYPOTHESIZED_PATH,
            node_ids=[n.id for n in nodes],
            edge_ids=[e.id for e in edges],
            confidence=confidence,
            supporting_evidence=[eid for eid in supporting],
            length=len(node_ids) - 1,
        )

    def _aggregate_confidence(self, edges: list[AttackGraphEdge]) -> Confidence:
        """Deterministic: the weakest confidence on the path."""
        if not edges:
            return Confidence.MEDIUM
        best = Confidence.CONFIRMED
        for edge in edges:
            if Confidence.to_score is not None:
                score = edge.confidence.to_score()
                if score < best.to_score():
                    best = edge.confidence
        return best

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict:
        return {
            "mission_id": str(self.mission_id),
            "graph_id": self.graph_id,
            "nodes": [n.model_dump(mode="json") for n in self.nodes()],
            "edges": [e.model_dump(mode="json") for e in self.edges()],
            "archived_nodes": [n.model_dump(mode="json") for n in self.archived_nodes()],
            "archived_edges": [e.model_dump(mode="json") for e in self.archived_edges()],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> AttackGraph:
        graph = cls(
            mission_id=MissionID(payload["mission_id"]),
            graph_id=payload["graph_id"],
        )
        for item in payload.get("archived_nodes", []):
            node = AttackGraphNode.model_validate(item)
            graph._archived_nodes[str(node.id)] = node
        for item in payload.get("nodes", []):
            node = AttackGraphNode.model_validate(item)
            graph._nodes[str(node.id)] = node
            graph._node_by_entity[str(node.entity_id)] = node
        for item in payload.get("archived_edges", []):
            edge = AttackGraphEdge.model_validate(item)
            graph._archived_edges[str(edge.id)] = edge
        for item in payload.get("edges", []):
            edge = AttackGraphEdge.model_validate(item)
            graph._edges[str(edge.id)] = edge
            graph._edges_by_dedup[str(edge.dedup_key)] = edge
        return graph
