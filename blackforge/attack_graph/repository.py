"""Persistence for derived attack-graph records and assessment plans.

Three layers: the abstract :class:`AttackGraphRepository`, an in-memory
repository for fast, mission-scoped operation, and a SQLite repository for
durable persistence with dedup-aware, supersede-preserving writes. Graph and
plan records are identified by ``mission_id`` + ``graph_id`` and deduplicated
by deterministic keys; superseded rows coexist with their successors because
the dedup uniqueness index only constrains non-superseded (active) rows.
"""

from __future__ import annotations

import sqlite3
import time
from abc import ABC, abstractmethod
from typing import Any

from blackforge.attack_graph.graph import AttackGraph
from blackforge.attack_graph.models import (
    AssessmentPlan,
    AttackGraphEdge,
    AttackGraphNode,
)
from blackforge.core.logging import get_logger
from blackforge.core.types import MissionID

log = get_logger("attack_graph.repository")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_graph_headers (
    graph_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_headers_mission ON attack_graph_headers(mission_id, created_at);
CREATE TABLE IF NOT EXISTS attack_graph_nodes (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    graph_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    confidence TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    supersedes TEXT
);
CREATE INDEX IF NOT EXISTS idx_nodes_graph ON attack_graph_nodes(graph_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_dedup
    ON attack_graph_nodes(graph_id, dedup_key) WHERE lifecycle != 'superseded';
CREATE TABLE IF NOT EXISTS attack_graph_edges (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    graph_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    relationship TEXT NOT NULL,
    state TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    confidence TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    supersedes TEXT
);
CREATE INDEX IF NOT EXISTS idx_edges_graph ON attack_graph_edges(graph_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_dedup
    ON attack_graph_edges(graph_id, dedup_key) WHERE lifecycle != 'superseded';
CREATE TABLE IF NOT EXISTS attack_graph_plans (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    graph_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plans_mission ON attack_graph_plans(mission_id);
"""


class AttackGraphRepository(ABC):
    """Repository contract for derived graphs and assessment plans."""

    @abstractmethod
    def save_graph(self, graph: AttackGraph) -> str:
        """Persist a graph, returning its graph_id."""

    @abstractmethod
    def get_graph(self, graph_id: str) -> AttackGraph | None:
        """Load a graph by id (including its archived history)."""

    @abstractmethod
    def get_latest_graph(self, mission_id: MissionID) -> AttackGraph | None:
        """Load the most recently saved graph for a mission."""

    @abstractmethod
    def store_plan(self, plan: AssessmentPlan) -> str:
        """Persist an assessment plan, returning its plan_id."""

    @abstractmethod
    def get_plan(self, plan_id: str) -> AssessmentPlan | None:
        """Load a single plan by id."""

    @abstractmethod
    def plans_for_mission(self, mission_id: MissionID) -> list[AssessmentPlan]:
        """All plans for a mission, newest first."""

    @abstractmethod
    def health_check(self) -> bool:
        """Non-destructive backend health probe."""

    @abstractmethod
    def close(self) -> None:
        """Release held resources; idempotent-safe."""


class InMemoryAttackGraphRepository(AttackGraphRepository):
    """Mission-scoped, thread-safe in-memory repository."""

    def __init__(self) -> None:
        self._graphs: dict[str, AttackGraph] = {}
        self._mission_latest: dict[str, str] = {}
        self._plans: dict[str, AssessmentPlan] = {}

    def save_graph(self, graph: AttackGraph) -> str:
        self._graphs[graph.graph_id] = graph
        self._mission_latest[str(graph.mission_id)] = graph.graph_id
        return graph.graph_id

    def get_graph(self, graph_id: str) -> AttackGraph | None:
        return self._graphs.get(graph_id)

    def get_latest_graph(self, mission_id: MissionID) -> AttackGraph | None:
        graph_id = self._mission_latest.get(str(mission_id))
        if graph_id is None:
            return None
        return self._graphs.get(graph_id)

    def store_plan(self, plan: AssessmentPlan) -> str:
        self._plans[str(plan.id)] = plan
        return str(plan.id)

    def get_plan(self, plan_id: str) -> AssessmentPlan | None:
        return self._plans.get(plan_id)

    def plans_for_mission(self, mission_id: MissionID) -> list[AssessmentPlan]:
        plans = [p for p in self._plans.values() if str(p.mission_id) == str(mission_id)]
        plans.sort(key=lambda p: p.created_at, reverse=True)
        return plans

    def health_check(self) -> bool:
        return True

    def close(self) -> None:
        return None


class SQLiteAttackGraphRepository(AttackGraphRepository):
    """SQLite-backed repository with dedup-aware, history-preserving writes.

    Saving a graph upserts the header then writes node/edge rows while a)
    skipping rows whose (graph_id, dedup_key) already exists with the same
    state (a corroborating no-op), b) archiving the previous active row as
    ``SUPERSEDED`` and inserting a versioned successor when state differs.
    Rebuilds argue corroborate instead of duplicate, and history is never
    silently destroyed.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._connect()

    def _connect(self) -> None:
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------ #
    # Graph persistence
    # ------------------------------------------------------------------ #
    def save_graph(self, graph: AttackGraph) -> str:
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO attack_graph_headers (graph_id, mission_id, created_at) "
                "VALUES (?, ?, ?)",
                (graph.graph_id, str(graph.mission_id), time.time()),
            )
            for node in graph.nodes():
                self._save_node(node)
            for edge in graph.edges():
                self._save_edge(edge)
            for archived in graph.archived_nodes():
                _insert_node(self._conn, _node_row(archived))
            for archived in graph.archived_edges():
                _insert_edge(self._conn, _edge_row(archived))
        return graph.graph_id

    def _save_node(self, node: AttackGraphNode) -> None:
        assert self._conn is not None
        existing = _active_row(
            self._conn, "attack_graph_nodes", node.graph_id, node.dedup_key
        )
        if existing is not None and existing["state"] == node.state.value:
            return
        if existing is not None:
            _archive(self._conn, "attack_graph_nodes", node.graph_id, node.dedup_key)
        _insert_node(self._conn, _node_row(node))

    def _save_edge(self, edge: AttackGraphEdge) -> None:
        assert self._conn is not None
        existing = _active_row(
            self._conn, "attack_graph_edges", edge.graph_id, edge.dedup_key
        )
        if existing is not None and existing["state"] == edge.state.value:
            return
        if existing is not None:
            _archive(self._conn, "attack_graph_edges", edge.graph_id, edge.dedup_key)
        _insert_edge(self._conn, _edge_row(edge))

    def get_graph(self, graph_id: str) -> AttackGraph | None:
        assert self._conn is not None
        header = self._conn.execute(
            "SELECT mission_id, graph_id FROM attack_graph_headers WHERE graph_id = ?",
            (graph_id,),
        ).fetchone()
        if header is None:
            return None

        graph = AttackGraph(
            mission_id=MissionID(header["mission_id"]),
            graph_id=header["graph_id"],
        )
        for row in self._conn.execute(
            "SELECT * FROM attack_graph_nodes WHERE graph_id = ? AND lifecycle = 'superseded'",
            (graph_id,),
        ):
            graph._archived_nodes[row["id"]] = _node_from_row(row)
        for row in self._conn.execute(
            "SELECT * FROM attack_graph_nodes WHERE graph_id = ? AND lifecycle != 'superseded'",
            (graph_id,),
        ):
            node = _node_from_row(row)
            graph._nodes[row["id"]] = node
            graph._node_by_entity[row["entity_id"]] = node
        for row in self._conn.execute(
            "SELECT * FROM attack_graph_edges WHERE graph_id = ? AND lifecycle = 'superseded'",
            (graph_id,),
        ):
            graph._archived_edges[row["id"]] = _edge_from_row(row)
        for row in self._conn.execute(
            "SELECT * FROM attack_graph_edges WHERE graph_id = ? AND lifecycle != 'superseded'",
            (graph_id,),
        ):
            edge = _edge_from_row(row)
            graph._edges[row["id"]] = edge
            if edge.dedup_key:
                graph._edges_by_dedup[edge.dedup_key] = edge
        return graph

    def get_latest_graph(self, mission_id: MissionID) -> AttackGraph | None:
        assert self._conn is not None
        header = self._conn.execute(
            "SELECT graph_id FROM attack_graph_headers "
            "WHERE mission_id = ? ORDER BY created_at DESC LIMIT 1",
            (str(mission_id),),
        ).fetchone()
        if header is None:
            return None
        return self.get_graph(header["graph_id"])

    # ------------------------------------------------------------------ #
    # Plan persistence
    # ------------------------------------------------------------------ #
    def store_plan(self, plan: AssessmentPlan) -> str:
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO attack_graph_plans "
                "(id, mission_id, graph_id, status, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(plan.id),
                    str(plan.mission_id),
                    plan.graph_id,
                    plan.status.value,
                    plan.model_dump_json(),
                    plan.created_at,
                ),
            )
        return str(plan.id)

    def get_plan(self, plan_id: str) -> AssessmentPlan | None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT payload FROM attack_graph_plans WHERE id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            return None
        return AssessmentPlan.model_validate_json(row["payload"])

    def plans_for_mission(self, mission_id: MissionID) -> list[AssessmentPlan]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT payload FROM attack_graph_plans "
            "WHERE mission_id = ? ORDER BY created_at DESC",
            (str(mission_id),),
        ).fetchall()
        return [AssessmentPlan.model_validate_json(r["payload"]) for r in rows]

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def health_check(self) -> bool:
        try:
            if self._conn is None:
                return False
            self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


# --------------------------------------------------------------------- #
# Row helpers (kept in this module to stay close to the schema)
# --------------------------------------------------------------------- #
def _node_row(node: AttackGraphNode) -> tuple:
    return (
        str(node.id),
        str(node.mission_id),
        node.graph_id,
        str(node.entity_id),
        node.entity_type,
        node.name,
        node.state.value,
        node.lifecycle.value,
        node.confidence.value,
        node.dedup_key or "",
        node.version,
        str(node.supersedes) if node.supersedes else None,
    )


def _edge_row(edge: AttackGraphEdge) -> tuple:
    return (
        str(edge.id),
        str(edge.mission_id),
        edge.graph_id,
        str(edge.source_node_id),
        str(edge.target_node_id),
        str(edge.source_entity_id),
        str(edge.target_entity_id),
        edge.relationship.value,
        edge.state.value,
        edge.lifecycle.value,
        edge.confidence.value,
        edge.dedup_key or "",
        edge.version,
        str(edge.supersedes) if edge.supersedes else None,
    )


def _insert_node(conn: sqlite3.Connection, row: tuple) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO attack_graph_nodes "
        "(id, mission_id, graph_id, entity_id, entity_type, name, state, "
        "lifecycle, confidence, dedup_key, version, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        row,
    )


def _insert_edge(conn: sqlite3.Connection, row: tuple) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO attack_graph_edges "
        "(id, mission_id, graph_id, source_node_id, target_node_id, "
        "source_entity_id, target_entity_id, relationship, state, lifecycle, "
        "confidence, dedup_key, version, supersedes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        row,
    )


def _active_row(
    conn: sqlite3.Connection, table: str, graph_id: str, dedup_key: str | None
) -> Any | None:
    if not dedup_key:
        return None
    return conn.execute(
        f"SELECT state FROM {table} "
        "WHERE graph_id = ? AND dedup_key = ? AND lifecycle != 'superseded'",
        (graph_id, dedup_key),
    ).fetchone()


def _archive(conn: sqlite3.Connection, table: str, graph_id: str, dedup_key: str | None) -> None:
    if not dedup_key:
        return
    conn.execute(
        f"UPDATE {table} SET lifecycle = 'superseded' "
        "WHERE graph_id = ? AND dedup_key = ? AND lifecycle != 'superseded'",
        (graph_id, dedup_key),
    )


def _node_from_row(row: Any) -> AttackGraphNode:
    return AttackGraphNode(
        id=row["id"],
        mission_id=MissionID(row["mission_id"]),
        graph_id=row["graph_id"],
        entity_id=row["entity_id"],
        entity_type=row["entity_type"],
        name=row["name"],
        state=row["state"],
        lifecycle=row["lifecycle"],
        confidence=row["confidence"],
        dedup_key=row["dedup_key"],
        version=row["version"],
        supersedes=row["supersedes"],
    )


def _edge_from_row(row: Any) -> AttackGraphEdge:
    return AttackGraphEdge(
        id=row["id"],
        mission_id=MissionID(row["mission_id"]),
        graph_id=row["graph_id"],
        source_node_id=row["source_node_id"],
        target_node_id=row["target_node_id"],
        source_entity_id=row["source_entity_id"],
        target_entity_id=row["target_entity_id"],
        relationship=row["relationship"],
        state=row["state"],
        lifecycle=row["lifecycle"],
        confidence=row["confidence"],
        dedup_key=row["dedup_key"],
        version=row["version"],
        supersedes=row["supersedes"],
    )
