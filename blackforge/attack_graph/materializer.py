"""Bridge the derived attack graph into BLACKFORGE memory.

The materializer is a *summary* bridge: it writes one KNOWLEDGE record per
requested slice of the derived graph so later phases can reason over the
attack-graph layer. It never elevates — graph state maps back down using
``graph_state_to_evidence_status`` — and it never claims exploitation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from blackforge.attack_graph.models import (
    GraphState,
    graph_state_to_evidence_status,
)
from blackforge.core.logging import get_logger
from blackforge.memory.base import MemoryRecord, MemoryType
from blackforge.memory.provenance import MemoryProvenance, MemorySource

if TYPE_CHECKING:
    from blackforge.attack_graph.graph import AttackGraph
    from blackforge.core.types import MissionID, SessionID
    from blackforge.memory.manager import MemoryManager

log = get_logger("attack_graph.materializer")


@dataclass(frozen=True)
class MaterializeEntry:
    """What to pull out of the graph for a single memory record."""

    node_entity_ids: tuple[str, ...]
    include_evidence: bool = False


@dataclass(frozen=True)
class MaterializeReport:
    """Deterministic outcome of one materialization call."""

    wrote: int = 0
    skipped: int = 0
    memory_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class AttackGraphMemoryMaterializer:
    """Writes derived-graph knowledge into memory, never upward."""

    def __init__(self, memory: MemoryManager | None = None) -> None:
        self.memory = memory

    def materialize(
        self,
        graph: AttackGraph,
        entry: MaterializeEntry,
        mission_id: MissionID,
        session_id: SessionID | None = None,
    ) -> MaterializeReport:
        if self.memory is None:
            return MaterializeReport(skipped=1, warnings=["no memory manager bound"])

        nodes = [graph.node_for_entity(eid) for eid in entry.node_entity_ids]
        present = [n for n in nodes if n is not None]
        if not present:
            return MaterializeReport(
                skipped=1, warnings=["no matching nodes in the derived graph"]
            )

        descriptors = []
        source_summary = []
        for node in present:
            descriptors.append(
                {
                    "entity_id": str(node.entity_id),
                    "entity_type": node.entity_type,
                    "name": node.name,
                    "state": node.state.value,
                    "confidence": node.confidence.value,
                }
            )
            source_summary.append(node.state)

        aggregate_state = _aggregate_state(present)
        content = {
            "graph_id": graph.graph_id,
            "mission_id": str(mission_id),
            "summary": f"derived attack-graph view of {len(present)} canonical entities",
            "nodes": descriptors,
            "derived_edges": _derived_edge_summary(graph, present, entry.include_evidence),
            "epistemic": {
                "aggregate_state": aggregate_state.value,
                "note": "derived relational view; not an exploitability claim",
            },
        }

        source = (
            MemorySource.LLM_INFERENCE
            if _is_hypothetical(present)
            else MemorySource.CAPABILITY_EXECUTION
        )
        status = graph_state_to_evidence_status(aggregate_state)
        record = MemoryRecord(
            memory_type=MemoryType.KNOWLEDGE,
            key=f"attack_graph:{graph.graph_id}",
            content=content,
            status=status,
            confidence=_aggregate_confidence(present),
            mission_id=mission_id,
            session_id=session_id,
            source=source,
            provenance=MemoryProvenance(
                source=source,
                source_detail="attack-graph-materializer-v1",
                evidence_ids=_evidence_ids(present),
            ),
            dedup_key=_dedup_key(graph.graph_id, present),
            tags=["attack_graph", graph.graph_id],
            metadata={
                "graph_id": graph.graph_id,
                "derivation_rules": sorted({d.rule_id for d in [n.derivation for n in present]}),
            },
        )
        memory_id = self.memory.store(record)

        log.info(
            "attack_graph_materialized",
            graph_id=graph.graph_id,
            record_id=memory_id,
            nodes=len(present),
            status=status.value,
        )
        return MaterializeReport(wrote=1, memory_ids=[memory_id])

    def health_check(self) -> bool:
        return True


def _aggregate_state(nodes) -> GraphState:
    """Deterministic: the strongest honest state among *derived* nodes."""
    for node in nodes:
        if node.state == GraphState.CONTRADICTED:
            return GraphState.CONTRADICTED
    for node in nodes:
        if node.state == GraphState.BLOCKED:
            return GraphState.BLOCKED
    for node in nodes:
        if node.state == GraphState.HYPOTHESIZED:
            return GraphState.HYPOTHESIZED
    for node in nodes:
        if node.state == GraphState.INFERRED:
            return GraphState.INFERRED
    return GraphState.OBSERVED


def _is_hypothetical(nodes) -> bool:
    return any(n.state == GraphState.HYPOTHESIZED for n in nodes)


def _aggregate_confidence(nodes) -> float:
    scores = [n.confidence.to_score() for n in nodes]
    return min(scores) if scores else 0.5


def _evidence_ids(nodes) -> list:
    collected: list[str] = []
    for node in nodes:
        for eid in node.supporting_evidence:
            stringified = str(eid)
            if stringified not in collected:
                collected.append(stringified)
    return collected


def _dedup_key(graph_id: str, nodes) -> str:
    digest = hashlib.sha256()
    for node in nodes:
        digest.update(str(node.id).encode())
    return f"attack_graph_knowledge:{graph_id}:{digest.hexdigest()[:16]}"


def _derived_edge_summary(graph: AttackGraph, nodes, include_evidence: bool) -> list[dict]:
    node_ids = {str(n.id) for n in nodes}
    summary: list[dict] = []
    for edge in graph.edges():
        if str(edge.source_node_id) not in node_ids:
            continue
        if not include_evidence and edge.derivation.rule_id is None:
            continue
        summary.append(
            {
                "relationship": edge.relationship.value,
                "state": edge.state.value,
                "source": str(edge.source_entity_id),
                "target": str(edge.target_entity_id),
                "rule_id": edge.derivation.rule_id,
            }
        )
    summary.sort(key=lambda item: (item["rule_id"], item["source"], item["target"]))
    return summary
