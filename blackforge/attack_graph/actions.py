"""Evidence-gap reasoning and candidate capability mapping (pure, bounded).

``compute_gaps`` and ``candidate_actions`` never execute capabilities. They
only produce candidate actions for a downstream planner to rank and submit
through the normal BLACKFORGE authorization boundary.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from blackforge.attack_graph.models import CandidateAction, ExpectedEvidence
from blackforge.core.types import RiskLevel

if TYPE_CHECKING:
    from blackforge.attack_graph.graph import AttackGraph
    from blackforge.attack_graph.models import AttackGraphEdge, GraphPath
    from blackforge.capabilities.models import CapabilityMeta

# Coverage-oriented evidence capabilities that are always considered.
_COVERAGE_CAPABILITIES = frozenset(
    {"custom_greeting", "backend_probe", "http_probe", "app_probe"}
)


class EvidenceGap(BaseModel):
    """An unanswered question about a derived relationship or path."""

    path_id: str
    edge_id: str
    predicate: str
    description: str
    evidence_kind: str = "validation_result"
    prerequisite_descriptions: list[str] = Field(default_factory=list)


def compute_gaps(graph: AttackGraph, paths: list[GraphPath]) -> list[EvidenceGap]:
    """Compute evidence gaps across the derived edges of candidate paths.

    Every graph edge is a derived read over world-model relationships, so
    every edge is an evidence gap until an assessment step validates it.
    """
    gaps: list[EvidenceGap] = []
    for path in paths:
        for edge in _path_edges(graph, path):
            gaps.append(
                EvidenceGap(
                    path_id=str(path.id),
                    edge_id=str(edge.id),
                    predicate=str(edge.relationship.value),
                    description=f"evidence needed for {edge.relationship.value} validation",
                    evidence_kind=expected_evidence_kind(edge),
                    prerequisite_descriptions=[p.description for p in edge.prerequisites],
                )
            )
    return gaps


def expected_evidence_kind(edge: AttackGraphEdge) -> str:
    prereqs = [p.description for p in edge.prerequisites]
    joined = " ".join(prereqs).lower()
    if "declared-vs-runtime" in joined:
        return "differs_from"
    if "authentication" in joined:
        return "auth_missing_or_weak"
    if "exposure" in joined:
        return "exposure_unconfirmed"
    return "validation_result"


def _path_edges(graph: AttackGraph, path: GraphPath) -> list[AttackGraphEdge]:
    return [
        edge
        for edge in (graph.get_edge(i) for i in path.edge_ids)
        if edge is not None
    ]


def candidate_actions(
    gaps: list[EvidenceGap],
    metas: list[CapabilityMeta],
    target_value: str,
    target_label: str,
    risk_level: RiskLevel = RiskLevel.LOW,
) -> list[tuple[CandidateAction, EvidenceGap]]:
    """Deterministically map gaps to registered capabilities.

    The planner needs the gap behind each action, so every candidate is
    returned alongside the gap it would answer.
    """
    by_name = {meta.name: meta for meta in metas}
    selected: dict[str, tuple[CandidateAction, EvidenceGap]] = {}
    for gap in gaps:
        for cap_name in _capabilities_for_gap(gap, metas):
            meta = by_name[cap_name]
            if cap_name not in selected:
                selected[cap_name] = (
                    _candidate(meta, gap, target_value, target_label, risk_level),
                    gap,
                )
    for cap_name in sorted(_COVERAGE_CAPABILITIES & set(by_name)):
        if cap_name in selected:
            continue
        meta = by_name[cap_name]
        selected[cap_name] = (
            _coverage_candidate(meta, target_value, target_label, risk_level),
            EvidenceGap(
                path_id="coverage",
                edge_id="coverage",
                predicate="coverage",
                description="broad validation sweep",
                evidence_kind="validation_result",
            ),
        )
    return [selected[key] for key in sorted(selected)]


def _candidate(
    meta: CapabilityMeta,
    gap: EvidenceGap,
    target_value: str,
    target_label: str,
    risk_level: RiskLevel,
) -> CandidateAction:
    return CandidateAction(
        capability_name=meta.name,
        target=target_value,
        gap=gap.description,
        risk_level=risk_level,
        expected_evidence=[
            ExpectedEvidence(
                evidence_type=gap.evidence_kind,
                description=gap.description,
                target=target_value,
            )
        ],
        rationale=[
            f"gather evidence for {gap.predicate} ({gap.description})",
            f"target {target_label}",
        ],
    )


def _coverage_candidate(
    meta: CapabilityMeta,
    target_value: str,
    target_label: str,
    risk_level: RiskLevel,
) -> CandidateAction:
    return CandidateAction(
        capability_name=meta.name,
        target=target_value,
        gap="coverage evidence collection",
        risk_level=risk_level,
        expected_evidence=[
            ExpectedEvidence(
                evidence_type="validation_result",
                description="broad validation sweep",
                target=target_value,
            )
        ],
        rationale=[f"coverage-oriented evidence collection on {target_label}"],
    )


def _capabilities_for_gap(gap: EvidenceGap, metas: list[CapabilityMeta]) -> list[str]:
    names = {
        meta.name
        for meta in metas
        if gap.evidence_kind in meta.evidence_types_produced
    }
    names |= {meta.name for meta in metas if meta.name in _COVERAGE_CAPABILITIES}
    return sorted(names)


def saturation_reached(budget_remaining: int) -> bool:
    return budget_remaining <= 0
