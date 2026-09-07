"""Bounded, deterministic, fail-closed autonomous assessment planner.

The planner never executes anything. It selects *registered* BLACKFORGE
capabilities that could produce evidence for the highest-priority derived
gaps, and only routes them through the existing Scope → Authorization →
Capability pipeline. ``NO_ACTION_AVAILABLE`` and ``INSUFFICIENT_SCOPE`` are
first-class outcomes.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from blackforge.attack_graph.actions import (
    EvidenceGap,
    candidate_actions,
    compute_gaps,
)
from blackforge.attack_graph.builder import (
    AttackGraphBuilder,
    AttackGraphBuildRequest,
)
from blackforge.attack_graph.graph import AttackGraph  # noqa: TC001  # pydantic field
from blackforge.attack_graph.models import (
    AssessmentPlan,
    PlanStatus,
    PlanStep,
)
from blackforge.attack_graph.query import AttackGraphQuery
from blackforge.attack_graph.scoring import assess
from blackforge.core.errors import PlanningError
from blackforge.core.logging import get_logger
from blackforge.core.types import (
    AssessmentPlanID,
    MissionID,
    RiskLevel,
    SessionID,
)
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields

if TYPE_CHECKING:
    from blackforge.attack_graph.models import AttackGraphNode, CandidateAction
    from blackforge.attack_graph.repository import AttackGraphRepository
    from blackforge.authorization import AuthorizationBoundary
    from blackforge.capabilities.models import CapabilityMeta
    from blackforge.capabilities.registry import CapabilityRegistry

log = get_logger("attack_graph.planner")

# Default per-capability assessment step duration in hours (deterministic).
_CAP_DURATION_HOURS = {
    "custom_greeting": 0.6,
    "backend_probe": 0.7,
    "http_probe": 0.9,
    "app_probe": 0.8,
    "app_listing": 0.75,
    "sql_injection_probe": 0.55,
    "nosql_injection_probe": 0.55,
    "ldap_injection_probe": 0.55,
    "xml_injection_probe": 0.55,
    "ssti_probe": 0.55,
    "ssrf_probe": 0.55,
    "path_traversal_probe": 0.55,
    "code_injection_probe": 0.55,
}
_DEFAULT_CAP_HOURS = 0.65
_SEED = 20260907


class AssessmentMetadata(BaseModel):
    """Epistemic provenance for a produced plan (advisory, truthable)."""

    generated_by: str = "blackforge-attack-planner-v1"
    input_graph_id: str
    input_ide_hours: float
    input_scope_allowed_targets: list[str] = Field(default_factory=list)
    llm_advisory_used: bool = False
    primary_plan_status: str = "plan_ready"
    max_replans_reached: bool = False


class PlanningRequest(BaseModel):
    """Everything the planner needs; mirrors the Phase-14 notebook inputs."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    mission_id: MissionID
    session_id: SessionID | None = None
    scope: TargetScope
    focus: str | None = None
    input_graph_id: str | None = None
    ide_budget_hours: float = Field(default=22.0, ge=0.0, le=48.0)
    max_steps: int = Field(default=10, ge=1, le=30)
    max_candidates: int = Field(default=5, ge=1, le=20)
    max_graph_depth: int = Field(default=3, ge=1, le=6)
    max_replans: int = Field(default=3, ge=0, le=10)
    llm_advisory: str | None = None
    graph: AttackGraph | None = None
    build_request: AttackGraphBuildRequest | None = None


class IdleBudgetTracker:
    """Tracks assessment hours spent vs the idle budget (saturation)."""

    def __init__(self, budget_hours: float, seed: int = _SEED) -> None:
        self.budget_hours = budget_hours
        self.spent_hours = 0.0
        self.rng = random.Random(_SEED)
        self.rng.seed(seed)

    def step_cost(self, capability_name: str) -> float:
        hours = _CAP_DURATION_HOURS.get(capability_name, _DEFAULT_CAP_HOURS)
        return max(0.0, min(1.5, hours + self.rng.uniform(-0.15, 0.15)))

    def spend(self, capability_name: str) -> float:
        cost = self.step_cost(capability_name)
        self.spent_hours += cost
        return cost

    @property
    def remaining(self) -> float:
        return max(0.0, self.budget_hours - self.spent_hours)

    @property
    def saturated(self) -> bool:
        return self.remaining <= 0.0


class AssessmentPlanner:
    """Deterministic planner with bounded budget, scope, and authorization."""

    def __init__(
        self,
        repository: AttackGraphRepository | None = None,
        builder: AttackGraphBuilder | None = None,
        registry: CapabilityRegistry | None = None,
        authorization: AuthorizationBoundary | None = None,
    ) -> None:
        self.repository = repository
        self.builder = builder
        self.registry = registry
        self.authorization = authorization
        self.replan_count: dict[str, int] = {}

    # ------------------------------------------------------------------ #
    # Planning
    # ------------------------------------------------------------------ #
    def plan(self, request: PlanningRequest) -> AssessmentPlan:
        return self._plan_internal(request, prior=None)

    def replan(
        self,
        request: PlanningRequest,
        prior: AssessmentPlan,
        newly_answered_kinds: list[str] | None = None,
    ) -> AssessmentPlan:
        if prior.status == PlanStatus.NO_ACTION_AVAILABLE:
            return prior
        done = self.replan_count.get(str(prior.id), 0)
        if done >= request.max_replans:
            raise PlanningError(f"replan limit reached for {prior.id}")
        self.replan_count[str(prior.id)] = done + 1
        plan = self._plan_internal(request, prior=prior)
        if newly_answered_kinds:
            plan.warnings.append(
                f"replan acknowledged answered evidence: {', '.join(newly_answered_kinds)}"
            )
        plan.note = f"replan {done + 1} of {request.max_replans} for {str(prior.id)}"
        return plan

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _plan_internal(
        self, request: PlanningRequest, prior: AssessmentPlan | None
    ) -> AssessmentPlan:
        registry = self.registry
        if registry is None:
            raise PlanningError("planner requires a capability registry")

        graph = self._resolve_graph(request)
        if graph is None:
            raise PlanningError(
                "no graph available for planning; supply graph, builder, or repository"
            )

        query = AttackGraphQuery(graph)
        warnings: list[str] = []

        focus_node = self._focus_node(graph, request.focus)
        if request.focus and focus_node is None:
            warnings.append(
                f"focus target {request.focus} is not in the world model; "
                "planning from drive target"
            )
        target_value = (
            self._target_value(focus_node)
            if focus_node
            else self._infer_target_value(graph)
        )
        target_label = focus_node.name if focus_node else "default-target"

        if not request.scope.is_target_allowed(target_value):
            warnings.append(
                f"target {target_value} is outside the authorized scope; no actions planned"
            )
            return self._empty_plan(
                request,
                graph,
                PlanStatus.INSUFFICIENT_SCOPE,
                warnings,
                "out-of-scope target; planner fails closed",
            )

        paths = self._paths(graph, query, request, focus_node)
        if not paths:
            warnings.append("no derived paths from the focus/drive target")
            status = (
                PlanStatus.NO_ACTION_AVAILABLE
                if graph.node_count == 0
                else PlanStatus.NO_GAPS
            )
            return self._empty_plan(
                request,
                graph,
                status,
                warnings,
                "no actionable derived gaps under current evidence",
            )

        gaps = compute_gaps(graph, paths)
        if not gaps:
            return self._empty_plan(
                request,
                graph,
                PlanStatus.NO_GAPS,
                warnings,
                "world model fully corroborated; no derived gaps to assess",
            )

        metas = registry.list_meta()
        ranked = self._rank_actions(
            gaps=gaps,
            metas=metas,
            paths=paths,
            target_value=target_value,
            target_label=target_label,
        )
        if prior is not None:
            ranked = self._drop_answered(ranked, prior)
        if len(ranked) > request.max_steps:
            ranked = ranked[: request.max_steps]
            warnings.append(f"candidate steps capped at {request.max_steps}")

        steps: list[PlanStep] = []
        capped_count = 0
        budget = IdleBudgetTracker(request.ide_budget_hours)
        saturated = False
        for order, (action, _gap) in enumerate(ranked, start=1):
            if saturated:
                capped_count += 1
                continue
            decision = self._authorize(
                request, action.capability_name, target_value, action.risk_level
            )
            if decision != "authorized":
                warnings.append(
                    f"{action.capability_name} not authorized ({decision}); excluded"
                )
                continue
            budget.spend(action.capability_name)
            action.rank = order
            steps.append(
                PlanStep(
                    step_id=f"{request.mission_id}-step-{order}",
                    order=order,
                    action=action,
                )
            )
            if budget.saturated:
                saturated = True
                capped_count += 1
                warnings.append("idle IDE budget saturated; downstream steps capped")

        status = self._plan_status(steps, capped_count, gaps, warnings)
        plan = AssessmentPlan(
            id=self._ids(),
            mission_id=request.mission_id,
            session_id=request.session_id,
            graph_id=graph.graph_id,
            status=status,
            steps=steps,
            unmet_prerequisites=sorted(
                {
                    p
                    for path in paths
                    for p in _path_prereqs(graph, path)
                }
            ),
            warnings=warnings,
            max_steps=request.max_steps,
            max_candidates=request.max_candidates,
            max_graph_depth=request.max_graph_depth,
            note="assessment plan (advisory; never executes anything)",
        )
        if self.repository is not None:
            self.repository.store_plan(plan)
        log.info(
            "assessment_plan_ready",
            mission_id=str(request.mission_id),
            plan_id=str(plan.id),
            status=plan.status.value,
            steps=len(plan.steps),
        )
        return plan

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _resolve_graph(self, request: PlanningRequest) -> AttackGraph | None:
        if request.graph is not None:
            return request.graph
        if self.builder is not None:
            build_request = request.build_request or AttackGraphBuildRequest(
                mission_id=request.mission_id,
                session_id=request.session_id,
            )
            result = self.builder.build(build_request)
            return result.graph
        if self.repository is not None:
            return self.repository.get_latest_graph(request.mission_id)
        return None

    def _focus_node(self, graph: AttackGraph, focus: str | None) -> AttackGraphNode | None:
        if not focus:
            return None
        node = graph.node_for_entity(focus)
        if node is not None:
            return node
        for candidate in graph.nodes():
            if str(candidate.entity_id) == focus or candidate.name == focus:
                return candidate
        return None

    def _paths(self, graph, query: AttackGraphQuery, request: PlanningRequest, focus_node):
        if focus_node is not None:
            paths = query.paths_for_start(
                str(focus_node.entity_id),
                max_depth=request.max_graph_depth,
                max_paths=request.max_candidates * 4,
            )
            if paths:
                return paths
            all_paths = query.open_paths(
                max_depth=request.max_graph_depth,
                max_paths=request.max_candidates * 4,
            )
            return [
                p
                for p in all_paths
                if str(p.start_entity_id) == str(focus_node.entity_id)
                or str(p.end_entity_id) == str(focus_node.entity_id)
            ]
        return query.open_paths(
            max_depth=request.max_graph_depth,
            max_paths=request.max_candidates * 4,
        )

    def _target_value(self, node: AttackGraphNode) -> str:
        for key in ("url", "address", "canonical_key"):
            value = node.properties.get(key)
            if value and isinstance(value, str):
                return value
        return node.name

    def _infer_target_value(self, graph: AttackGraph) -> str:
        surfaces = graph.exposure_surfaces()
        if surfaces:
            return self._target_value(surfaces[0])
        nodes = graph.nodes()
        if nodes:
            return self._target_value(nodes[0])
        return ""

    def _rank_actions(
        self,
        gaps: list[EvidenceGap],
        metas: list[CapabilityMeta],
        paths,
        target_value: str,
        target_label: str,
    ):
        actions = candidate_actions(
            gaps,
            metas,
            target_value=target_value,
            target_label=target_label,
        )
        path_by_id = {str(p.id): p for p in paths}
        scored: list[tuple[float, str, Any, EvidenceGap]] = []
        for action, gap in actions:
            path = path_by_id.get(gap.path_id)
            score = self._score_action(action, path)
            scored.append((score.value, str(action.capability_name), action, gap))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [(action, gap) for _, _, action, gap in scored]

    def _score_action(self, action: CandidateAction, path):
        if path is None or path.length == 0:
            return assess(
                path_depth=1,
                is_blocked=False,
                near_saturation=False,
                exposed_ratio=1.0,
                focus_matches=True,
                has_contradiction=False,
                corroboration=0,
                derived_confidence=0.5,
            )
        return assess(
            path_depth=path.length,
            is_blocked=False,
            near_saturation=False,
            exposed_ratio=1.0,
            focus_matches=True,
            has_contradiction=False,
            corroboration=len(path.supporting_evidence),
            derived_confidence=path.confidence.to_score(),
        )

    def _authorize(
        self,
        request: PlanningRequest,
        capability_name: str,
        target_value: str,
        risk_level: RiskLevel,
    ) -> str:
        if not request.scope.is_capability_allowed(capability_name):
            return "DENIED"
        if self.authorization is None:
            return "authorized"
        decision = self.authorization.authorize(
            request.mission_id,
            request.scope,
            capability_name,
            target_value,
            risk_level,
        )
        return decision.value

    def _drop_answered(
        self, ranked, prior: AssessmentPlan
    ):
        answered = {
            goal.evidence_type
            for step in prior.steps
            for goal in step.action.expected_evidence
        }
        return [
            (action, gap)
            for action, gap in ranked
            if not any(e.evidence_type in answered for e in action.expected_evidence)
        ]

    def _plan_status(self, steps, capped_count, gaps, warnings) -> PlanStatus:
        if steps:
            if capped_count:
                return PlanStatus.PLAN_CAPPED
            return PlanStatus.PLAN_READY
        if capped_count:
            return PlanStatus.PLAN_CAPPED
        if not gaps:
            return PlanStatus.NO_GAPS
        return PlanStatus.NO_ACTION_AVAILABLE

    def _empty_plan(
        self,
        request: PlanningRequest,
        graph: AttackGraph,
        status: PlanStatus,
        warnings: list[str],
        note: str,
    ) -> AssessmentPlan:
        plan = AssessmentPlan(
            id=self._ids(),
            mission_id=request.mission_id,
            session_id=request.session_id,
            graph_id=graph.graph_id,
            status=status,
            warnings=warnings,
            max_steps=request.max_steps,
            max_candidates=request.max_candidates,
            max_graph_depth=request.max_graph_depth,
            note=note,
        )
        if self.repository is not None:
            self.repository.store_plan(plan)
        return plan

    def _ids(self) -> AssessmentPlanID:
        return AssessmentPlanID()


def _path_prereqs(graph, path) -> list[str]:
    return [
        prereq.description
        for edge in (
            graph.get_edge(i) for i in path.edge_ids
        )
        if edge is not None
        for prereq in edge.prerequisites
    ]
