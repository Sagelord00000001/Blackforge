"""Deterministic mission orchestration engine for the Development Console.

The orchestrator is the only component allowed to *decide* whether a planner
proposal may be executed. Its loop never trusts the planner: every proposed
investigation passes, in order:

1. registration gate (capability exists and is routed),
2. authorization gate (``AuthorizationBoundary``),
3. scope gate (target + capability within the mission's ``TargetScope``),
4. adapter gate (mock vs real-controlled, conditioned on policy and profile),
5. typed request construction and bounded transport execution,
6. normalization into evidence, memory, world model and attack graph.

The loop terminates deterministically via max steps, max capability calls,
max runtime, max (non-productive) replans, repeated invalid planner
decisions, duplicate-action evictions, evidence saturation, explicit
cancellation, or a planner-requested stop.

Nothing here spawns a process, evaluates code, or runs a generic shell
command. ``os.system``, ``subprocess``, ``eval`` and ``exec`` are forbidden
by the phase security scan.
"""

from __future__ import annotations

import contextlib
import json
import time
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from blackforge.attack_graph.builder import AttackGraphBuildRequest
from blackforge.attack_graph.models import GraphRelationship
from blackforge.core.errors import MissionError
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    MissionStatus,
    ProvenanceType,
    RiskLevel,
    SessionID,
    TargetType,
)
from blackforge.evidence.models import Evidence, Provenance
from blackforge.memory.base import MemoryRecord, MemoryType
from blackforge.orchestration.models import (
    AdapterMode,
    AssessmentProfile,
    AssetSummary,
    CapabilityRouting,
    CapabilityView,
    DecisionKind,
    EvidenceViewRow,
    ExecutionPhase,
    GraphEdgeView,
    GraphSummary,
    InstructionRecord,
    InvestigationStatus,
    MissionPolicy,
    MissionRuntimeState,
    MissionSetup,
    PlannerContext,
    PlannerDecision,
    PlannerSource,
    ScopeClassification,
    StopReason,
)
from blackforge.orchestration.planner import (
    LLMPlanner,
    MockPlanner,
    PlannerBase,
    PlannerInvalidDecision,
    RuleBasedPlanner,
)
from blackforge.orchestration.routing import CapabilityRouter
from blackforge.world_model.materializer import EntityFact, WorldMaterializer
from blackforge.world_model.models import EntityType, EvidenceLinkRef
from blackforge.world_model.query import WorldQuery

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from blackforge.orchestration.adapters import (
        RealObservation,
        RealObservationAdapter,
    )

_DEFAULT_MAX_OBSERVATIONS = 200


class OrchestrationError(Exception):
    """Raised when a mission cannot enter its declared lifecycle state."""


class DispatchOutcome(BaseModel):
    """Result of one dispatched capability call."""

    success: bool = False
    evidence_ids: list[EvidenceID] = Field(default_factory=list)
    summary: str = ""
    error: str | None = None
    adapter_mode: AdapterMode = AdapterMode.MOCK_ONLY


class MissionOrchestrator:
    """Binds planner + router + engines + evidence/world/attack-graph layers.

    Instantiate with the bootstrapped app so the orchestrator reuses the
    existing mission manager, authorization boundary, capability registry,
    evidence store, world model and attack graph components — no parallel
    authorization system is introduced.
    """

    def __init__(
        self,
        app: Any,
        *,
        planner: PlannerBase | None = None,
        allow_real_controlled: bool = False,
        evidence_saturation_floor: int = 5,
    ) -> None:
        self.app = app
        from blackforge.orchestration.adapters import RealAdapterRegistry

        self._real_adapters = RealAdapterRegistry()
        self.router = CapabilityRouter(
            registry=app.capability_registry,
            engines={
                "recon_engine": app.recon_engine,
                "webapi_engine": app.webapi_engine,
                "auth_engine": app.auth_engine,
                "business_logic_engine": app.business_logic_engine,
                "network_engine": app.network_engine,
                "identity_engine": app.identity_engine,
                "cloud_engine": app.cloud_engine,
                "container_engine": app.container_engine,
                "source_runtime_engine": app.source_runtime_engine,
            },
            real_adapters=self._real_adapters,
        )
        self.evidence_saturation_floor = evidence_saturation_floor
        self.allow_real_controlled = bool(allow_real_controlled)
        self._materializer = WorldMaterializer(store=app.world_model)
        self._scopes: dict[MissionID, Any] = {}
        self._runtimes: dict[MissionID, MissionRuntimeState] = {}

        def _risk(capability: str) -> RiskLevel:
            meta = self.router.meta_of(capability)
            return meta.risk_level if meta is not None else RiskLevel.MEDIUM

        self._risk_lookup = _risk
        self.mock_planner = MockPlanner()
        self.rule_planner = RuleBasedPlanner(risk_lookup=_risk)
        self._planner = planner or self.rule_planner
        self._fallback_planner: PlannerBase | None = self.rule_planner

    # ------------------------------------------------------------------
    # Mission lifecycle
    # ------------------------------------------------------------------
    def create_mission(self, setup: MissionSetup) -> Any:
        """Create a mission bound to a validated seed target and scope."""
        seed = _validate_seed(setup.seed_target)
        scope = self._scope_for(setup, seed)
        mission = self.app.mission_manager.create(
            name=setup.name,
            description=setup.objective,
            scope_id=str(scope.mission_id),
            metadata={
                "objective": setup.objective,
                "seed_target": setup.seed_target,
                "profile": setup.profile.value,
                "policy": setup.policy.model_dump(mode="json"),
            },
        )
        self._scopes[str(mission.id)] = scope
        with contextlib.suppress(MissionError, ValueError):
            self.app.mission_manager.transition(mission.id, MissionStatus.READY)
        return mission

    def scope_for(self, mission_id: MissionID) -> Any:
        scope = self._scopes.get(mission_id)
        if scope is None:
            raise OrchestrationError(f"no scope registered for mission: {mission_id}")
        return scope

    def mission_record(self, mission_id: MissionID) -> Any:
        return self.app.mission_manager.get(mission_id)

    def list_missions(self) -> list[Any]:
        return self.app.mission_manager.list_missions()

    def runtime(self, mission_id: MissionID) -> MissionRuntimeState | None:
        return self._runtimes.get(mission_id)

    def cancel(self, mission_id: MissionID) -> MissionRuntimeState:
        state = self._require_runtime(mission_id)
        if state.phase not in (ExecutionPhase.COMPLETED, ExecutionPhase.CANCELLED):
            state.phase = ExecutionPhase.CANCELLED
            state.stop_reason = StopReason.CANCELLED
            state.finished_at = time.time()
            with contextlib.suppress(MissionError, ValueError):
                self.app.mission_manager.transition(mission_id, MissionStatus.CANCELLED)
        return state

    # ------------------------------------------------------------------
    # Execution loop
    # ------------------------------------------------------------------
    def run_mission(
        self,
        mission_id: MissionID,
        *,
        planner: PlannerBase | None = None,
        session_id: SessionID | None = None,
    ) -> MissionRuntimeState:
        """Run (or resume) a mission until a deterministic stop condition."""
        mission = self.app.mission_manager.get(mission_id)
        scope = self.scope_for(mission_id)
        if mission.status.value not in ("ready", "paused"):
            raise OrchestrationError(
                f"mission {mission_id} cannot run from status {mission.status.value}"
            )

        state = self._runtimes.get(mission_id)
        if state is None or state.phase in (
            ExecutionPhase.COMPLETED,
            ExecutionPhase.CANCELLED,
        ):
            state = MissionRuntimeState(
                mission_id=mission_id,
                steps_remaining=self._policy(mission).max_steps,
            )
        state.session_id = session_id or _synthetic_session_id()
        state.phase = ExecutionPhase.PLANNING
        state.started_at = state.started_at or time.time()
        state.redundant_steps = 0
        self._runtimes[mission_id] = state
        with contextlib.suppress(MissionError, ValueError):
            self.app.mission_manager.transition(mission_id, MissionStatus.RUNNING)

        active_planner = planner or self._planner
        policy = self._policy(mission)
        started = time.time()

        while True:
            if self._budget_broken(policy, state, started):
                break
            if state.phase is ExecutionPhase.CANCELLED:
                break

            ctx = self._planner_context(mission, scope, state, policy)
            decision = self._obtain_decision(active_planner, ctx, state, policy)
            state.last_decision = decision

            if decision.kind is DecisionKind.COMPLETE:
                state.stop_reason = state.stop_reason or StopReason.NO_ACTIONS_REMAIN
                break

            if not self._decision_in_routing(ctx, decision):
                state.invalid_plans += 1
                if state.invalid_plans >= policy.invalid_plan_limit:
                    state.stop_reason = StopReason.REPEATED_INVALID_PLANNER
                    break
                state.replans += 1
                if state.replans >= policy.max_replans:
                    state.stop_reason = StopReason.MAX_REPLANS
                    break
                continue

            if (
                self._is_duplicate(mission_id, decision)
                and decision.kind is not DecisionKind.REVALIDATE
            ):
                state.duplicate_evictions += 1
                if state.duplicate_evictions >= policy.max_duplicate_evictions:
                    state.stop_reason = StopReason.DUPLICATE_EVICTION
                    break
                state.replans += 1
                if state.replans >= policy.max_replans:
                    state.stop_reason = StopReason.MAX_REPLANS
                    break
                continue

            instruction = self._approve(mission_id, decision)
            state.replans = 0
            outcome = self._dispatch(mission_id, scope, instruction, state)
            state.steps_completed += 1
            state.steps_remaining = max(0, policy.max_steps - state.steps_completed)
            if outcome.success:
                instruction.status = InvestigationStatus.COMPLETED
                instruction.evidence_ids = list(outcome.evidence_ids)
                self._post_process(mission_id, state, instruction, outcome)
            else:
                instruction.status = InvestigationStatus.FAILED
                instruction.note = outcome.error

        return self._finalize(mission, state)

    def _obtain_decision(
        self,
        planner: PlannerBase,
        ctx: PlannerContext,
        state: MissionRuntimeState,
        policy: MissionPolicy,
    ) -> PlannerDecision:
        """Ask the chosen planner; fail over deterministically on failure."""
        try:
            return planner.plan(ctx)
        except PlannerInvalidDecision as exc:
            state.invalid_plans += 1
            if state.invalid_plans >= policy.invalid_plan_limit:
                state.stop_reason = StopReason.REPEATED_INVALID_PLANNER
                return _closed_decision(f"planner failed closed repeatedly: {exc}")
            fallback = self._fallback_planner
            if fallback is None or fallback is planner:
                return _closed_decision(f"planner failed closed: {exc}")
            try:
                return fallback.plan(ctx)
            except PlannerInvalidDecision as exc2:
                return _closed_decision(f"fallback planner failed closed: {exc2}")
        except Exception as exc:  # noqa: BLE001 - planner infrastructure failures
            state.invalid_plans += 1
            if state.invalid_plans >= policy.invalid_plan_limit:
                state.stop_reason = StopReason.REPEATED_INVALID_PLANNER
            return _closed_decision(f"planner infrastructure failure: {type(exc).__name__}")

    # ------------------------------------------------------------------
    # Gates (before any transport)
    # ------------------------------------------------------------------
    def _decision_in_routing(self, ctx: PlannerContext, decision: PlannerDecision) -> bool:
        return decision.capability in set(ctx.routing.authorized) | set(
            ctx.routing.applicable
        )

    def _dispatch(
        self,
        mission_id: MissionID,
        scope: Any,
        instruction: InstructionRecord,
        state: MissionRuntimeState,
    ) -> DispatchOutcome:
        capability = instruction.capability
        target = instruction.target
        meta = self.router.meta_of(capability)
        if meta is None:
            instruction.status = InvestigationStatus.BLOCKED
            instruction.note = "unknown capability"
            return DispatchOutcome(success=False, error="unknown capability")

        # Gate 1: authorization (before any transport)
        decision = self.app.authorization.authorize(
            mission_id=mission_id,
            scope=scope,
            capability_name=capability,
            target_value=target,
            risk_level=meta.risk_level,
        )
        if decision.value not in ("authorized", "requires_approval"):
            instruction.status = InvestigationStatus.BLOCKED
            instruction.note = f"authorization denied ({decision.value})"
            return DispatchOutcome(success=False, error=f"authorization {decision.value}")

        # Gate 2: scope (before any transport)
        if not scope.is_target_allowed(target) or not scope.is_capability_allowed(
            capability
        ):
            instruction.status = InvestigationStatus.BLOCKED
            instruction.note = "scope enforcement failed"
            return DispatchOutcome(success=False, error="out of scope")

        # Gate 3: adapter selection (mock vs real-controlled)
        real_adapter = self.router.adapter_for(capability)
        if real_adapter is not None:
            mission = self.app.mission_manager.get(mission_id)
            profile = self._profile(mission)
            policy = self._policy(mission)
            real_enabled = policy.allow_real_controlled and self.allow_real_controlled
            real_forbidden_profile = profile is AssessmentProfile.CONTROLLED_DEMONSTRATION
            if real_enabled and not real_forbidden_profile:
                return self._run_real(mission_id, scope, state, instruction, real_adapter, target)
            engine = self.router.engine_for(capability)
            if engine is None:
                instruction.status = InvestigationStatus.BLOCKED
                instruction.note = "real-controlled adapter not enabled for mission"
                return DispatchOutcome(success=False, error="real adapter disabled")

        return self._run_mock(mission_id, scope, state, instruction, capability, target)

    def _run_mock(
        self,
        mission_id: MissionID,
        scope: Any,
        state: MissionRuntimeState,
        instruction: InstructionRecord,
        capability: str,
        target: str,
    ) -> DispatchOutcome:
        engine = self.router.engine_for(capability)
        if engine is None:
            instruction.status = InvestigationStatus.BLOCKED
            instruction.note = "no engine binding"
            return DispatchOutcome(success=False, error="no engine binding")
        try:
            request = self.router.build_request(
                capability,
                mission_id=mission_id,
                scope=scope,
                session_id=state.session_id,
                max_observations=_DEFAULT_MAX_OBSERVATIONS,
            )
        except KeyError as exc:
            instruction.status = InvestigationStatus.BLOCKED
            instruction.note = str(exc)
            return DispatchOutcome(success=False, error=str(exc))
        except Exception as exc:  # noqa: BLE001
            instruction.status = InvestigationStatus.BLOCKED
            instruction.note = f"request construction failed: {exc}"
            return DispatchOutcome(success=False, error=str(exc))

        state.capability_calls += 1
        try:
            result = engine.run(capability_id=capability, request=request, target=target)
        except Exception as exc:  # noqa: BLE001 - failure-aware result handling
            instruction.note = f"execution error: {type(exc).__name__}: {exc}"
            return DispatchOutcome(success=False, error=str(exc))
        if getattr(result, "authorized", True) is False:
            instruction.status = InvestigationStatus.BLOCKED
            instruction.note = "engine refused (authorization)"
            return DispatchOutcome(success=False, error="engine unauthorized")
        evidence_ids = list(getattr(result, "evidence_ids", []) or [])
        error = getattr(result, "error", None)
        outcome = DispatchOutcome(
            success=bool(evidence_ids),
            evidence_ids=evidence_ids,
            summary=_outcome_summary(capability, target, evidence_ids),
            error=str(error) if error else None,
            adapter_mode=AdapterMode.MOCK_ONLY,
        )
        instruction.note = outcome.summary
        return outcome

    def _run_real(
        self,
        mission_id: MissionID,
        scope: Any,
        state: MissionRuntimeState,
        instruction: InstructionRecord,
        adapter: RealObservationAdapter,
        target: str,
    ) -> DispatchOutcome:
        state.capability_calls += 1
        try:
            observation = adapter.observe(target)
        except Exception as exc:  # noqa: BLE001 - adapters fail closed
            instruction.note = f"real observation error: {type(exc).__name__}"
            return DispatchOutcome(success=False, error=str(exc))
        evidence_id = self._record_real_evidence(
            mission_id, state, instruction, observation
        )
        outcome = DispatchOutcome(
            success=observation.success,
            evidence_ids=[evidence_id] if evidence_id else [],
            summary=observation.summary,
            error=observation.error,
            adapter_mode=AdapterMode.REAL_CONTROLLED,
        )
        instruction.note = outcome.summary
        return outcome

    def _record_real_evidence(
        self,
        mission_id: MissionID,
        state: MissionRuntimeState,
        instruction: InstructionRecord,
        observation: RealObservation,
    ) -> EvidenceID | None:
        evidence = Evidence(
            mission_id=mission_id,
            session_id=state.session_id,
            source_capability=instruction.capability,
            target=observation.target,
            evidence_type=EvidenceType.OBSERVATION,
            status=EvidenceStatus.OBSERVED if observation.success else EvidenceStatus.HYPOTHESIZED,
            confidence=Confidence.MEDIUM if observation.success else Confidence.LOW,
            summary=observation.summary,
            raw_data=json.dumps(
                {"observed": observation.observed, "redacted": observation.redacted},
                sort_keys=True,
            ),
            provenance=Provenance(
                capability_id=instruction.capability,
                provenance_type=ProvenanceType.DIRECT,
            ),
        )
        try:
            stored = self.app.evidence_store.add(evidence)
            return EvidenceID(stored.id)
        except Exception:  # noqa: BLE001 - failure-aware handling
            return None

    # ------------------------------------------------------------------
    # Planner context construction (structured, redaction-safe)
    # ------------------------------------------------------------------
    def _planner_context(
        self,
        mission: Any,
        scope: Any,
        state: MissionRuntimeState,
        policy: MissionPolicy,
    ) -> PlannerContext:
        return PlannerContext(
            mission_id=mission.id,
            objective=str(mission.metadata.get("objective", mission.description or "")),
            seed_target=str(mission.metadata.get("seed_target", "")),
            scope=scope,
            policy=policy,
            routing=self._routing(mission, scope),
            world_entities=self._asset_summaries(mission.id, scope),
            recent_evidence=self._evidence_rows(mission.id),
            graph=self._graph_summary(mission.id, state.session_id),
            previous_actions=[
                f"{record.capability}@{record.target}"
                for record in state.instructions
                if record.status is InvestigationStatus.COMPLETED
            ],
            steps_used=state.steps_completed,
            steps_limit=policy.max_steps,
            capability_calls_used=state.capability_calls,
            capability_calls_limit=policy.max_capability_calls,
            runtime_seconds_remaining=self._seconds_remaining(state, policy),
            valid_llm=isinstance(self._planner, LLMPlanner),
        )

    def _routing(self, mission: Any, scope: Any) -> CapabilityRouting:
        target_type = _seed_target_type(str(mission.metadata.get("seed_target", "")))
        applicable = self.router.applicable(target_type)
        authorized: list[str] = []
        for capability in applicable:
            meta = self.router.meta_of(capability)
            if meta is None:
                continue
            decision = self.app.authorization.authorize(
                mission_id=mission.id,
                scope=scope,
                capability_name=capability,
                target_value=str(mission.metadata.get("seed_target", "")),
                risk_level=meta.risk_level,
            )
            if decision.value == "authorized":
                authorized.append(capability)
        real = set(self.router.real_controlled())
        return CapabilityRouting(
            applicable=applicable,
            authorized=authorized,
            real_controlled=[cap for cap in authorized if cap in real],
        )

    def _asset_summaries(self, mission_id: MissionID, scope: Any) -> list[AssetSummary]:
        try:
            entities = self.app.world_model.list_entities(
                WorldQuery(mission_id=mission_id, limit=200)
            )
        except Exception:  # noqa: BLE001 - the view must never break the loop
            return []
        summaries: list[AssetSummary] = []
        for entity in entities:
            classification = _classify_target(entity.name, scope)
            summaries.append(
                AssetSummary(
                    entity_id=entity.id,
                    entity_type=entity.entity_type.value,
                    name=entity.name,
                    namespace=entity.namespace,
                    classification=classification,
                    authorized=scope.is_target_allowed(entity.name),
                    confidence=str(getattr(entity, "confidence", "")) or None,
                    evidence_ids=list(getattr(entity, "evidence", []) or []),
                )
            )
        return summaries

    def _evidence_rows(self, mission_id: MissionID) -> list[EvidenceViewRow]:
        try:
            evidence = self.app.evidence_store.get_by_mission(mission_id)
        except Exception:  # noqa: BLE001
            return []
        rows: list[EvidenceViewRow] = []
        for item in evidence:
            rows.append(
                EvidenceViewRow(
                    evidence_id=str(item.id),
                    evidence_type=item.evidence_type.value,
                    status=item.status.value,
                    confidence=item.confidence.value,
                    source_capability=item.source_capability,
                    target=item.target,
                    timestamp=item.timestamp,
                    summary=_safe_summary(item),
                    redacted=_needs_redaction_flag(item),
                )
            )
        return rows

    def _graph_summary(
        self, mission_id: MissionID, session_id: SessionID | None
    ) -> GraphSummary:
        latest = self.app.attack_graph_repository.get_latest_graph(mission_id)
        edges: list[GraphEdgeView] = []
        gaps: list[str] = []
        node_count = edge_count = open_count = uncertain_count = 0
        if latest is not None:
            node_count = latest.node_count
            edge_count = latest.edge_count
            edges_list = latest.edges() if callable(latest.edges) else list(latest.edges)
            for edge in edges_list:
                if isinstance(edge, dict):  # pragma: no cover - defensive
                    continue
                state = getattr(edge, "state", "open")
                state_name = state.value if hasattr(state, "value") else str(state or "open")
                relationship = getattr(edge, "relationship", None) or GraphRelationship.DEPENDS_ON
                edges.append(
                    GraphEdgeView(
                    source=str(
                        getattr(
                            edge,
                            "source_entity_id",
                            getattr(edge, "source_node_id", "?"),
                        )
                    ),
                    target=str(
                        getattr(
                            edge,
                            "target_entity_id",
                            getattr(edge, "target_node_id", "?"),
                        )
                    ),
                        relationship=(
                            relationship
                            if isinstance(relationship, GraphRelationship)
                            else GraphRelationship.DEPENDS_ON
                        ),
                        state=state_name,
                        confidence=str(getattr(edge, "confidence", "") or ""),
                        certainty=_certainty(getattr(edge, "confidence", None)),
                        evidence_ids=list(getattr(edge, "supporting_evidence", []) or []),
                    )
                )
                if state_name in ("open", "hypothesized", "inferred"):
                    open_count += 1
                    gaps.append(
                        f"{getattr(edge, 'source_entity_id', '?')} -> "
                        f"{getattr(edge, 'target_entity_id', '?')} "
                        f"{_relationship_label(relationship)}"
                    )
                if _certainty(getattr(edge, "confidence", None)) < 1.0:
                    uncertain_count += 1
        return GraphSummary(
            node_count=node_count,
            edge_count=edge_count,
            open_path_count=open_count,
            uncertain_path_count=uncertain_count,
            gaps=gaps[:5],
            edges=edges[:30],
        )

    # ------------------------------------------------------------------
    # Post-processing: evidence -> memory -> world model -> attack graph
    # ------------------------------------------------------------------
    def _post_process(
        self,
        mission_id: MissionID,
        state: MissionRuntimeState,
        instruction: InstructionRecord,
        outcome: DispatchOutcome,
    ) -> None:
        before = self._evidence_count(mission_id)
        evidence_ids: list[EvidenceID] = []
        for evidence_id in outcome.evidence_ids:
            evidence = self.app.evidence_store.get(evidence_id)
            if evidence is None or evidence.mission_id != mission_id:
                continue
            evidence_ids.append(EvidenceID(str(evidence.id)))
            self._materialize_from_evidence(mission_id, evidence, state, instruction)

        memory_record = MemoryRecord(
            memory_type=MemoryType.EXPERIENCE,
            key=f"{instruction.capability}@{instruction.target}",
            content={
                "capability": instruction.capability,
                "target": instruction.target,
                "source": instruction.source.value,
                "status": instruction.status.value,
                "evidence_ids": [str(e) for e in evidence_ids],
                "summary": outcome.summary,
            },
            mission_id=mission_id,
            session_id=state.session_id,
            evidence_ids=evidence_ids,
            dedup_key=f"{mission_id}:{instruction.capability}:{instruction.target}",
        )
        with contextlib.suppress(Exception):  # noqa: BLE001 - memory is best-effort
            self.app.memory.store(memory_record)

        self._rebuild_graph(mission_id, state)
        after = self._evidence_count(mission_id)
        if after <= before:
            state.redundant_steps += 1
            if state.redundant_steps >= self.evidence_saturation_floor:
                state.stop_reason = StopReason.EVIDENCE_SATURATION
        else:
            state.redundant_steps = 0

    def _materialize_from_evidence(
        self,
        mission_id: MissionID,
        evidence: Any,
        state: MissionRuntimeState,
        instruction: InstructionRecord,
    ) -> None:
        fact = EntityFact(
            entity_type=_entity_type_for(instruction.capability),
            name=evidence.target,
            namespace=_namespace_for(instruction.capability),
            properties={
                "observed_by": instruction.capability,
                "evidence_id": str(evidence.id),
            },
            confidence=evidence.confidence,
            evidence=[EvidenceLinkRef(evidence_id=evidence.id)],
        )
        with contextlib.suppress(Exception):  # noqa: BLE001 - entity is advisory
            self._materializer.materialize_entity(
                mission_id,
                fact=fact,
                evidence_statuses=[evidence.status],
                session_id=state.session_id,
            )

    def _rebuild_graph(self, mission_id: MissionID, state: MissionRuntimeState) -> None:
        try:
            result = self.app.attack_graph_builder.build(
                AttackGraphBuildRequest(mission_id=mission_id, session_id=state.session_id)
            )
            self.app.attack_graph_repository.save_graph(result.graph)
            state.phase = ExecutionPhase.REPLANNING
        except Exception:  # noqa: BLE001 - graph rebuild cannot stop the loop
            pass

    def _evidence_count(self, mission_id: MissionID) -> int:
        try:
            return self.app.evidence_store.count(mission_id)
        except Exception:  # noqa: BLE001
            return 0

    # ------------------------------------------------------------------
    # Stop-condition evaluation (deterministic)
    # ------------------------------------------------------------------
    def _budget_broken(
        self, policy: MissionPolicy, state: MissionRuntimeState, started: float
    ) -> bool:
        if state.phase is ExecutionPhase.CANCELLED:
            return True
        if state.stop_reason in (
            StopReason.MAX_STEPS,
            StopReason.MAX_CAPABILITY_CALLS,
            StopReason.MAX_RUNTIME,
            StopReason.MAX_REPLANS,
            StopReason.REPEATED_INVALID_PLANNER,
            StopReason.DUPLICATE_EVICTION,
            StopReason.EVIDENCE_SATURATION,
        ):
            return True
        if state.steps_completed >= policy.max_steps:
            state.stop_reason = StopReason.MAX_STEPS
            return True
        if state.capability_calls >= policy.max_capability_calls:
            state.stop_reason = StopReason.MAX_CAPABILITY_CALLS
            return True
        if time.time() - started >= policy.max_runtime_seconds:
            state.stop_reason = StopReason.MAX_RUNTIME
            return True
        if state.replans >= policy.max_replans:
            state.stop_reason = StopReason.MAX_REPLANS
            return True
        return False

    def _seconds_remaining(self, state: MissionRuntimeState, policy: MissionPolicy) -> float:
        if not state.started_at:
            return policy.max_runtime_seconds
        return max(0.0, policy.max_runtime_seconds - (time.time() - state.started_at))

    # ------------------------------------------------------------------
    # Instruction lifecycle helpers
    # ------------------------------------------------------------------
    def _is_duplicate(self, mission_id: MissionID, decision: PlannerDecision) -> bool:
        state = self._require_runtime(mission_id)
        record = state.active_instruction(decision.capability, decision.target)
        if record is None:
            return False
        return record.status in (InvestigationStatus.COMPLETED, InvestigationStatus.EXECUTING)

    def _approve(
        self, mission_id: MissionID, decision: PlannerDecision
    ) -> InstructionRecord:
        state = self._require_runtime(mission_id)
        record = InstructionRecord(
            mission_id=mission_id,
            capability=decision.capability,
            target=decision.target,
            reason=decision.reason,
            source=decision.source,
            priority=decision.priority,
            status=InvestigationStatus.APPROVED,
            approved_at=time.time(),
        )
        state.last_instruction = record
        state.instructions.append(record)
        return record

    def _finalize(self, mission: Any, state: MissionRuntimeState) -> MissionRuntimeState:
        state.phase = ExecutionPhase.COMPLETED
        state.finished_at = time.time()
        reason = state.stop_reason or StopReason.NO_ACTIONS_REMAIN
        state.stop_reason = reason
        if reason is StopReason.CANCELLED:
            target_status = MissionStatus.CANCELLED
        elif reason in (
            StopReason.MAX_STEPS,
            StopReason.MAX_CAPABILITY_CALLS,
            StopReason.MAX_RUNTIME,
            StopReason.MAX_REPLANS,
        ):
            target_status = MissionStatus.PAUSED
        else:
            target_status = MissionStatus.COMPLETED
        with contextlib.suppress(MissionError, ValueError):
            self.app.mission_manager.transition(mission.id, target_status)
        return state

    def _require_runtime(self, mission_id: MissionID) -> MissionRuntimeState:
        state = self._runtimes.get(mission_id)
        if state is None:
            state = MissionRuntimeState(
                mission_id=mission_id,
                steps_remaining=self.policy_for(mission_id).max_steps,
            )
            self._runtimes[mission_id] = state
        return state

    # ------------------------------------------------------------------
    # Console-facing read models
    # ------------------------------------------------------------------
    def capability_view(self, mission_id: MissionID) -> CapabilityView:
        mission = self.app.mission_manager.get(mission_id)
        scope = self.scope_for(mission_id)
        executed: dict[tuple[str, str], int] = {}
        state = self._runtimes.get(mission_id)
        if state is not None:
            for record in state.instructions:
                if record.status is InvestigationStatus.COMPLETED:
                    executed[(record.capability, record.target)] = (
                        executed.get((record.capability, record.target), 0) + 1
                    )
        return self.router.view(
            mission_id=mission_id,
            scope=scope,
            seed_target_type=_seed_target_type(
                str(mission.metadata.get("seed_target", ""))
            ),
            executed=executed,
        )

    def assets(self, mission_id: MissionID) -> list[AssetSummary]:
        return self._asset_summaries(mission_id, self.scope_for(mission_id))

    def evidence_rows(self, mission_id: MissionID) -> list[EvidenceViewRow]:
        return self._evidence_rows(mission_id)

    def graph_summary(self, mission_id: MissionID) -> GraphSummary:
        state = self._runtimes.get(mission_id)
        return self._graph_summary(mission_id, state.session_id if state else None)

    def planner_id(self) -> str:
        return self._planner.planner_id

    def policy_for(self, mission_id: MissionID) -> MissionPolicy:
        return self._policy(self.app.mission_manager.get(mission_id))

    # ------------------------------------------------------------------
    # Policy / profile / scope derivation
    # ------------------------------------------------------------------
    def _policy(self, mission: Any) -> MissionPolicy:
        view = (mission.metadata or {}).get("policy")
        if isinstance(view, dict):
            return MissionPolicy(**view)
        return MissionPolicy()

    def _profile(self, mission: Any) -> AssessmentProfile:
        value = (mission.metadata or {}).get(
            "profile", AssessmentProfile.AUTHORIZED_ASSESSMENT.value
        )
        return AssessmentProfile(value)

    def _scope_for(self, setup: MissionSetup, seed: str) -> Any:
        from blackforge.scope.models import ExecutionLimits, Target, TargetScope

        target_type = _seed_target_type(seed)
        if setup.profile is AssessmentProfile.CONTROLLED_DEMONSTRATION:
            risk = RiskLevel.LOW
            policy = setup.policy.model_copy(update={"allow_real_controlled": False})
        else:
            risk = RiskLevel.MEDIUM
            policy = setup.policy

        return TargetScope(
            mission_id=str(setup.mission_id),
            allowed_targets=[Target(value=seed, target_type=target_type)],
            allowed_capabilities=[],
            max_risk_level=risk,
            execution_limits=ExecutionLimits(timeout_seconds=int(policy.max_runtime_seconds)),
        )


# -----------------------------------------------------------------------
# Module-level deterministic helpers
# -----------------------------------------------------------------------

def _validate_seed(seed: str) -> str:
    seed = (seed or "").strip()
    if not seed:
        raise OrchestrationError("seed target must not be empty")
    if any(char in seed for char in " \t\n\r"):
        raise OrchestrationError("seed target must be a single host")
    lowered = seed.lower()
    _seed_target_type(lowered)
    return lowered


def _seed_target_type(seed: str) -> TargetType:
    candidate = (seed or "").strip().lower()
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return TargetType.URL
    if "." in candidate or ":" in candidate:
        return TargetType.DOMAIN
    return TargetType.DOMAIN


def _classify_target(target: str, scope: Any) -> ScopeClassification:
    if scope.is_target_allowed(target):
        return ScopeClassification.IN_SCOPE
    return ScopeClassification.CANDIDATE


def _entity_type_for(capability: str) -> EntityType:
    if capability.startswith("webapi."):
        return EntityType.APPLICATION
    if capability.startswith("recon."):
        return EntityType.ENDPOINT
    if capability.startswith("network."):
        return EntityType.NETWORK
    if capability.startswith("cloud."):
        return EntityType.CLOUD_RESOURCE
    return EntityType.ASSET


def _namespace_for(capability: str) -> str | None:
    return capability.split(".", 1)[0] if "." in capability else None


def _safe_summary(evidence: Any) -> str:
    value = getattr(evidence, "summary", "") or ""
    return str(value)[:240]


def _certainty(confidence: Any) -> float:
    """Map a ``Confidence`` enum (or numeric) to a 0..1 certainty scale."""
    if confidence is None:
        return 0.0
    if isinstance(confidence, (int, float)):
        return float(confidence)
    value = getattr(confidence, "value", None) or str(confidence).lower()
    return {
        "high": 1.0,
        "medium": 0.6,
        "low": 0.3,
        "unverified": 0.1,
    }.get(value, 0.0)


def _relationship_label(relationship: Any) -> str:
    """Render a relationship for gap surfacing without exploding on enums."""
    try:
        if hasattr(relationship, "value"):
            return f"({relationship.value})"
    except Exception:  # noqa: BLE001 - never let labeling break the loop
        pass
    return f"({relationship})"


def _needs_redaction_flag(evidence: Any) -> bool:
    raw = getattr(evidence, "raw_data", None)
    if not raw:
        return False
    return "REDACTED" in str(raw) or "redacted" in str(raw).lower()


def _outcome_summary(
    capability: str, target: str, evidence_ids: list[EvidenceID]
) -> str:
    return f"{capability} on {target}: {len(evidence_ids)} evidence record(s)"


def _closed_decision(reason: str) -> PlannerDecision:
    return PlannerDecision(
        kind=DecisionKind.COMPLETE,
        capability="",
        target="",
        reason=reason,
        source=PlannerSource.RULE,
    )


def _synthetic_session_id() -> SessionID:
    return SessionID(f"mission_run_{int(time.time() * 1000)}")


__all__ = [
    "DispatchOutcome",
    "MissionOrchestrator",
    "OrchestrationError",
]
