from __future__ import annotations

import json
from typing import Any

import pytest

from blackforge.attack_graph.models import GraphRelationship
from blackforge.core.errors import CapabilityError
from blackforge.core.types import RiskLevel
from blackforge.intelligence.llm.base import LLMResponse
from blackforge.orchestration import (
    AssessmentProfile,
    CapabilityRouter,
    DecisionKind,
    LLMPlanner,
    MissionOrchestrator,
    MissionPolicy,
    MissionSetup,
    MockPlanner,
    PlannerBase,
    PlannerDecision,
    PlannerInvalidDecision,
    PlannerSource,
    Priority,
    RuleBasedPlanner,
    StopReason,
)
from blackforge.orchestration.adapters import (
    RealAdapterRegistry,
    RealObservation,
    RealObservationAdapter,
)
from blackforge.orchestration.models import (
    AdapterMode,
    CapabilityRouting,
    CapabilityView,
    ExecutionPhase,
    GraphSummary,
    InvestigationStatus,
    MissionRuntimeState,
    PlannerContext,
)
from blackforge.scope.models import TargetScope

MID = "mission_p141"
SEED = "getaelionix.com"


def _policy(**overrides: Any) -> MissionPolicy:
    values: dict[str, Any] = {
        "max_steps": 4,
        "max_capability_calls": 16,
        "max_runtime_seconds": 120,
        "max_replans": 2,
        "invalid_plan_limit": 2,
        "max_duplicate_evictions": 2,
        "allow_real_controlled": False,
    }
    values.update(overrides)
    return MissionPolicy(**values)


def _scope(seed: str = SEED) -> TargetScope:
    return TargetScope(mission_id=MID, seed_targets={seed})


def _routing(authorized: list[str] | None = None) -> CapabilityRouting:
    return CapabilityRouting(
        registered=list(authorized or []),
        applicable=list(authorized or []),
        authorized=list(authorized or []),
    )


def _ctx(
    authorized: list[str] | None = None,
    seed: str = SEED,
    policy: MissionPolicy | None = None,
    **overrides: Any,
) -> PlannerContext:
    values: dict[str, Any] = {
        "mission_id": MID,
        "objective": "authorized read-only assessment",
        "seed_target": seed,
        "scope": _scope(seed),
        "policy": policy or _policy(),
        "routing": _routing(authorized),
        "graph": GraphSummary(),
    }
    values.update(overrides)
    return PlannerContext(**values)


class _StubObservationAdapter(RealObservationAdapter):
    """Deterministic, network-free stand-in for a real-controlled adapter."""

    capability_id = "recon.dns"
    description = "stub"

    def __init__(self, *, success: bool = True) -> None:
        self._success = success

    def observe(self, target: str) -> RealObservation:
        if not self._success:
            return RealObservation(
                capability_id=self.capability_id,
                target=target,
                success=False,
                error="simulated transport failure",
            )
        return RealObservation(
            capability_id=self.capability_id,
            target=target,
            success=True,
            summary="stub observation",
            observed={"nameserver": "192.0.2.53", "records": ["A 192.0.2.1"]},
            redacted={"records": "<redacted>"},
        )


class _ScriptedLLM:
    def __init__(self, decisions: list[dict[str, str]]) -> None:
        self.decisions = list(decisions)
        self.calls = 0

    def generate(self, request: Any) -> LLMResponse:
        self.calls += 1
        if not self.decisions:
            raise AssertionError("scripted LLM asked beyond its script")
        return LLMResponse(content=json.dumps(self.decisions.pop(0)))


# ---------------------------------------------------------------------- #
# Planner contracts
# ---------------------------------------------------------------------- #
class TestPlannerContracts:
    def test_mock_planner_always_completes(self) -> None:
        planner = MockPlanner()
        decision = planner.plan(_ctx())
        assert decision.kind is DecisionKind.COMPLETE
        assert decision.source is PlannerSource.MOCK

    def test_mock_planner_is_a_valid_planner_base(self) -> None:
        assert isinstance(MockPlanner(), PlannerBase)

    def test_rule_planner_prefers_low_risk_first(self) -> None:
        app = _app()
        router = _router_for(app)
        authorized = list(router.list_registered())[:8]
        planner = RuleBasedPlanner(
            risk_lookup=lambda capability: _meta(app, capability).risk_level
        )
        decision = planner.plan(_ctx(authorized=authorized))
        assert decision.kind is DecisionKind.INVESTIGATE
        assert decision.capability == "recon.dns"  # lowest-risk, first alphabetically

    def test_rule_planner_stops_when_nothing_remains(self) -> None:
        planner = RuleBasedPlanner()
        decision = planner.plan(_ctx(authorized=[], previous_actions=[f"recon.dns@{SEED}"]))
        assert decision.kind is DecisionKind.COMPLETE

    def test_rule_planner_deduplicates_previous_actions(self) -> None:
        app = _app()
        router = _router_for(app)
        authorized = list(router.list_registered())[:6]
        planner = RuleBasedPlanner(
            risk_lookup=lambda capability: _meta(app, capability).risk_level
        )
        decision = planner.plan(
            _ctx(authorized=authorized, policy=_policy(max_steps=6),
                 previous_actions=[f"{authorized[0]}@{SEED}"])
        )
        assert decision.capability in authorized
        assert decision.capability != authorized[0]
        # the planner refuses to refire an executed capability/target pair
        candidates = [c for c in authorized if c != authorized[0]]
        assert decision.capability in candidates

    def test_rule_planner_marks_open_graph_targets_high_priority(self) -> None:
        from blackforge.orchestration.models import GraphEdgeView

        planner = RuleBasedPlanner(risk_lookup=lambda _c: RiskLevel.LOW)
        graph = GraphSummary(
            edges=[
                GraphEdgeView(
                    source="router",
                    target=SEED,
                    relationship=GraphRelationship.POTENTIALLY_LEADS_TO,
                    state="open",
                    confidence="low",
                ),
            ]
        )
        decision = planner.plan(
            _ctx(authorized=["recon.dns", "webapi.http_request"], graph=graph)
        )
        assert decision.kind is DecisionKind.INVESTIGATE
        assert decision.priority is Priority.HIGH
        assert "open attack-graph" in decision.reason

    def test_planner_decision_defaults_are_safe(self) -> None:
        decision = PlannerDecision(kind=DecisionKind.INVESTIGATE, capability="recon.dns",
                                   target=SEED, reason="r")
        assert decision.priority is Priority.MEDIUM
        assert decision.source is PlannerSource.RULE
        assert decision.require_registered is not None
        with pytest.raises(ValueError):
            decision.require_registered({"webapi.http_request"})


# ---------------------------------------------------------------------- #
# LLM planner fail-closed
# ---------------------------------------------------------------------- #
class TestLLMPlannerFailClosed:
    @staticmethod
    def _provider(content: str) -> Any:
        class _P:
            def generate(self, request: Any) -> LLMResponse:
                return LLMResponse(content=content)

        return _P()

    def test_valid_decision_accepted(self) -> None:
        planner = LLMPlanner(provider=self._provider(
            json.dumps({"capability": "recon.dns", "target": SEED,
                        "reason": "r", "priority": "LOW"})
        ))
        decision = planner.plan(_ctx(authorized=["recon.dns"]))
        assert decision.kind is DecisionKind.INVESTIGATE
        assert decision.capability == "recon.dns"
        assert decision.source is PlannerSource.LLM

    def test_unknown_capability_rejected(self) -> None:
        planner = LLMPlanner(provider=self._provider(
            json.dumps({"capability": "does.not_exist", "target": SEED,
                        "reason": "r", "priority": "LOW"})
        ))
        with pytest.raises(PlannerInvalidDecision):
            planner.plan(_ctx(authorized=["recon.dns"]))

    def test_out_of_scope_target_rejected(self) -> None:
        planner = LLMPlanner(provider=self._provider(
            json.dumps({"capability": "recon.dns", "target": "evil.example.com",
                        "reason": "r", "priority": "LOW"})
        ))
        with pytest.raises(PlannerInvalidDecision):
            planner.plan(_ctx(authorized=["recon.dns"]))

    def test_malformed_response_rejected(self) -> None:
        planner = LLMPlanner(provider=self._provider("this is not json"))
        with pytest.raises(PlannerInvalidDecision):
            planner.plan(_ctx(authorized=["recon.dns"]))

    def test_stop_direction_becomes_complete(self) -> None:
        planner = LLMPlanner(provider=self._provider('{"decision": "stop", "rationale": "done"}'))
        decision = planner.plan(_ctx(authorized=["recon.dns"]))
        assert decision.kind is DecisionKind.COMPLETE
        assert decision.reason == "done"


# ---------------------------------------------------------------------- #
# Registry / routing discovery
# ---------------------------------------------------------------------- #
class TestRoutingDiscovery:
    def test_registered_capabilities_present(self) -> None:
        app = _app()
        router = _router_for(app)
        ids = router.list_registered()
        assert len(ids) >= 61
        assert "recon.dns" in ids
        assert "webapi.security_header_analysis" in ids

    def test_unknown_capability_meta_raises(self) -> None:
        app = _app()
        router = _router_for(app)
        with pytest.raises((KeyError, CapabilityError)):
            router.meta("does.not_exist")

    def test_registered_capabilities_have_engines_or_real_adapters(self) -> None:

        app = _app()
        router = _router_for(app)
        for capability in router.list_registered():
            if capability == "mock_discovery":
                continue  # deliberately engine-less fake used by tests
            assert router.engine_for(capability) is not None

    def test_real_adapter_registry_installs_four(self) -> None:
        registry = RealAdapterRegistry()
        ids = registry.installed_capability_ids()
        assert set(ids) == {
            "recon.dns",
            "recon.tls_metadata",
            "recon.http_metadata",
            "webapi.security_header_analysis",
        }
        for capability in ids:
            assert registry.get(capability) is not None

    def test_default_mode_is_engine_driven(self) -> None:
        app = _app()
        router = _router_for(app)
        modes = {router.default_mode_for(c) for c in router.list_registered()}
        assert modes.issubset({"active", "controlled", "unknown"})
        assert router.default_mode_for("recon.dns") == "active"
        assert router.default_mode_for("identity.identity_enumeration") == "controlled"

    def test_capability_view_reports_engine_default_mode(self) -> None:
        orch = MissionOrchestrator(_app())
        mission = orch.create_mission(MissionSetup(name="m", objective="o", seed_target=SEED))
        view = orch.capability_view(str(mission.id))
        recon = next(r for r in view.rows if r.capability == "recon.dns")
        assert recon.mode == "active"
        assert recon.category == "recon"


# ---------------------------------------------------------------------- #
# Mission orchestration
# ---------------------------------------------------------------------- #
class TestMissionOrchestration:
    def _orchestrator(
        self, *, policy: MissionPolicy | None = None, **kwargs: Any
    ) -> tuple[MissionOrchestrator, str]:
        app = _app()
        orch = MissionOrchestrator(app, evidence_saturation_floor=10, **kwargs)
        mission = orch.create_mission(
            MissionSetup(
                name="p141 test",
                objective="authorized read-only assessment",
                seed_target=SEED,
                profile=AssessmentProfile.AUTHORIZED_ASSESSMENT,
                policy=policy or _policy(),
            )
        )
        return orch, str(mission.id)

    def test_capability_view_counts(self) -> None:
        orch, mid = self._orchestrator()
        view: CapabilityView = orch.capability_view(mid)
        assert view.registered >= 61
        assert view.applicable >= 61
        assert view.authorized >= 61
        assert view.real_controlled == 4
        real_rows = [r for r in view.rows if r.adapter is AdapterMode.REAL_CONTROLLED]
        assert {r.capability for r in real_rows} == {
            "recon.dns",
            "recon.tls_metadata",
            "recon.http_metadata",
            "webapi.security_header_analysis",
        }

    def test_mock_run_terminates_deterministically(self) -> None:
        orch, mid = self._orchestrator()
        state = orch.run_mission(mid)
        assert state.phase is ExecutionPhase.COMPLETED
        assert state.stop_reason in (
            StopReason.MAX_STEPS,
            StopReason.NO_ACTIONS_REMAIN,
            StopReason.EVIDENCE_SATURATION,
        )
        assert state.steps_completed >= 1
        assert len(state.instructions) == state.steps_completed
        for record in state.instructions:
            assert record.status is InvestigationStatus.COMPLETED
            assert record.capability
            assert record.target
            assert record.reason
            assert record.source in (PlannerSource.RULE, PlannerSource.LLM)

    def test_mock_run_stores_evidence_and_assets(self) -> None:
        orch, mid = self._orchestrator()
        orch.run_mission(mid)
        rows = orch.evidence_rows(mid)
        assert len(rows) >= 1
        assert orch.graph_summary(mid).node_count >= 1
        assets = orch.assets(mid)
        assert any(asset.name == SEED for asset in assets)

    def test_scope_restriction_stops_with_no_actions(self) -> None:
        orch, mid = self._orchestrator()
        scope = orch.scope_for(mid)
        scope.allowed_capabilities = ["no.such.capability"]  # nothing authorized
        state = orch.run_mission(mid)
        assert state.stop_reason is StopReason.NO_ACTIONS_REMAIN
        assert state.steps_completed == 0

    def test_cancel_before_run(self) -> None:
        orch, mid = self._orchestrator()
        state = orch.cancel(mid)
        assert state.phase is ExecutionPhase.CANCELLED
        assert state.stop_reason is StopReason.CANCELLED

    def test_real_adapter_dispatch_via_stub(self) -> None:
        orch, mid = self._orchestrator(
            allow_real_controlled=True,
            policy=_policy(allow_real_controlled=True),
        )
        orch._real_adapters.install(_StubObservationAdapter())
        scope = orch.scope_for(mid)
        scope.allowed_capabilities = ["recon.dns"]
        scope.max_risk_level = RiskLevel.LOW
        state = orch.run_mission(mid)
        assert state.steps_completed >= 1
        completed = [i for i in state.instructions if i.status is InvestigationStatus.COMPLETED]
        assert completed, "expected at least one completed instruction"
        first = completed[0]
        assert first.capability == "recon.dns"
        assert first.evidence_ids
        rows = orch.evidence_rows(mid)
        assert rows and len(rows) >= 1
        assert any(row.redacted for row in rows)  # redaction flag carried
        evidence = orch.app.evidence_store.get_by_mission(mid)
        raw_docs = [e.raw_data for e in evidence if e.raw_data]
        assert raw_docs, "evidence raw data should be persisted"
        parsed = json.loads(raw_docs[0])
        assert parsed["observed"]  # serialized JSON, not a python dict
        assert parsed["redacted"]

    def test_real_adapter_failure_fails_closed(self) -> None:
        orch, mid = self._orchestrator(
            allow_real_controlled=True,
            policy=_policy(allow_real_controlled=True),
        )
        orch._real_adapters.install(_StubObservationAdapter(success=False))
        scope = orch.scope_for(mid)
        scope.allowed_capabilities = ["recon.dns"]
        scope.max_risk_level = RiskLevel.LOW
        state = orch.run_mission(mid)
        executed = [i for i in state.instructions if i.capability == "recon.dns"]
        assert executed and executed[0].status is InvestigationStatus.FAILED

    def test_real_dispatch_blocked_without_opt_in_uses_mock(self) -> None:
        orch, mid = self._orchestrator()  # allow_real_controlled=False
        orch._real_adapters.install(_StubObservationAdapter())
        scope = orch.scope_for(mid)
        scope.allowed_capabilities = ["recon.dns"]
        scope.max_risk_level = RiskLevel.LOW
        state = orch.run_mission(mid)
        executed = [i for i in state.instructions if i.capability == "recon.dns"]
        assert executed, "mock fallback should still execute mock recon.dns"
        # unknowable stub adapter was not used (no redacted real evidence)
        insights = [i for i in state.instructions if i.status is InvestigationStatus.FAILED]
        assert all("real-controlled" not in (i.note or "") for i in insights)

    def test_llm_invalid_planner_stops_deterministically(self) -> None:
        stub = _ScriptedLLM([
            {"capability": "does.not_exist", "target": SEED, "reason": "r", "priority": "LOW"},
        ])
        orch, mid = self._orchestrator(
            planner=LLMPlanner(provider=stub),
            policy=_policy(invalid_plan_limit=1),
        )
        state = orch.run_mission(mid)
        assert state.stop_reason is StopReason.REPEATED_INVALID_PLANNER

    def test_llm_scripted_run_produces_instructions(self) -> None:
        decisions = [
            {"capability": "recon.dns", "target": SEED, "reason": "r", "priority": "LOW"},
            {"capability": "recon.dns", "target": SEED, "reason": "r", "priority": "LOW"},
            {"capability": "recon.dns", "target": SEED, "reason": "r", "priority": "LOW"},
        ]
        orch, mid = self._orchestrator(
            planner=LLMPlanner(provider=_ScriptedLLM(decisions)),
            policy=_policy(invalid_plan_limit=1),
        )
        scope = orch.scope_for(mid)
        scope.allowed_capabilities = ["recon.dns"]
        scope.max_risk_level = RiskLevel.LOW
        state = orch.run_mission(mid)
        assert state.stop_reason in (
            StopReason.DUPLICATE_EVICTION,
            StopReason.MAX_REPLANS,
            StopReason.MAX_STEPS,
        )
        executed = [i for i in state.instructions if i.capability == "recon.dns"]
        assert any(i.status is InvestigationStatus.COMPLETED for i in executed)

    def test_planner_context_is_structured_and_safe(self) -> None:
        orch, mid = self._orchestrator()
        state = MissionRuntimeState(mission_id=mid)
        orch._runtimes[mid] = state
        ctx = orch._planner_context(
            orch.mission_record(mid),
            orch.scope_for(mid),
            state,
            _policy(),
        )
        assert ctx.mission_id == mid
        assert ctx.seed_target == SEED
        assert ctx.objective
        assert ctx.policy.max_steps == 4
        assert ctx.routing is not None
        assert ctx.routing.applicable


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #
def _app() -> Any:
    from blackforge.runtime.bootstrap import bootstrap

    return bootstrap()


def _meta(app: Any, capability: str) -> Any:
    capability_obj = app.capability_registry.get(capability)
    if capability_obj is None:
        raise KeyError(capability)
    return capability_obj.meta()


def _router_for(app: Any) -> CapabilityRouter:
    return CapabilityRouter(
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
        real_adapters=RealAdapterRegistry(),
    )
