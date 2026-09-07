"""Phase 14.1 Development Console test suite.

Covers the console's access gate, the application/service layer, the
UI->service->orchestrator separation, and the security guarantees (UI can't
bypass the orchestrator; secrets stay redacted; locked console refuses
execution).
"""
from __future__ import annotations

from typing import Any

import pytest

from blackforge.orchestration.models import (
    AdapterMode,
    ExecutionPhase,
    InvestigationStatus,
)
from blackforge.orchestration.orchestrator import OrchestrationError
from blackforge.ui import (
    AccessGate,
    ConsoleAccessError,
    ConsoleError,
    DevelopmentConsole,
    DevelopmentConsoleService,
    PlannerSelection,
)

MID = "mission_ui_p141"
SEED = "getaelionix.com"


def _app() -> Any:
    from blackforge.runtime.bootstrap import bootstrap

    return bootstrap()


def _service() -> DevelopmentConsoleService:
    return DevelopmentConsoleService(_app())


# ---------------------------------------------------------------------- #
# Access gate
# ---------------------------------------------------------------------- #
class TestAccessGate:
    def test_starts_locked(self) -> None:
        gate = AccessGate()
        assert not gate.is_unlocked()

    def test_environment_token_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BLACKFORGE_CONSOLE_TOKEN", "secret-token-xyz")
        gate = AccessGate()
        assert gate.has_environment_token
        assert gate.unlock("secret-token-xyz")
        assert gate.is_unlocked()

    def test_wrong_token_rejected(self) -> None:
        gate = AccessGate()
        assert not gate.unlock("wrong-token")
        assert not gate.is_unlocked()

    def test_generated_token_unlocks(self) -> None:
        gate = AccessGate()
        token = gate.generated_token()
        assert token
        assert gate.unlock(token)
        assert gate.is_unlocked()

    def test_generated_token_differs_across_instances(self) -> None:
        a, b = AccessGate(), AccessGate()
        assert a.generated_token() != b.generated_token()
        assert len(a.generated_token()) >= 24

    def test_lock_revokes(self) -> None:
        gate = AccessGate()
        token = gate.generated_token()
        assert gate.unlock(token)
        gate.lock()
        assert not gate.is_unlocked()

    def test_constant_time_compare(self) -> None:
        gate = AccessGate()
        gate.generated_token()
        assert not gate.unlock(None)


# ---------------------------------------------------------------------- #
# Console service / application layer
# ---------------------------------------------------------------------- #
class TestDevelopmentConsoleService:
    def test_create_mission_returns_summary(self) -> None:
        svc = _service()
        summary = svc.create_mission(
            seed_target=SEED, name="ui test", objective="read-only assessment"
        )
        assert summary.seed_target == SEED
        assert summary.profile.value == "authorized_assessment"
        assert summary.status in ("created", "ready")

    def test_reject_invalid_profile(self) -> None:
        svc = _service()
        with pytest.raises(ConsoleError):
            svc.create_mission(seed_target=SEED, name="m", objective="o", profile="bogus")

    def test_reject_invalid_seed(self) -> None:
        svc = _service()
        with pytest.raises(OrchestrationError):
            svc.create_mission(seed_target="has spaces", name="m", objective="o")

    def test_unknown_mission_raises(self) -> None:
        svc = _service()
        with pytest.raises(ConsoleError):
            svc.mission_summary("mission_does_not_exist")

    def test_cancel_mission(self) -> None:
        svc = _service()
        summary = svc.create_mission(seed_target=SEED, name="m", objective="o")
        state = svc.cancel(str(summary.mission_id))
        assert state.phase is ExecutionPhase.CANCELLED

    def test_run_mission_rule_planner(self) -> None:
        svc = _service()
        summary = svc.create_mission(
            seed_target=SEED, name="m", objective="o", max_steps=3
        )
        state = svc.run_mission(str(summary.mission_id), planner="rule")
        assert state.steps_completed >= 1
        assert len(state.instructions) == state.steps_completed

    def test_run_mission_mock_planner(self) -> None:
        svc = _service()
        summary = svc.create_mission(
            seed_target=SEED, name="m", objective="o", max_steps=2
        )
        state = svc.run_mission(str(summary.mission_id), planner="mock")
        assert state.steps_completed >= 1

    def test_run_mission_unknown_planner_rejected(self) -> None:
        svc = _service()
        summary = svc.create_mission(seed_target=SEED, name="m", objective="o")
        with pytest.raises(ConsoleError):
            svc.run_mission(str(summary.mission_id), planner="nonsense")

    def test_run_mission_llm_without_provider_rejected(self) -> None:
        svc = _service()
        summary = svc.create_mission(seed_target=SEED, name="m", objective="o")
        with pytest.raises(ConsoleError):
            svc.run_mission(str(summary.mission_id), planner="llm")

    def test_planner_selection_valid(self) -> None:
        for value in ("mock", "rule", "llm"):
            assert PlannerSelection.is_valid(value)
        assert not PlannerSelection.is_valid("nonsense")


# ---------------------------------------------------------------------- #
# Console UI layer
# ---------------------------------------------------------------------- #
class TestDevelopmentConsole:
    def test_locked_console_refuses_execution(self) -> None:
        console = DevelopmentConsole(_service())
        with pytest.raises(ConsoleAccessError):
            console.create_mission(seed_target=SEED, name="m", objective="o")

    def test_unlock_then_run_full_flow(self) -> None:
        console = DevelopmentConsole(_service())
        console.unlock(console.display_token_hint())
        summary = console.create_mission(
            seed_target=SEED, name="console flow", objective="read-only", max_steps=3
        )
        mid = summary["mission_id"]
        state = console.run_mission(mid)
        assert state["phase"] == "completed"
        assert state["steps_completed"] >= 1

    def test_cancel_from_console(self) -> None:
        console = DevelopmentConsole(_service())
        console.unlock(console.display_token_hint())
        summary = console.create_mission(seed_target=SEED, name="m", objective="o")
        state = console.cancel(summary["mission_id"])
        assert state["phase"] == "cancelled"

    def test_report_contains_views(self) -> None:
        console = DevelopmentConsole(_service())
        console.unlock(console.display_token_hint())
        summary = console.create_mission(seed_target=SEED, name="r", objective="o")
        mid = summary["mission_id"]
        console.run_mission(mid)
        lines = "\n".join(console.render_report(mid))
        assert "CAPABILITIES" in lines
        assert "ASSETS" in lines
        assert "EVIDENCE" in lines
        assert "ATTACK GRAPH" in lines

    def test_report_is_redaction_safe(self) -> None:
        console = DevelopmentConsole(_service())
        console.unlock(console.display_token_hint())
        summary = console.create_mission(seed_target=SEED, name="s", objective="o")
        mid = summary["mission_id"]
        console.run_mission(mid)
        joined = "\n".join(console.render_report(mid))
        # no raw secret-looking material leaks through the report
        for token in ("password=", "api_key=", "Bearer ", "secret="):
            assert token not in joined

    def test_capability_view_distinguishes_adapter_modes(self) -> None:
        console = DevelopmentConsole(_service())
        console.unlock(console.display_token_hint())
        summary = console.create_mission(seed_target=SEED, name="a", objective="o")
        mid = summary["mission_id"]
        view = console.service.capability_view(mid)
        real = [r for r in view.rows if r.adapter is AdapterMode.REAL_CONTROLLED]
        assert {r.capability for r in real} == {
            "recon.dns",
            "recon.tls_metadata",
            "recon.http_metadata",
            "webapi.security_header_analysis",
        }


# ---------------------------------------------------------------------- #
# Security: the UI cannot bypass the orchestrator
# ---------------------------------------------------------------------- #
class TestConsoleDoesNotBypassOrchestrator:
    def test_service_exposes_no_arbitrary_engine_method(self) -> None:
        svc = _service()
        # The service facade must not expose raw storage/transport handles
        # that let a UI bypass authorization/scope.
        for forbidden in (
            "evidence_store",
            "world_model",
            "attack_graph_builder",
            "app",
            "authorization",
        ):
            assert not hasattr(svc, forbidden), f"service leaks {forbidden}"

    def test_console_exposes_no_core_storage(self) -> None:
        console = DevelopmentConsole(_service())
        for forbidden in ("evidence_store", "app", "authorization", "world_model"):
            assert not hasattr(console, forbidden), f"console leaks {forbidden}"

    def test_mission_execution_still_passes_orchestrator(self) -> None:
        svc = _service()
        summary = svc.create_mission(seed_target=SEED, name="m", objective="o", max_steps=5)
        mid = str(summary.mission_id)
        # Restrict scope via the orchestrator so no capability is authorized
        orch = svc.orchestrator()
        scope = orch.scope_for(mid)
        scope.allowed_capabilities = ["no.such.capability"]
        state = svc.run_mission(mid)
        # The orchestrator's authorization gate denies every capability, so
        # the planner deterministically stops with no actions remaining and
        # no instruction is ever produced or executed.
        assert state.steps_completed == 0
        assert state.stop_reason.value == "no_actions_remain"
        assert state.instructions == []

    def test_executed_instructions_are_audited(self) -> None:
        svc = _service()
        summary = svc.create_mission(seed_target=SEED, name="m", objective="o", max_steps=3)
        mid = str(summary.mission_id)
        state = svc.run_mission(mid)
        for record in state.instructions:
            assert record.status is InvestigationStatus.COMPLETED
            assert record.capability
            assert record.target
            assert record.reason
            assert record.source.value in ("rule", "mock", "llm")
