"""Development Console application/service layer.

This module is the single service API the console UI may call. It sits
between the UI and the orchestrator + Blackforge core:

    UI  ->  DevelopmentConsoleService  ->  MissionOrchestrator  ->  core

It deliberately exposes *no* method to write evidence, mutate world-model
storage, or bypass authorization/scope. Every mission-creating or
mission-running call eventually funnels through the deterministic
:class:`MissionOrchestrator`, which enforces the registration, authorization,
scope and adapter gates. The service exposes only read-only view models
derived from the orchestrator's own redaction-safe projections.

The service is provider-agnostic about planners: callers may select
``mock``, ``rule``, or ``llm``. An LLM planner is only ever wired in when the
caller supplies a provider instance; no network transport lives here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from blackforge.orchestration.models import (
    AssessmentProfile,
    AssetSummary,
    CapabilityView,
    EvidenceViewRow,
    ExecutionMode,
    FindingView,
    GraphSummary,
    LLMRuntimeStatus,
    MissionPolicy,
    MissionRuntimeState,
    MissionSetup,
    MissionSummary,
)
from blackforge.orchestration.orchestrator import MissionOrchestrator

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from collections.abc import Callable

    from blackforge.intelligence.llm.base import LLMProvider


class ConsoleError(Exception):
    """Raised when the console requests something invalid."""

    __slots__ = ("message",)

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class PlannerSelection:
    """Valid planner identifiers the console supports."""

    MOCK = "mock"
    RULE = "rule"
    LLM = "llm"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        return value in (cls.MOCK, cls.RULE, cls.LLM)


class DevelopmentConsoleService:
    """Typed, read-mostly facade over the mission orchestrator.

    Construct with a bootstrapped Blackforge app. The console (UI) receives
    this object and may only use these methods.
    """

    def __init__(
        self,
        app: Any,
        *,
        orchestrator: MissionOrchestrator | None = None,
        llm_resolver: Callable[[str], LLMProvider | None] | None = None,
    ) -> None:
        self._orchestrator = orchestrator or MissionOrchestrator(app)
        self._llm_resolver = llm_resolver

    # ------------------------------------------------------------------
    # Mission lifecycle (creation always funnels through the orchestrator)
    # ------------------------------------------------------------------
    def create_mission(
        self,
        *,
        seed_target: str,
        name: str,
        objective: str,
        profile: str = "authorized_assessment",
        max_steps: int = 10,
        max_capability_calls: int = 25,
        max_runtime_seconds: float = 300.0,
        max_replans: int = 3,
        allow_real_controlled: bool = False,
        execution_mode: str = "auto",
        planner_mode: str = "auto",
        validation_target: str | None = None,
    ) -> MissionSummary:
        """Create a new mission bound to the seed target.

        The seed target is validated by the orchestrator (non-empty, single
        host, resolvable target type) and a bounded scope is built around it.
        The scope's `allowed_capabilities` is left empty (all registered
        capabilities subject to authorization/risk gates); the max risk is
        capped by the assessment profile.

        ``execution_mode``/``planner_mode`` are ``mock`` | ``real`` | ``auto``
        and are enforced by the orchestrator (REAL fails instead of silently
        falling back to mock). ``validation_target`` records the authorized
        reachable target used for real-world validation.
        """
        try:
            profile_enum = AssessmentProfile(profile)
        except ValueError as exc:
            raise ConsoleError(f"unknown assessment profile: {profile}") from exc
        try:
            exec_mode = ExecutionMode(execution_mode)
            plan_mode = ExecutionMode(planner_mode)
        except ValueError as exc:
            raise ConsoleError(f"invalid mode: {exc}") from exc

        policy = MissionPolicy(
            max_steps=max_steps,
            max_capability_calls=max_capability_calls,
            max_runtime_seconds=max_runtime_seconds,
            max_replans=max_replans,
            allow_real_controlled=allow_real_controlled,
            execution_mode=exec_mode,
            planner_mode=plan_mode,
            validation_target=validation_target,
        )
        setup = MissionSetup(
            name=name or "Development Console Mission",
            objective=objective or "authorized read-only assessment",
            seed_target=seed_target,
            profile=profile_enum,
            policy=policy,
        )
        mission = self._orchestrator.create_mission(setup)
        return self._mission_summary(str(mission.id))

    def mission_summary(self, mission_id: str) -> MissionSummary:
        self._require_mission(mission_id)
        return self._mission_summary(mission_id)

    def list_mission_ids(self) -> list[str]:
        return [str(m.id) for m in self._orchestrator.list_missions()]

    def cancel(self, mission_id: str) -> MissionRuntimeState:
        self._require_mission(mission_id)
        return self._orchestrator.cancel(mission_id)

    # ------------------------------------------------------------------
    # Execution (planner selection is explicit and validated)
    # ------------------------------------------------------------------
    def run_mission(
        self,
        mission_id: str,
        *,
        planner: str = "rule",
        llm_provider: LLMProvider | None = None,
        provider: str = "mock",
    ) -> MissionRuntimeState:
        """Run a mission with an explicit planner.

        ``planner`` may be ``mock``, ``rule``, or ``llm``. An ``llm``
        selection requires a provider: pass one directly, or rely on the
        service's ``llm_resolver`` and name one via ``provider``
        (``mock``, ``ollama``, ``huggingface``). All execution still passes
        through the orchestrator's gates; planner/execution modes are
        enforced there and never silently downgraded.
        """
        self._require_mission(mission_id)
        if not PlannerSelection.is_valid(planner):
            raise ConsoleError(f"unknown planner selection: {planner}")

        orch_planner: Any = None
        if planner == PlannerSelection.MOCK:
            orch_planner = self._orchestrator.mock_planner
        elif planner == PlannerSelection.RULE:
            orch_planner = self._orchestrator.rule_planner
        elif planner == PlannerSelection.LLM:
            resolved = llm_provider
            if resolved is None and self._llm_resolver is not None:
                resolved = self._llm_resolver(provider)
            if resolved is None:
                raise ConsoleError("llm planner selected but no provider available")
            from blackforge.orchestration.planner import LLMPlanner

            orch_planner = LLMPlanner(provider=resolved)

        return self._orchestrator.run_mission(
            mission_id, planner=orch_planner
        )

    # ------------------------------------------------------------------
    # Read-only view models (never raw storage)
    # ------------------------------------------------------------------
    def capability_view(self, mission_id: str) -> CapabilityView:
        self._require_mission(mission_id)
        return self._orchestrator.capability_view(mission_id)

    def assets(self, mission_id: str) -> list[AssetSummary]:
        self._require_mission(mission_id)
        return self._orchestrator.assets(mission_id)

    def evidence_rows(self, mission_id: str) -> list[EvidenceViewRow]:
        self._require_mission(mission_id)
        return self._orchestrator.evidence_rows(mission_id)

    def graph_summary(self, mission_id: str) -> GraphSummary:
        self._require_mission(mission_id)
        return self._orchestrator.graph_summary(mission_id)

    def findings(self, mission_id: str) -> list[FindingView]:
        self._require_mission(mission_id)
        return self._orchestrator.findings(mission_id)

    def runtime(self, mission_id: str) -> MissionRuntimeState | None:
        self._orchestrator.mission_record(mission_id)
        return self._orchestrator.runtime(mission_id)

    def llm_status(self, mission_id: str) -> LLMRuntimeStatus | None:
        state = self.runtime(mission_id)
        if state is None:
            return None
        return state.llm_status

    def planner_id(self) -> str:
        return self._orchestrator.planner_id()

    def provider_status(self) -> dict[str, Any]:
        return self._orchestrator.provider_status()

    def status(self) -> dict[str, Any]:
        """High-level console status payload (never raw storage)."""
        real_ids = self._orchestrator.router.real_controlled()
        return {
            "missions": self.list_mission_ids(),
            "capabilities_registered": len(self._orchestrator.router.list_registered()),
            "real_controlled_capabilities": real_ids,
            **self.provider_status(),
        }

    def orchestrator(self) -> MissionOrchestrator:
        return self._orchestrator

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _require_mission(self, mission_id: str) -> None:
        try:
            mission = self._orchestrator.mission_record(mission_id)
        except Exception as exc:  # noqa: BLE001 - normalize missing missions
            raise ConsoleError(f"unknown mission: {mission_id}") from exc
        if mission is None:
            raise ConsoleError(f"unknown mission: {mission_id}")

    def _mission_summary(self, mission_id: str) -> MissionSummary:
        mission = self._orchestrator.mission_record(mission_id)
        scope = self._orchestrator.scope_for(mission_id)
        state = self._orchestrator.runtime(mission_id) or MissionRuntimeState(
            mission_id=mission_id
        )
        return MissionSummary(
            mission_id=str(mission.id),
            name=mission.name,
            objective=str(mission.metadata.get("objective", mission.description or "")),
            seed_target=str(mission.metadata.get("seed_target", "")),
            status=mission.status.value,
            profile=AssessmentProfile(mission.metadata.get("profile", "authorized_assessment")),
            policy=self._orchestrator.policy_for(mission_id),
            scope=scope,
            runtime=state,
        )


__all__ = [
    "ConsoleError",
    "DevelopmentConsoleService",
    "PlannerSelection",
]
