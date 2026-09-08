"""Phase 14.1 real-world validation remediation — deterministic Layer A tests.

These tests are hermetic (no network, no models). They prove the
*guards and honest reporting* for real-vs-mock execution:

* execution_mode=real fails instead of silently falling back to mock,
* execution_mode=mock never touches a real adapter,
* planner_mode=real requires a real planner provider,
* planner_mode=mock never invokes a real model,
* AUTO falls back explicitly and reports the fallback,
* evidence provenance (REAL/MOCK) survives into the console views,
* findings are built strictly from evidence with honest epistemic status,
* the console HTTP server enforces the access token on every route
  except ``/health``.
"""
from __future__ import annotations

import json
import threading
from typing import Any

import pytest

from blackforge.intelligence.llm.base import LLMProvider, LLMRequest, LLMResponse
from blackforge.orchestration.models import (
    AdapterMode,
    AssessmentProfile,
    EvidenceSource,
    ExecutionMode,
    MissionPolicy,
    MissionSetup,
    StopReason,
)
from blackforge.orchestration.orchestrator import MissionOrchestrator
from blackforge.orchestration.planner import LLMPlanner
from blackforge.ui import AccessGate, DevelopmentConsoleService
from blackforge.ui.server import start_server

SEED = "getaelionix.com"


def _app() -> Any:
    from blackforge.runtime.bootstrap import bootstrap

    return bootstrap()


def _service() -> DevelopmentConsoleService:
    return DevelopmentConsoleService(_app())


class _StubProvider(LLMProvider):
    """Deterministic provider stub; never touches a network.

    ``provider`` controls the metadata label so tests can simulate a real
    (non-mock) model without ever contacting one.
    """

    def __init__(
        self,
        *,
        provider: str = "mock",
        model: str = "qwen-2.5-3b",
        decisions: list[str] | None = None,
    ) -> None:
        self._provider = provider
        self._model = model
        self._decisions = list(decisions or [])
        self.calls = 0

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        if self._decisions:
            content = self._decisions.pop(0)
        else:
            content = (
                '{"decision":"investigate","capability":"recon.dns",'
                '"target":"' + SEED + '","rationale":"stub","priority":"low"}'
            )
        return LLMResponse(content=content, model=self._model)

    def metadata(self) -> dict[str, Any]:
        return {"provider": self._provider, "model": self._model}

    def health_check(self) -> bool:
        return self._provider != "down"


def _mission(orch: MissionOrchestrator, **policy: Any) -> Any:
    setup = MissionSetup(
        name="real-validation-layer-a",
        objective="authorized read-only validation",
        seed_target=SEED,
        profile=AssessmentProfile.AUTHORIZED_ASSESSMENT,
        policy=MissionPolicy(**policy),
    )
    return orch.create_mission(setup)


# ---------------------------------------------------------------------- #
# execution_mode guards
# ---------------------------------------------------------------------- #
class TestExecutionModeGuard:
    def test_real_mode_without_real_adapter_fails_not_falls_back(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)
        mission = _mission(orch, execution_mode=ExecutionMode.REAL)
        state = orch.run_mission(str(mission.id), planner=orch.rule_planner)
        assert state.stop_reason is StopReason.REAL_MODE_GUARD
        assert state.real_observations == 0
        assert state.mock_observations == 0
        assert str(orch.mission_record(mission.id).status.value) == "failed"

    def test_real_mode_with_adapter_disabled_fails(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app, allow_real_controlled=False)
        mission = _mission(
            orch,
            execution_mode=ExecutionMode.REAL,
            allow_real_controlled=True,
        )
        state = orch.run_mission(str(mission.id), planner=orch.rule_planner)
        assert state.stop_reason is StopReason.REAL_MODE_GUARD
        assert state.real_observations == 0

    def test_mock_mode_never_touches_real_adapter(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app, allow_real_controlled=True)
        calls = {"n": 0}

        real = orch._real_adapters.get("recon.dns")

        def observe(_target: str) -> Any:
            calls["n"] += 1
            return real.observe("127.0.0.1")

        real.observe = observe  # type: ignore[method-assign]
        mission = _mission(
            orch,
            execution_mode=ExecutionMode.MOCK,
            allow_real_controlled=True,
            max_steps=6,
        )
        state = orch.run_mission(str(mission.id), planner=orch.rule_planner)
        assert state.real_observations == 0
        assert state.mock_observations >= 1
        assert calls["n"] == 0

    def test_auto_selects_real_transport_for_real_capability(self) -> None:
        from blackforge.orchestration.adapters import RealObservation
        from blackforge.orchestration.models import (
            InstructionRecord,
            PlannerSource,
            Priority,
        )

        app = _app()
        orch = MissionOrchestrator(app, allow_real_controlled=True)
        real = orch._real_adapters.get("recon.dns")

        def observe(target: str) -> RealObservation:
            return RealObservation(
                capability_id="recon.dns",
                target=target,
                success=True,
                summary="stubbed dns observation",
                observed={"stub": True},
            )

        real.observe = observe  # type: ignore[method-assign]
        mission = _mission(
            orch,
            execution_mode=ExecutionMode.AUTO,
            allow_real_controlled=True,
        )
        mid = str(mission.id)
        state = orch._require_runtime(mid)
        instruction = InstructionRecord(
            mission_id=mission.id,
            capability="recon.dns",
            target=SEED,
            reason="test",
            source=PlannerSource.RULE,
            priority=Priority.LOW,
        )
        outcome = orch._dispatch(mid, orch.scope_for(mid), instruction, state)
        assert outcome.success
        assert outcome.adapter_mode is AdapterMode.REAL_CONTROLLED
        assert state.real_observations == 1
        assert state.transport_mode == "real_controlled"

    def test_auto_reports_real_observations_when_enabled(self) -> None:
        from blackforge.orchestration.adapters import RealObservation

        app = _app()
        orch = MissionOrchestrator(app, allow_real_controlled=True)
        real = orch._real_adapters.get("recon.dns")

        def observe(target: str) -> RealObservation:
            return RealObservation(
                capability_id="recon.dns",
                target=target,
                success=True,
                summary="stubbed dns observation",
                observed={"stub": True},
            )

        real.observe = observe  # type: ignore[method-assign]
        mission = _mission(
            orch,
            execution_mode=ExecutionMode.AUTO,
            allow_real_controlled=True,
            max_steps=2,
        )
        orch.scope_for(str(mission.id)).allowed_capabilities = ["recon.dns"]
        state = orch.run_mission(str(mission.id), planner=orch.rule_planner)
        assert state.real_observations >= 1
        assert state.transport_mode == "real_controlled"


# ---------------------------------------------------------------------- #
# planner_mode guards (no-silent-mock)
# ---------------------------------------------------------------------- #
class TestPlannerModeGuard:
    def test_real_planner_mode_with_rule_planner_fails(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)
        mission = _mission(orch, planner_mode=ExecutionMode.REAL)
        state = orch.run_mission(str(mission.id), planner=orch.rule_planner)
        assert state.stop_reason is StopReason.REAL_MODE_GUARD
        assert state.llm_status is not None
        assert state.llm_status.health == "FAIL"
        assert state.llm_status.invocation == "NOT_USED"

    def test_real_planner_mode_with_mock_provider_fails(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)
        stub = _StubProvider(provider="mock")
        mission = _mission(orch, planner_mode=ExecutionMode.REAL)
        state = orch.run_mission(
            str(mission.id), planner=LLMPlanner(provider=stub)
        )
        assert state.stop_reason is StopReason.REAL_MODE_GUARD
        assert stub.calls == 0

    def test_real_planner_mode_with_real_provider_records_real(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)
        decisions = [
            '{"decision":"investigate","capability":"recon.dns",'
            '"target":"' + SEED + '","rationale":"a","priority":"low"}',
            '{"decision":"investigate","capability":"recon.tls_metadata",'
            '"target":"' + SEED + '","rationale":"b","priority":"low"}',
            '{"decision":"stop","capability":"","target":"","rationale":"done","priority":"low"}',
        ]
        stub = _StubProvider(provider="huggingface", decisions=decisions)
        mission = _mission(
            orch,
            planner_mode=ExecutionMode.REAL,
            execution_mode=ExecutionMode.MOCK,
            max_steps=4,
        )
        state = orch.run_mission(str(mission.id), planner=LLMPlanner(provider=stub))
        assert state.stop_reason is not StopReason.REAL_MODE_GUARD
        assert stub.calls >= 3
        assert state.llm_status is not None
        assert state.llm_status.invocation == "REAL"
        assert state.llm_status.health == "PASS"
        assert state.llm_status.provider == "huggingface"

    def test_mock_planner_mode_with_real_provider_never_invokes_it(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)
        stub = _StubProvider(provider="huggingface")
        mission = _mission(
            orch,
            planner_mode=ExecutionMode.MOCK,
            max_steps=2,
        )
        state = orch.run_mission(str(mission.id), planner=LLMPlanner(provider=stub))
        assert stub.calls == 0
        assert state.llm_status is not None
        assert state.llm_status.invocation == "NOT_USED"

    def test_auto_reports_fallback_when_llm_fails(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)

        class _FailingProvider(_StubProvider):
            def generate(self, request: LLMRequest) -> LLMResponse:
                raise RuntimeError("provider down")

        stub = _FailingProvider(provider="huggingface")
        mission = _mission(
            orch,
            planner_mode=ExecutionMode.AUTO,
            execution_mode=ExecutionMode.MOCK,
            max_steps=2,
        )
        state = orch.run_mission(str(mission.id), planner=LLMPlanner(provider=stub))
        assert state.llm_status is not None
        assert state.llm_status.invocation == "FALLBACK"
        assert state.mock_observations >= 1


# ---------------------------------------------------------------------- #
# Evidence provenance + findings honesty
# ---------------------------------------------------------------------- #
class TestEvidenceProvenanceAndFindings:
    def test_real_evidence_carries_real_source(self) -> None:
        from blackforge.orchestration.adapters import RealObservation

        app = _app()
        orch = MissionOrchestrator(app, allow_real_controlled=True)
        real = orch._real_adapters.get("recon.dns")

        def observe(target: str) -> RealObservation:
            return RealObservation(
                capability_id="recon.dns",
                target=target,
                success=True,
                summary="stubbed dns observation",
                observed={"stub": True},
            )

        real.observe = observe  # type: ignore[method-assign]
        mission = _mission(
            orch,
            execution_mode=ExecutionMode.REAL,
            allow_real_controlled=True,
            max_steps=2,
        )
        state = orch.run_mission(str(mission.id), planner=orch.rule_planner)
        assert state.real_observations >= 1
        rows = orch.evidence_rows(str(mission.id))
        assert rows
        assert all(row.source is EvidenceSource.REAL for row in rows)

    def test_mock_evidence_carries_mock_source(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)
        mission = _mission(orch, execution_mode=ExecutionMode.MOCK, max_steps=2)
        orch.run_mission(str(mission.id), planner=orch.rule_planner)
        rows = orch.evidence_rows(str(mission.id))
        assert rows
        assert all(row.source is EvidenceSource.MOCK for row in rows)

    def test_findings_are_evidence_backed_and_never_self_validated(self) -> None:
        app = _app()
        orch = MissionOrchestrator(app)
        mission = _mission(orch, execution_mode=ExecutionMode.MOCK, max_steps=2)
        orch.run_mission(str(mission.id), planner=orch.rule_planner)
        findings = orch.findings(str(mission.id))
        assert findings
        for finding in findings:
            assert finding.affected_asset
            assert finding.evidence_ids

            observed = [
                row.status for row in orch.evidence_rows(str(mission.id))
            ]
            assert finding.status in {"observed", "inferred", "hypothesized", "validated"}
            assert finding.status != "validated" or "validated" in observed

    def test_finding_uses_strongest_observed_confidence(self) -> None:
        from blackforge.core.types import Confidence, EvidenceStatus, EvidenceType, MissionID
        from blackforge.evidence.models import Evidence, Provenance

        app = _app()
        orch = MissionOrchestrator(app)
        mission = _mission(orch)
        mid = MissionID(str(mission.id))
        store = app.evidence_store
        store.add(
            Evidence(
                mission_id=mid,
                source_capability="recon.dns",
                target=SEED,
                evidence_type=EvidenceType.OBSERVATION,
                status=EvidenceStatus.INFERRED,
                confidence=Confidence.HIGH,
                summary="dns observed",
                raw_data="{}",
                provenance=Provenance(capability_id="recon.dns"),
            )
        )
        findings = orch.findings(str(mission.id))
        dns = [f for f in findings if f.capability == "recon.dns"]
        assert dns
        assert dns[0].confidence == "high"
        assert dns[0].status == "inferred"


# ---------------------------------------------------------------------- #
# Console HTTP server + token gate
# ---------------------------------------------------------------------- #
class TestConsoleServerAuth:
    @staticmethod
    def _server():
        app = _app()
        gate = AccessGate(token="test-console-token")
        service = DevelopmentConsoleService(app)
        server = start_server(service, access=gate)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, gate

    def test_health_is_open(self) -> None:
        import urllib.request

        server, _ = self._server()
        try:
            with urllib.request.urlopen(server.base_url + "/health", timeout=5) as resp:  # noqa: S310
                payload = json.loads(resp.read())
            assert payload["status"] == "ok"
        finally:
            server.shutdown()

    def test_data_route_requires_token(self) -> None:
        import urllib.error
        import urllib.request

        server, _ = self._server()
        try:
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(server.base_url + "/api/status", timeout=5)  # noqa: S310
            assert exc.value.code == 401
        finally:
            server.shutdown()

    def test_status_with_token_reports_provider(self) -> None:
        import urllib.request

        server, gate = self._server()
        try:
            request = urllib.request.Request(  # noqa: S310
                server.base_url + "/api/status",
                headers={"Authorization": "Bearer test-console-token"},
            )
            with urllib.request.urlopen(request, timeout=5) as resp:
                payload = json.loads(resp.read())
            assert payload["ok"] is True
            assert "provider" in payload
            assert payload["planner"] == "rule"
        finally:
            server.shutdown()

    def test_mission_lifecycle_over_http(self) -> None:
        import urllib.request

        server, _ = self._server()
        try:
            base = server.base_url
            headers = {
                "Authorization": "Bearer test-console-token",
                "Content-Type": "application/json",
            }

            req = urllib.request.Request(  # noqa: S310
                base + "/api/missions",
                data=json.dumps(
                    {"seed_target": SEED, "name": "http-mission", "objective": "o"}
                ).encode(),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                created = json.loads(resp.read())
            mid = created["mission"]["mission_id"]
            assert created["mission"]["execution_mode"] == "auto"

            req = urllib.request.Request(  # noqa: S310
                base + f"/api/missions/{mid}/run",
                data=json.dumps({"planner": "rule"}).encode(),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                run = json.loads(resp.read())
            assert run["ok"] is True
            assert run["runtime"]["steps_completed"] >= 1

            with urllib.request.urlopen(  # noqa: S310
                urllib.request.Request(base + f"/api/missions/{mid}/findings", headers=headers),
                timeout=10,
            ) as resp:
                findings = json.loads(resp.read())
            assert "findings" in findings
        finally:
            server.shutdown()

    def test_server_keeps_ui_stdlib_only(self) -> None:
        import ast

        with open("blackforge/ui/server.py", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in ("subprocess", "os"), (
                        f"server.py imports forbidden module: {root}"
                    )
            if isinstance(node, ast.Call):
                func = node.func
                name = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else (func.id if isinstance(func, ast.Name) else "")
                )
                assert name not in ("system", "eval", "exec"), (
                    f"server.py calls forbidden: {name}"
                )
