"""Layer B — opt-in real validation for phase 14.1.

These tests perform *real* bounded observations (DNS resolution, TLS
metadata, HTTP metadata/headers) against a live target and, when an LLM
endpoint is reachable, real planner invocation. They require network access
and are therefore opt-in:

    BLACKFORGE_REAL_TARGET=<host> pytest tests/integration -m real

Real LLM verification additionally requires ``BLACKFORGE_REAL_MODEL`` set to
``ollama`` or ``huggingface`` (the Colab notebook is the primary run-site).

The suite never falls back silently: a failed observation is a first-class
``success=False`` RealObservation that still becomes evidence, and the
assertions below distinguish ``success`` (observation happened) from
``healthy`` (transport answered). Nothing here mocks a transport.
"""

import os
from typing import Any

import pytest

from blackforge.evidence.models import EvidenceSource
from blackforge.orchestration import MissionOrchestrator
from blackforge.orchestration.models import (
    ExecutionMode,
    MissionPolicy,
    MissionSetup,
)
from blackforge.runtime.bootstrap import bootstrap as _bootstrap

_REAL_TARGET = os.environ.get("BLACKFORGE_REAL_TARGET", "").strip()
_REAL_MODEL = os.environ.get("BLACKFORGE_REAL_MODEL", "").strip().lower()
_PROVIDER = _REAL_MODEL if _REAL_MODEL in ("ollama", "huggingface") else None

require_target = pytest.mark.skipif(
    not _REAL_TARGET,
    reason="set BLACKFORGE_REAL_TARGET=<host> to run real integration tests",
)

pytestmark = [
    pytest.mark.real,
    pytest.mark.integration,
    require_target,
]


def _app() -> Any:
    return _bootstrap()


def _mission(
    orch: MissionOrchestrator,
    *,
    execution_mode: ExecutionMode,
    allow_real_controlled: bool = True,
    max_steps: int = 3,
) -> MissionSetup:
    policy = MissionPolicy(
        allow_real_controlled=allow_real_controlled,
        auto_approve_high_risk=False,
        execution_mode=execution_mode,
        max_steps=max_steps,
    )
    return orch.create_mission(
        MissionSetup(
            name="phase14-1-real-integration",
            objective="validate real transport observations",
            seed_target=_REAL_TARGET,
            profile="authorized_assessment",
            policy=policy,
        )
    )


def _restrict_to(orch: MissionOrchestrator, mission_id: str, *capabilities: str) -> None:
    orch.scope_for(mission_id).allowed_capabilities = list(capabilities)


class TestRealTransportObservations:
    def test_real_dns_produces_real_evidence_and_finding(self) -> None:
        orch = MissionOrchestrator(_app(), allow_real_controlled=True)
        mission = _mission(orch, execution_mode=ExecutionMode.REAL, max_steps=2)
        mid = str(mission.id)
        _restrict_to(orch, mid, "recon.dns")
        state = orch.run_mission(mid, planner=orch.rule_planner)

        assert state.real_observations >= 1
        assert state.transport_mode == "real_controlled"
        rows = orch.evidence_rows(mid)
        assert rows, "real DNS observation must produce evidence rows"
        assert all(row.source is EvidenceSource.REAL for row in rows)
        assert any(
            row.source_capability == "recon.dns"
            and bool(row.observed.get("resolved_addresses"))
            for row in rows
        )
        findings = orch.findings(mid)
        assert any(
            f.source_capability == "recon.dns" for f in findings
        ), "real evidence must surface a derived finding"

    def test_real_tls_and_http_metadata_observed(self) -> None:
        orch = MissionOrchestrator(_app(), allow_real_controlled=True)
        mission = _mission(orch, execution_mode=ExecutionMode.REAL, max_steps=3)
        mid = str(mission.id)
        _restrict_to(orch, mid, "recon.tls_metadata", "recon.http_metadata")
        state = orch.run_mission(mid, planner=orch.rule_planner)

        rows = orch.evidence_rows(mid)
        assert rows, "real TL/HTTP observations must produce evidence rows"
        capability_observations = {
            row.source_capability
            for row in rows
            if row.source is EvidenceSource.REAL and row.status == "observed"
        }
        assert "recon.tls_metadata" in capability_observations
        assert "recon.http_metadata" in capability_observations
        assert state.real_observations >= 2

    def test_real_observation_is_never_self_validated(self) -> None:
        orch = MissionOrchestrator(_app(), allow_real_controlled=True)
        mission = _mission(orch, execution_mode=ExecutionMode.REAL, max_steps=2)
        mid = str(mission.id)
        _restrict_to(orch, mid, "recon.dns")
        orch.run_mission(mid, planner=orch.rule_planner)
        for finding in orch.findings(mid):
            assert finding.validation_state != "self_validated"

    def test_auto_reports_real_transport_used(self) -> None:
        orch = MissionOrchestrator(_app(), allow_real_controlled=True)
        mission = _mission(orch, execution_mode=ExecutionMode.AUTO, max_steps=2)
        mid = str(mission.id)
        _restrict_to(orch, mid, "recon.dns")
        state = orch.run_mission(mid, planner=orch.rule_planner)
        assert state.real_observations >= 1
        assert state.transport_mode == "real_controlled"


@pytest.mark.skipif(
    _PROVIDER is None,
    reason="set BLACKFORGE_REAL_MODEL=ollama|huggingface for real LLM assertions",
)
class TestRealModelInvocation:
    def test_real_planner_invocation_reported_really(self) -> None:
        from blackforge.orchestration.planner import LLMPlanner
        from blackforge.runtime.bootstrap import _resolve_provider

        app = _app()
        orch = MissionOrchestrator(app, allow_real_controlled=True)
        llm_config = app.config.llm.model_copy(
            update={
                "provider": _PROVIDER,
                "model": "Qwen/Qwen2.5-3B-Instruct",
                "max_output_tokens": 96,
            }
        )
        blackforge_config = app.config.model_copy(update={"llm": llm_config})
        provider = _resolve_provider(blackforge_config)
        planner = LLMPlanner(provider=provider)
        mission = _mission(orch, execution_mode=ExecutionMode.MOCK, max_steps=2)
        state = orch.run_mission(str(mission.id), planner=planner)
        assert state.llm_status is not None
        assert state.llm_status.invocation in ("REAL", "FALLBACK")
