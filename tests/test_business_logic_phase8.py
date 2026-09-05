from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from blackforge.auth.capabilities import build_auth_capabilities
from blackforge.auth.engine import AuthEngine
from blackforge.authorization import AuthorizationBoundary
from blackforge.business_logic.capabilities import (
    BUSINESS_LOGIC_CAPABILITY_IDS,
    build_business_logic_capabilities,
    build_business_logic_meta,
)
from blackforge.business_logic.engine import BusinessLogicEngine
from blackforge.business_logic.evidence import (
    artifact_evidence,
    evidence_dedup_key_for,
    observation_confidence,
    observation_evidence,
    observation_reference,
    observation_summary,
)
from blackforge.business_logic.models import (
    BusinessLogicHypothesisObservation,
    BusinessLogicMode,
    BusinessLogicRequest,
    BusinessLogicResult,
    BusinessLogicStatus,
    BusinessLogicValidationObservation,
    BusinessObservationKind,
    HypothesisOutcome,
    ReplaySafetyClass,
    ReplaySimulator,
    TransitionResult,
    ValidationResult,
    WorkflowModel,
)
from blackforge.business_logic.normalization import adapter_for_tool
from blackforge.business_logic.redaction import (
    credential_value_redacted,
    redact_credential_fields,
    redact_nested_credential_values,
)
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import (
    AuthorizationError,
    BusinessLogicExecutionError,
    BusinessLogicNormalizationError,
)
from blackforge.core.types import (
    Confidence,
    EvidenceStatus,
    EvidenceType,
    ProvenanceType,
    RiskLevel,
    TargetType,
)
from blackforge.evidence.repository import InMemoryEvidenceRepository
from blackforge.evidence.store import EvidenceStore
from blackforge.recon.capabilities import build_recon_capabilities
from blackforge.scope.models import Target, TargetScope, detect_target_type
from blackforge.webapi import redaction as webapi_redaction
from blackforge.webapi.capabilities import build_webapi_capabilities
from blackforge.world_model.models import EntityType, WorldLifecycle
from blackforge.world_model.query import RelationshipQuery, WorldQuery
from blackforge.world_model.repository import InMemoryWorldRepository
from blackforge.world_model.store import WorldModelStore

# --------------------------------------------------------------------------- #
# Shared fixtures
# --------------------------------------------------------------------------- #
MID = "mission_bl"
SID = "sess_bl"
SHOP = "shop.example.com"
ACTIONS = ["submit_order", "process_payment", "ship_order", "confirm_delivery", "cancel_order"]

HOSTS = [SHOP]
for suffix in ("throttled", "unreachable", "slow", "malformed"):
    HOSTS.append(f"{suffix}.example.com")


def _scope(
    mission_id: str = MID,
    *,
    max_risk_level: RiskLevel = RiskLevel.HIGH,
    allowed_targets: list[str] | None = None,
) -> TargetScope:
    targets = (
        [Target(value=t, target_type=detect_target_type(t)) for t in allowed_targets]
        if allowed_targets is not None
        else [Target(value="example.com", target_type=TargetType.DOMAIN)]
    )
    return TargetScope(
        mission_id=mission_id,
        allowed_targets=targets,
        allowed_capabilities=[],
        max_risk_level=max_risk_level,
    )


def _request(
    mission_id: str = MID,
    *,
    scope: TargetScope | None = None,
    mode: BusinessLogicMode = BusinessLogicMode.ACTIVE,
    test_identities: list[str] | None = None,
) -> BusinessLogicRequest:
    return BusinessLogicRequest(
        mission_id=mission_id,
        session_id=SID,
        scope=scope or _scope(mission_id),
        mode=mode,
        test_identities=test_identities or [],
        max_observations=500,
        timeout_seconds=30.0,
    )


def _engine(
    *,
    registry: CapabilityRegistry | None = None,
    use_stores: bool = True,
) -> tuple[
    BusinessLogicEngine, EvidenceStore | None, WorldModelStore | None
]:
    evidence_store = EvidenceStore(repository=InMemoryEvidenceRepository()) if use_stores else None
    world = WorldModelStore(repository=InMemoryWorldRepository()) if use_stores else None
    engine = BusinessLogicEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


def _shop_scope() -> TargetScope:
    return _scope(allowed_targets=[SHOP])


def _ident_req(*, identities: list[str] | None = None) -> BusinessLogicRequest:
    return _request(
        test_identities=identities or ["alice", "bob", "customer", "admin", "warehouse"]
    )


# --------------------------------------------------------------------------- #
# 1. Models
# --------------------------------------------------------------------------- #
class TestBusinessLogicModels:
    def test_mode_enum(self) -> None:
        assert BusinessLogicMode.PASSIVE.value == "passive"
        assert BusinessLogicMode.ACTIVE.value == "active"

    def test_status_enum(self) -> None:
        expected = {
            "success",
            "partial",
            "limited",
            "no_evidence",
            "request_failed",
            "rate_limited",
            "unauthorized",
            "out_of_scope",
            "malformed_response",
            "timeout",
            "failed",
        }
        assert {s.value for s in BusinessLogicStatus} == expected

    def test_kind_enum(self) -> None:
        expected = {
            "workflow",
            "state",
            "state_transition",
            "business_rule",
            "ownership",
            "role_boundary",
            "workflow_consistency",
            "workflow_replay",
            "business_logic_hypothesis",
            "business_logic_validation",
        }
        assert {k.value for k in BusinessObservationKind} == expected

    def test_transition_result_enum(self) -> None:
        assert TransitionResult.SUCCESS.value == "success"
        assert TransitionResult.UNEXPECTED_TRANSITION.value == "unexpected_transition"
        assert TransitionResult.MISSING_PREREQUISITE.value == "missing_prerequisite"
        assert TransitionResult.TERMINAL.value == "terminal"
        assert TransitionResult.REPEATED.value == "repeated"
        assert TransitionResult.UNKNOWN_ACTION.value == "unknown_action"
        assert TransitionResult.MALFORMED.value == "malformed"

    def test_replay_safety_enum(self) -> None:
        assert {s.value for s in ReplaySafetyClass} == {"passive", "bounded", "prohibited"}

    def test_hypothesis_outcome_enum(self) -> None:
        assert {o.value for o in HypothesisOutcome} == {"supported", "refuted", "inconclusive"}

    def test_validation_result_enum(self) -> None:
        assert {r.value for r in ValidationResult} == {
            "validated",
            "invalidated",
            "unverifiable",
        }

    def test_request_validation(self) -> None:
        with pytest.raises(ValidationError):
            BusinessLogicRequest(mission_id=MID, scope=_shop_scope(), timeout_seconds=0)
        with pytest.raises(ValidationError):
            BusinessLogicRequest(mission_id=MID, scope=_shop_scope(), max_observations=0)

    def test_result_observation_count(self) -> None:
        result = BusinessLogicResult(
            mission_id=MID,
            session_id=SID,
            target=SHOP,
            capability_id="business_logic.workflow_discovery",
            mode=BusinessLogicMode.ACTIVE,
        )
        assert result.observation_count == 0

    def test_workflow_model_unknown_action_fails_closed(self) -> None:
        model = WorkflowModel(
            workflow="order_workflow",
            host=SHOP,
            initial_state="created",
            states=["created"],
            terminal_states=[],
            actions=["process_payment"],
            transitions={},
            action_safety={},
        )
        assert model.safety_for("anything") == ReplaySafetyClass.PROHIBITED

    def test_workflow_model_safety_lookup(self) -> None:
        model = WorkflowModel(
            workflow="order_workflow",
            host=SHOP,
            initial_state="created",
            states=["created"],
            terminal_states=[],
            actions=["process_payment"],
            transitions={},
            action_safety={"process_payment": ReplaySafetyClass.BOUNDED},
        )
        assert model.safety_for("process_payment") == ReplaySafetyClass.BOUNDED


class TestReplaySimulator:
    @staticmethod
    def _model() -> WorkflowModel:
        return WorkflowModel(
            workflow="order_workflow",
            host=SHOP,
            initial_state="created",
            states=["created", "paid", "shipped", "delivered", "cancelled"],
            terminal_states=["delivered", "cancelled"],
            actions=ACTIONS,
            transitions={
                "submit_order": [
                    {
                        "action": "submit_order",
                        "source_state": "created",
                        "target_state": "created",
                        "prerequisites": ["created"],
                        "note": "created -> created (idempotent)",
                    }
                ],
                "process_payment": [
                    {
                        "action": "process_payment",
                        "source_state": "created",
                        "target_state": "paid",
                        "prerequisites": ["created"],
                        "note": "created -> paid",
                    }
                ],
                "ship_order": [
                    {
                        "action": "ship_order",
                        "source_state": "paid",
                        "target_state": "shipped",
                        "prerequisites": ["paid"],
                        "note": "paid -> shipped",
                    }
                ],
                "confirm_delivery": [
                    {
                        "action": "confirm_delivery",
                        "source_state": "shipped",
                        "target_state": "delivered",
                        "prerequisites": ["shipped"],
                        "note": "shipped -> delivered",
                    }
                ],
                "cancel_order": [
                    {
                        "action": "cancel_order",
                        "source_state": "created",
                        "target_state": "cancelled",
                        "prerequisites": ["created"],
                        "note": "created -> cancelled",
                    }
                ],
            },
            action_safety={
                "submit_order": ReplaySafetyClass.PASSIVE,
                "process_payment": ReplaySafetyClass.BOUNDED,
                "ship_order": ReplaySafetyClass.BOUNDED,
                "confirm_delivery": ReplaySafetyClass.PASSIVE,
                "cancel_order": ReplaySafetyClass.BOUNDED,
            },
        )

    def test_step_success(self) -> None:
        step = ReplaySimulator(self._model()).step("process_payment", "created")
        assert step.result == TransitionResult.SUCCESS
        assert step.target_state == "paid"
        assert step.safety_class == ReplaySafetyClass.BOUNDED

    def test_step_unexpected_transition(self) -> None:
        step = ReplaySimulator(self._model()).step(
            "ship_order", "paid", observed_target="cancelled"
        )
        assert step.result == TransitionResult.UNEXPECTED_TRANSITION
        assert step.target_state == "cancelled"

    def test_step_missing_prerequisite(self) -> None:
        step = ReplaySimulator(self._model()).step("ship_order", "created")
        assert step.result == TransitionResult.MISSING_PREREQUISITE
        assert step.note is not None

    def test_step_terminal(self) -> None:
        step = ReplaySimulator(self._model()).step("process_payment", "cancelled")
        assert step.result == TransitionResult.TERMINAL

    def test_step_unknown_action(self) -> None:
        step = ReplaySimulator(self._model()).step("refund_order", "created")
        assert step.result == TransitionResult.UNKNOWN_ACTION

    def test_step_repeated(self) -> None:
        step = ReplaySimulator(self._model()).step("submit_order", "created")
        assert step.result == TransitionResult.REPEATED

    def test_replay_short_circuits_terminal(self) -> None:
        steps = ReplaySimulator(self._model()).replay(
            ["process_payment", "ship_order", "confirm_delivery", "cancel_order"], "created"
        )
        results = [s.result for s in steps]
        assert results[-1] == TransitionResult.TERMINAL
        assert len(steps) == 4

    def test_replay_rejects_prohibited(self) -> None:
        model = WorkflowModel(
            workflow="order_workflow",
            host=SHOP,
            initial_state="created",
            states=["created"],
            terminal_states=[],
            actions=ACTIONS,
            transitions={},
            action_safety={"cancel_order": ReplaySafetyClass.PROHIBITED},
        )
        with pytest.raises(ValueError, match="PROHIBITED"):
            ReplaySimulator(model).replay(["cancel_order"], "created")

    def test_replay_respects_max_sequence_length(self) -> None:
        steps = ReplaySimulator(self._model()).replay(
            ["process_payment", "ship_order", "cancel_order"], "created", max_sequence_length=2
        )
        assert len(steps) == 2

    def test_replay_observed_target_injection(self) -> None:
        steps = ReplaySimulator(self._model()).replay(
            ["process_payment", "ship_order", "cancel_order"],
            "created",
            observed_targets=[None, "delivered", None],
        )
        assert steps[1].result == TransitionResult.UNEXPECTED_TRANSITION
        assert steps[1].target_state == "delivered"


# --------------------------------------------------------------------------- #
# 2. Capability metadata & registration
# --------------------------------------------------------------------------- #
class TestBusinessLogicCapabilities:
    def test_capability_ids(self) -> None:
        expected = [
            "business_logic.workflow_discovery",
            "business_logic.workflow_modeling",
            "business_logic.state_transition_analysis",
            "business_logic.business_rule_analysis",
            "business_logic.ownership_analysis",
            "business_logic.role_boundary_analysis",
            "business_logic.workflow_consistency_analysis",
            "business_logic.controlled_workflow_replay",
            "business_logic.business_logic_hypothesis",
            "business_logic.business_logic_validation",
            "business_logic.workflow_evidence_collection",
        ]
        assert expected == BUSINESS_LOGIC_CAPABILITY_IDS
        assert len(set(BUSINESS_LOGIC_CAPABILITY_IDS)) == 11

    def test_meta_count_and_registration(self) -> None:
        meta = build_business_logic_meta()
        assert len(meta) == 11
        registry = CapabilityRegistry()
        registry.register_defaults()
        for cap in build_recon_capabilities():
            registry.register(cap)
        for cap in build_webapi_capabilities():
            registry.register(cap)
        for cap in build_auth_capabilities():
            registry.register(cap)
        assert len(registry.list_capabilities()) == 28
        for capability in build_business_logic_capabilities():
            if not registry.has(capability.capability_id):
                registry.register(capability)
        assert len(registry.list_capabilities()) == 39

    def test_risk_levels(self) -> None:
        medium_risk = {
            "business_logic.controlled_workflow_replay",
            "business_logic.business_logic_hypothesis",
            "business_logic.business_logic_validation",
            "business_logic.workflow_evidence_collection",
        }
        by_id = {m.id: m for m in build_business_logic_meta()}
        for cap_id in by_id:
            if cap_id in medium_risk:
                assert by_id[cap_id].risk_level == RiskLevel.MEDIUM, cap_id
            else:
                assert by_id[cap_id].risk_level == RiskLevel.LOW, cap_id

    def test_world_model_flag(self) -> None:
        assert all(m.world_model for m in build_business_logic_meta())

    def test_produced_kinds(self) -> None:
        by_id = {m.id: m for m in build_business_logic_meta()}
        assert by_id["business_logic.workflow_discovery"].produces == [
            BusinessObservationKind.WORKFLOW
        ]
        assert by_id["business_logic.state_transition_analysis"].produces == [
            BusinessObservationKind.STATE_TRANSITION
        ]
        assert by_id["business_logic.business_logic_validation"].produces == [
            BusinessObservationKind.BUSINESS_LOGIC_VALIDATION
        ]


# --------------------------------------------------------------------------- #
# 3. Mock transport
# --------------------------------------------------------------------------- #
class TestMockBusinessLogicTransport:
    def test_discover_workflows(self, engine_and_stores: tuple) -> None:
        engine, _, _ = engine_and_stores
        result = engine.discover_workflows(_request(scope=_shop_scope()), SHOP)
        assert result.status == BusinessLogicStatus.SUCCESS
        assert result.observation_count == 1
        obs = result.observations[0]
        assert obs.kind == "workflow"
        assert obs.workflow == "order_workflow"
        assert obs.host == SHOP
        assert set(obs.state_names) == {
            "created",
            "paid",
            "shipped",
            "delivered",
            "cancelled",
        }
        assert set(obs.action_names) == set(ACTIONS)

    def test_model_workflow(self) -> None:
        engine, _, _ = _engine()
        result = engine.model_workflow(_request(scope=_shop_scope()), SHOP)
        assert result.status == BusinessLogicStatus.SUCCESS
        assert result.observation_count == 5
        assert all(o.kind == "state" for o in result.observations)
        states = {o.state: o for o in result.observations}
        assert states["created"].initial is True
        assert states["delivered"].terminal is True
        assert states["cancelled"].terminal is True
        assert set(states["shipped"].allowed_roles) == {"admin", "warehouse"}

    def test_analyze_state_transitions(self) -> None:
        engine, _, _ = _engine()
        result = engine.analyze_state_transitions(_request(scope=_shop_scope()), SHOP)
        assert result.observation_count == 6
        anomalous = [o for o in result.observations if o.anomalous]
        assert len(anomalous) == 1
        assert anomalous[0].action == "ship_order"
        assert anomalous[0].source_state == "created"
        assert anomalous[0].target_state == "shipped"

    def test_analyze_business_rules(self) -> None:
        engine, _, _ = _engine()
        result = engine.analyze_business_rules(_request(scope=_shop_scope()), SHOP)
        assert result.observation_count == 3
        rules = {o.rule: o for o in result.observations}
        assert rules["only_paid_orders_ship"].enforcement == "broken"
        assert rules["no_post_shipment_cancel"].enforcement == "enforced"
        assert rules["payment_requires_created"].enforcement == "enforced"

    def test_analyze_ownership(self) -> None:
        engine, _, _ = _engine()
        result = engine.analyze_ownership(
            _request(scope=_shop_scope(), test_identities=["alice", "bob"]), SHOP
        )
        assert result.observation_count == 3
        owners = {(o.resource, o.owner) for o in result.observations}
        assert owners == {
            ("order-1001", "alice"),
            ("order-1002", "bob"),
            ("order-2001", "alice"),
        }

    def test_analyze_role_boundaries(self) -> None:
        engine, _, _ = _engine()
        result = engine.analyze_role_boundaries(
            _request(scope=_shop_scope(), test_identities=["customer"]),
            SHOP,
            test_identities=["customer"],
        )
        assert result.observation_count == 5
        assert all(o.role == "customer" for o in result.observations)
        assert all(o.consistent for o in result.observations)
        ship = next(o for o in result.observations if o.action == "ship_order")
        assert ship.allowed is False and ship.expected is False

    def test_check_workflow_consistency(self) -> None:
        engine, _, _ = _engine()
        result = engine.check_workflow_consistency(_request(scope=_shop_scope()), SHOP)
        assert result.observation_count == 3
        by_invariant = {o.invariant: o.status for o in result.observations}
        assert by_invariant["only_paid_orders_ship"] == "violated"
        assert by_invariant["no_post_shipment_cancel"] == "consistent"
        assert by_invariant["payment_requires_created"] == "consistent"

    def test_replay_workflow(self) -> None:
        engine, _, _ = _engine()
        result = engine.replay_workflow(
            _request(scope=_shop_scope()),
            SHOP,
            actions=["process_payment", "ship_order", "cancel_order"],
            start_state="created",
        )
        assert result.observation_count == 3
        assert [o.result for o in result.observations] == [
            TransitionResult.SUCCESS,
            TransitionResult.SUCCESS,
            TransitionResult.MISSING_PREREQUISITE,
        ]

    def test_hypothesize_business_logic(self) -> None:
        engine, _, _ = _engine()
        result = engine.hypothesize_business_logic(_request(scope=_shop_scope()), SHOP)
        assert result.observation_count == 3
        outcomes = {o.hypothesis: o.outcome for o in result.observations}
        assert outcomes["cancel_after_payment"] == HypothesisOutcome.SUPPORTED
        assert outcomes["cancel_after_shipping"] == HypothesisOutcome.REFUTED
        assert outcomes["cancel_ambiguous_order"] == HypothesisOutcome.INCONCLUSIVE

    def test_validate_business_logic(self) -> None:
        engine, _, _ = _engine()
        result = engine.validate_business_logic(_request(scope=_shop_scope()), SHOP)
        assert result.observation_count == 3
        outcomes = {o.hypothesis: o.result for o in result.observations}
        assert outcomes["cancel_after_payment"] == ValidationResult.VALIDATED
        assert outcomes["cancel_after_shipping"] == ValidationResult.INVALIDATED
        assert outcomes["cancel_ambiguous_order"] == ValidationResult.UNVERIFIABLE

    def test_collect_workflow_evidence(self) -> None:
        engine, _, _ = _engine()
        result = engine.collect_workflow_evidence(_request(scope=_shop_scope()), SHOP)
        assert result.status == BusinessLogicStatus.SUCCESS
        assert result.observation_count == 1
        assert result.observations[0].kind == "workflow"

    def test_error_hosts(self) -> None:
        engine, _, _ = _engine()
        expected = {
            "throttled.example.com": BusinessLogicStatus.RATE_LIMITED,
            "unreachable.example.com": BusinessLogicStatus.REQUEST_FAILED,
            "slow.example.com": BusinessLogicStatus.TIMEOUT,
            "malformed.example.com": BusinessLogicStatus.MALFORMED_RESPONSE,
            "elsewhere.example.com": BusinessLogicStatus.REQUEST_FAILED,
        }
        scope = _scope(allowed_targets=list(expected))
        for target, status in expected.items():
            result = engine.discover_workflows(_request(scope=scope), target)
            assert result.status == status, target
            assert result.observation_count == 0


# --------------------------------------------------------------------------- #
# 4. Redaction
# --------------------------------------------------------------------------- #
class TestBusinessLogicRedaction:
    def test_credential_like_keys_redacted(self) -> None:
        doc = {"credential_value": "secret", "owner": "alice", "nested": {"token": "x"}}
        out = redact_credential_fields(doc)
        assert out["credential_value"] == "REDACTED"
        assert out["owner"] == "alice"
        assert out["nested"]["token"] == "REDACTED"

    def test_nested_credential_values_forced(self) -> None:
        doc = {"meta": {"credential_value": "supersecret"}, "note": "keep"}
        out = redact_nested_credential_values(doc)
        assert out["meta"]["credential_value"] == "REDACTED"
        assert out["note"] == "keep"

    def test_stable_marker(self) -> None:
        assert credential_value_redacted() == "REDACTED"
        assert credential_value_redacted() == "REDACTED"

    def test_re_exports_from_webapi(self) -> None:
        assert webapi_redaction.redact_document is not None
        assert webapi_redaction.redact_secret is not None


# --------------------------------------------------------------------------- #
# 5. Normalization adapters
# --------------------------------------------------------------------------- #
class TestBusinessLogicNormalizationAdapters:
    def test_adapter_lookup(self) -> None:
        assert adapter_for_tool("discover_workflows").tool == "discover_workflows"
        assert adapter_for_tool("model_workflow").tool == "model_workflow"
        assert adapter_for_tool("replay_workflow").tool == "replay_workflow"
        assert adapter_for_tool("validate_business_logic").tool == "validate_business_logic"

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(BusinessLogicNormalizationError):
            adapter_for_tool("discover_workflows").adapt("{not json", context={})

    def test_workflow_adapter(self) -> None:
        raw = {
            "tool": "discover_workflows",
            "mode": "active",
            "target": SHOP,
            "host": SHOP,
            "observed_url": f"https://{SHOP}/",
            "workflow": "order_workflow",
            "state_names": ["created"],
            "action_names": ["submit_order"],
        }
        out = adapter_for_tool("discover_workflows").adapt(
            json.dumps(raw), context={"target": SHOP, "mode": BusinessLogicMode.ACTIVE}
        )
        assert out.observations[0].kind == "workflow"
        assert out.observations[0].host == SHOP

    def test_replay_adapter(self) -> None:
        raw = {
            "tool": "replay_workflow",
            "mode": "active",
            "target": SHOP,
            "host": SHOP,
            "observed_url": f"https://{SHOP}/",
            "workflow": "order_workflow",
            "start_state": "created",
            "requested_actions": ["process_payment"],
            "replay": [
                {
                    "action": "process_payment",
                    "source_state": "created",
                    "target_state": "paid",
                    "result": "success",
                    "safety_class": "bounded",
                    "sequence_length": 1,
                    "note": "created -> paid",
                }
            ],
        }
        out = adapter_for_tool("replay_workflow").adapt(
            json.dumps(raw), context={"target": SHOP, "mode": BusinessLogicMode.ACTIVE}
        )
        assert out.observations[0].result == TransitionResult.SUCCESS
        assert out.observations[0].safety_class == ReplaySafetyClass.BOUNDED

    def test_replay_rejected_becomes_warning(self) -> None:
        raw = {
            "tool": "replay_workflow",
            "mode": "active",
            "target": SHOP,
            "host": SHOP,
            "observed_url": f"https://{SHOP}/",
            "workflow": "order_workflow",
            "error": {"kind": "replay_rejected", "message": "no"},
            "note": "replay rejected",
            "replay": [],
        }
        out = adapter_for_tool("replay_workflow").adapt(
            json.dumps(raw), context={"target": SHOP, "mode": BusinessLogicMode.ACTIVE}
        )
        assert out.observations == []
        assert out.warnings == ["no"]

    def test_error_adapter(self) -> None:
        raw = json.dumps(
            {
                "tool": "discover_workflows",
                "mode": "active",
                "target": "unreachable.example.com",
                "host": "unreachable.example.com",
                "error": {"kind": "connection_refused", "message": "connection refused"},
            }
        )
        out = adapter_for_tool("discover_workflows").adapt(
            raw, context={"target": "unreachable.example.com", "mode": BusinessLogicMode.ACTIVE}
        )
        assert out.observations == []
        assert out.error == {"kind": "connection_refused", "message": "connection refused"}


# --------------------------------------------------------------------------- #
# 6. Confidence & evidence policy
# --------------------------------------------------------------------------- #
class TestBusinessLogicConfidencePolicy:
    def test_passive_is_low(self) -> None:
        engine, _, _ = _engine()
        result = engine.discover_workflows(
            _request(scope=_shop_scope(), mode=BusinessLogicMode.PASSIVE), SHOP
        )
        assert all(
            observation_confidence(o, BusinessLogicMode.PASSIVE) == Confidence.LOW
            for o in result.observations
        )

    def test_direct_active_is_high(self) -> None:
        adapter = adapter_for_tool("model_workflow")
        raw = {
            "tool": "model_workflow",
            "mode": "active",
            "target": SHOP,
            "host": SHOP,
            "observed_url": f"https://{SHOP}/",
            "workflow": "order_workflow",
            "states": [{"state": "created", "initial": True, "allowed_roles": []}],
        }
        out = adapter.adapt(
            json.dumps(raw), context={"target": SHOP, "mode": BusinessLogicMode.ACTIVE}
        )
        assert (
            observation_confidence(out.observations[0], BusinessLogicMode.ACTIVE)
            == Confidence.HIGH
        )

    def test_derived_is_medium(self) -> None:
        obs = {
            "kind": "ownership",
            "url": f"https://{SHOP}/",
            "host": SHOP,
            "workflow": "order_workflow",
            "resource": "orders",
            "owner": "alice",
        }
        holder = BuildObservation(obs)
        assert (
            observation_confidence(holder.build_ownership(), BusinessLogicMode.ACTIVE)
            == Confidence.MEDIUM
        )

    def test_hypothesis_is_low(self) -> None:
        obs = BuildObservation(
            {
                "kind": "business_logic_hypothesis",
                "url": f"https://{SHOP}/",
                "host": SHOP,
                "workflow": "order_workflow",
                "hypothesis": "cancel_after_payment",
                "outcome": "supported",
            }
        ).build_hypothesis()
        assert observation_confidence(obs, BusinessLogicMode.ACTIVE) == Confidence.LOW

    def test_validation_high_only_when_validated(self) -> None:
        def obs(result: ValidationResult) -> BusinessLogicValidationObservation:
            return BusinessLogicValidationObservation(
                kind="business_logic_validation",
                url=f"https://{SHOP}/",
                host=SHOP,
                workflow="order_workflow",
                hypothesis="cancel_after_payment",
                result=result,
            )

        assert (
            observation_confidence(obs(ValidationResult.VALIDATED), BusinessLogicMode.ACTIVE)
            == Confidence.HIGH
        )
        assert (
            observation_confidence(
                obs(ValidationResult.INVALIDATED), BusinessLogicMode.ACTIVE
            )
            == Confidence.LOW
        )
        assert (
            observation_confidence(
                obs(ValidationResult.UNVERIFIABLE), BusinessLogicMode.ACTIVE
            )
            == Confidence.LOW
        )


class BuildObservation:
    """Small factory helpers so confidence tests need no raw transport."""

    def __init__(self, values: dict) -> None:
        self._values = values

    def build_ownership(self):
        from blackforge.business_logic.models import OwnershipObservation

        return OwnershipObservation(**self._values)

    def build_hypothesis(self) -> BusinessLogicHypothesisObservation:
        return BusinessLogicHypothesisObservation(**self._values)


class TestBusinessLogicEvidence:
    def test_artifact_evidence(self) -> None:
        evidence = artifact_evidence(
            MID, SHOP, "business_logic.workflow_discovery", '{"workflow": "order_workflow"}'
        )
        assert evidence.evidence_type == EvidenceType.ARTIFACT
        assert evidence.status == EvidenceStatus.OBSERVED
        assert evidence.confidence == Confidence.HIGH
        assert evidence.provenance.provenance_type == ProvenanceType.DIRECT

    def test_observation_evidence_statuses(self) -> None:
        from blackforge.business_logic.models import (
            BusinessRuleObservation,
            StateTransitionObservation,
            WorkflowConsistencyObservation,
        )

        rule = BusinessRuleObservation(
            kind="business_rule",
            url=f"https://{SHOP}/",
            host=SHOP,
            workflow="order_workflow",
            rule="only_paid_orders_ship",
            enforcement="broken",
            observed=True,
        )
        tr = StateTransitionObservation(
            kind="state_transition",
            url=f"https://{SHOP}/",
            host=SHOP,
            workflow="order_workflow",
            action="ship_order",
            source_state="created",
            target_state="shipped",
            anomalous=True,
        )
        inv = WorkflowConsistencyObservation(
            kind="workflow_consistency",
            url=f"https://{SHOP}/",
            host=SHOP,
            workflow="order_workflow",
            invariant="only_paid_orders_ship",
            status="violated",
        )
        normal = StateTransitionObservation(
            kind="state_transition",
            url=f"https://{SHOP}/",
            host=SHOP,
            workflow="order_workflow",
            action="process_payment",
            source_state="created",
            target_state="paid",
        )
        for observation, expected in [
            (rule, EvidenceStatus.INFERRED),
            (tr, EvidenceStatus.INFERRED),
            (inv, EvidenceStatus.INFERRED),
            (normal, EvidenceStatus.OBSERVED),
        ]:
            evidence = observation_evidence(
                MID, SHOP, "business_logic.state_transition_analysis", observation
            )
            assert evidence.status == expected, observation.kind

    def test_observation_summary_and_reference(self) -> None:
        engine, _, _ = _engine()
        result = engine.discover_workflows(_request(scope=_shop_scope()), SHOP)
        observation = result.observations[0]
        assert observation_summary(observation).startswith("Workflow")
        assert observation_reference(observation) == f"https://{SHOP}/"

    def test_evidence_dedup_key_stable(self) -> None:
        engine, _, _ = _engine()
        result = engine.discover_workflows(_request(scope=_shop_scope()), SHOP)
        evidence = observation_evidence(
            MID, SHOP, "business_logic.workflow_discovery", result.observations[0]
        )
        assert evidence_dedup_key_for(evidence) == evidence_dedup_key_for(evidence)


# --------------------------------------------------------------------------- #
# 7. Engine end-to-end pipeline
# --------------------------------------------------------------------------- #
class TestBusinessLogicEnginePipeline:
    def _pipeline(self) -> BusinessLogicEngine:
        engine, _, _ = _engine()
        return engine

    def test_scenario_a_normal_workflow(self) -> None:
        engine = self._pipeline()
        model = engine.model_workflow(_ident_req(), SHOP)
        assert model.status == BusinessLogicStatus.SUCCESS
        assert model.observation_count == 5
        assert all(o.kind == "state" for o in model.observations)

    def test_scenario_b_anomalous_transition(self) -> None:
        engine, evidence, world = _engine()
        req = _ident_req()
        transitions = engine.analyze_state_transitions(req, SHOP)
        assert any(o.anomalous for o in transitions.observations)
        assert transitions.evidence_ids, "evidence must be persisted for observations"

        rules = engine.analyze_business_rules(req, SHOP)
        broken = next(o for o in rules.observations if o.rule == "only_paid_orders_ship")
        assert broken.enforcement == "broken"

        consistency = engine.check_workflow_consistency(req, SHOP)
        violated = next(
            o for o in consistency.observations if o.invariant == "only_paid_orders_ship"
        )
        assert violated.status == "violated"

        if evidence is not None:
            stored = evidence.list(limit=1000)
            inferred = [e for e in stored if e.status == EvidenceStatus.INFERRED]
            assert len(inferred) >= 1
        if world is not None:
            workflow = next(
                w
                for w in world.list_entities(
                    WorldQuery(mission_id=MID, entity_type=EntityType.WORKFLOW)
                )
                if w.lifecycle == WorldLifecycle.ACTIVE
            )
            assertions = world.list_assertions(str(workflow.id))
            assert any(
                "transition_violation" in a.property_key or "violated" in a.property_key
                for a in assertions
            )

    def test_scenario_c_ownership(self) -> None:
        engine = self._pipeline()
        result = engine.analyze_ownership(
            _ident_req(), SHOP, test_identities=["alice", "bob"]
        )
        assert result.status == BusinessLogicStatus.SUCCESS
        assert all(o.controlled for o in result.observations)
        assert all(o.owner in {"alice", "bob"} for o in result.observations)

    def test_scenario_d_role_boundaries(self) -> None:
        engine, evidence, _ = _engine()
        result = engine.analyze_role_boundaries(
            _ident_req(), SHOP, test_identities=["customer"]
        )
        assert result.status == BusinessLogicStatus.SUCCESS
        assert result.observation_count == 5
        assert all(o.consistent for o in result.observations)
        assert len(result.evidence_ids) == 1 + result.observation_count

    def test_scenario_e_controlled_replay(self) -> None:
        engine = self._pipeline()
        req = _ident_req()
        result = engine.replay_workflow(
            req, SHOP, actions=["process_payment", "ship_order"], start_state="created"
        )
        assert result.observation_count == 2
        assert all(o.result == TransitionResult.SUCCESS for o in result.observations)

    def test_scenario_f_hypothesis_and_validation(self) -> None:
        engine, evidence, _ = _engine()
        req = _ident_req()
        hypotheses = engine.hypothesize_business_logic(req, SHOP)
        assert hypotheses.observation_count == 3
        validations = engine.validate_business_logic(req, SHOP)
        assert validations.observation_count == 3
        assert evidence is not None
        stored = evidence.list(limit=1000)
        statuses = {e.status.value for e in stored}
        assert "hypothesized" in statuses
        assert "validated" in statuses

    def test_evidence_persisted_with_derived_from(self) -> None:
        engine, evidence, _ = _engine()
        req = _ident_req()
        result = engine.analyze_business_rules(req, SHOP)
        assert len(result.evidence_ids) == 4
        assert evidence is not None
        artifact = evidence.get(result.evidence_ids[0])
        assert artifact is not None and artifact.evidence_type == EvidenceType.ARTIFACT
        relations = evidence.get_relationships(result.evidence_ids[1])
        assert any(rel.relation_type.value == "derived_from" for rel in relations)

    def test_world_model_materialization(self) -> None:
        engine, _, world = _engine()
        req = _ident_req()
        engine.discover_workflows(req, SHOP)
        engine.model_workflow(req, SHOP)
        engine.analyze_state_transitions(req, SHOP)
        engine.analyze_business_rules(req, SHOP)
        engine.analyze_ownership(req, SHOP)
        engine.analyze_role_boundaries(req, SHOP, test_identities=["customer"])
        engine.check_workflow_consistency(req, SHOP)
        engine.replay_workflow(
            req, SHOP, actions=["process_payment", "ship_order"], start_state="created"
        )
        engine.hypothesize_business_logic(req, SHOP)
        engine.validate_business_logic(req, SHOP)
        assert world is not None
        entities = world.list_entities(WorldQuery(mission_id=MID, limit=1000))
        kinds = {e.entity_type for e in entities}
        assert EntityType.WORKFLOW in kinds
        assert EntityType.BUSINESS_STATE in kinds
        assert EntityType.BUSINESS_ACTION in kinds
        assert EntityType.IDENTITY in kinds
        relationships = world.list_relationships(RelationshipQuery(mission_id=MID, limit=1000))
        rel_kinds = {r.relationship_type.value for r in relationships}
        assert "has_workflow" in rel_kinds
        assert "has_state" in rel_kinds
        assert "has_action" in rel_kinds
        assert "transitions_to" in rel_kinds
        assert "operates_on" in rel_kinds
        workflow = next(
            e
            for e in entities
            if e.entity_type == EntityType.WORKFLOW and e.lifecycle == WorldLifecycle.ACTIVE
        )
        assertions = world.list_assertions(str(workflow.id))
        prop_prefixes = {a.property_key.split(".")[0] for a in assertions}
        assert {"rule", "invariant", "replay", "hypothesis", "validation"} <= prop_prefixes
        statuses = {a.epistemic_status for a in assertions}
        assert EvidenceStatus.VALIDATED in statuses

    def test_run_dispatcher(self) -> None:
        engine = self._pipeline()
        result = engine.run(
            _ident_req(), "business_logic.workflow_discovery", SHOP
        )
        assert result.status == BusinessLogicStatus.SUCCESS
        assert result.capability_id == "business_logic.workflow_discovery"
        with pytest.raises(BusinessLogicExecutionError):
            engine.run(_ident_req(), "business_logic.nonexistent", SHOP)

    def test_sqlite_persistence(self, tmp_path) -> None:
        from blackforge.evidence.repository import SQLiteEvidenceRepository
        from blackforge.world_model.repository import SQLiteWorldRepository

        evidence = EvidenceStore(repository=SQLiteEvidenceRepository(str(tmp_path / "bl_ev.db")))
        world = WorldModelStore(repository=SQLiteWorldRepository(str(tmp_path / "bl_wm.db")))
        engine = BusinessLogicEngine(
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        result = engine.model_workflow(_ident_req(), SHOP)
        assert result.observation_count == 5
        stored = evidence.list(limit=1000)
        assert len(stored) == 1 + result.observation_count
        entities = world.list_entities(WorldQuery(mission_id=MID, limit=1000))
        assert len(entities) >= 6


# --------------------------------------------------------------------------- #
# 8. Status mapping
# --------------------------------------------------------------------------- #
class TestBusinessLogicStatusMapping:
    def test_error_host_statuses(self) -> None:
        engine, _, _ = _engine()
        scope = _scope(
            allowed_targets=[SHOP, "throttled.example.com", "unreachable.example.com"]
        )
        req = _request(scope=scope)
        assert (
            engine.discover_workflows(req, "throttled.example.com").status
            == BusinessLogicStatus.RATE_LIMITED
        )
        assert (
            engine.discover_workflows(req, "unreachable.example.com").status
            == BusinessLogicStatus.REQUEST_FAILED
        )

    def test_out_of_scope_raises(self) -> None:
        engine, _, _ = _engine()
        req = _request(scope=_shop_scope())
        with pytest.raises(AuthorizationError):
            engine.discover_workflows(req, "unreachable.example.com")

    def test_risk_limit_exceeded(self) -> None:
        engine, _, _ = _engine()
        scope = _scope(allowed_targets=[SHOP], max_risk_level=RiskLevel.LOW)
        req = _request(scope=scope)
        result = engine.replay_workflow(
            req, SHOP, actions=["process_payment"], start_state="created"
        )
        assert result.status == BusinessLogicStatus.SUCCESS
        high = AuthorizationBoundary(mode="strict").authorize(
            mission_id=MID,
            scope=scope,
            capability_name="business_logic.workflow_modeling",
            target_value=SHOP,
            risk_level=RiskLevel.HIGH,
        )
        assert high.value == "requires_approval"


# --------------------------------------------------------------------------- #
# 9. Engine safety & authorization
# --------------------------------------------------------------------------- #
class TestBusinessLogicEngineSafety:
    def test_control_replay_identities_fail_closed(self) -> None:
        engine, _, _ = _engine()
        req = _request(scope=_shop_scope(), test_identities=[])
        with pytest.raises(BusinessLogicExecutionError, match="test identities"):
            engine.analyze_ownership(req, SHOP)
        with pytest.raises(BusinessLogicExecutionError, match="test identities"):
            engine.analyze_role_boundaries(req, SHOP)

    def test_unauthorized_supplied_identities(self) -> None:
        engine, _, _ = _engine()
        req = _request(scope=_shop_scope(), test_identities=["alice"])
        with pytest.raises(BusinessLogicExecutionError, match="not authorized"):
            engine.analyze_ownership(req, SHOP, test_identities=["mallory"])

    def test_authorized_identities_pass(self) -> None:
        engine, _, _ = _engine()
        req = _request(scope=_shop_scope(), test_identities=["alice", "bob"])
        result = engine.analyze_ownership(req, SHOP, test_identities=["alice"])
        assert result.status == BusinessLogicStatus.SUCCESS

    def test_replay_prohibited_action_fail_closed(self) -> None:
        engine, _, _ = _engine()
        req = _ident_req()
        with pytest.raises(BusinessLogicExecutionError, match="PROHIBITED"):
            engine.replay_workflow(req, SHOP, actions=["refund_order"], start_state="created")

    def test_validation_replay_safety_fail_closed(self) -> None:
        engine, _, _ = _engine()
        req = _ident_req()
        with pytest.raises(BusinessLogicExecutionError, match="PROHIBITED"):
            engine.validate_business_logic(req, SHOP, actions=["refund_order"])

    def test_validation_on_unreachable_reports_failed(self) -> None:
        engine, _, _ = _engine()
        req = _request(scope=_scope(allowed_targets=["unreachable.example.com"]))
        result = engine.validate_business_logic(req, "unreachable.example.com")
        assert result.status == BusinessLogicStatus.REQUEST_FAILED

    def test_passive_mode_request(self) -> None:
        engine, _, _ = _engine()
        result = engine.discover_workflows(
            _request(scope=_shop_scope(), mode=BusinessLogicMode.PASSIVE), SHOP
        )
        assert result.mode == BusinessLogicMode.PASSIVE
        assert result.status == BusinessLogicStatus.SUCCESS


# --------------------------------------------------------------------------- #
# 10. Evidence elevation through validation
# --------------------------------------------------------------------------- #
class TestBusinessLogicValidationElevation:
    def test_validated_evidence_only_from_validation(self) -> None:
        engine, evidence, _ = _engine()
        req = _ident_req()
        engine.analyze_business_rules(req, SHOP)
        before = evidence.list(limit=1000)
        assert all(e.status != EvidenceStatus.VALIDATED for e in before)
        engine.validate_business_logic(req, SHOP)
        after = evidence.list(limit=1000)
        assert any(e.status == EvidenceStatus.VALIDATED for e in after)

    def test_hypothesis_evidence_is_hypothesized(self) -> None:
        engine, evidence, _ = _engine()
        req = _ident_req()
        engine.hypothesize_business_logic(req, SHOP)
        stored = evidence.list(limit=1000)
        assert any(e.status == EvidenceStatus.HYPOTHESIZED for e in stored)
        assert all(
            e.status != EvidenceStatus.VALIDATED for e in stored
        )


# --------------------------------------------------------------------------- #
# 11. Deduplication & idempotency
# --------------------------------------------------------------------------- #
class TestBusinessLogicDedup:
    def test_repeat_run_does_not_duplicate_evidence(self) -> None:
        engine, evidence, _ = _engine()
        req = _ident_req()
        first = engine.model_workflow(req, SHOP)
        assert len(first.evidence_ids) == 6
        engine.model_workflow(req, SHOP)
        stored = evidence.list(limit=1000)
        assert len(stored) == 6

    def test_dedup_via_existing_evidence_id(self) -> None:
        engine, evidence, _ = _engine()
        req = _ident_req()
        first = engine.analyze_state_transitions(req, SHOP)
        second = engine.analyze_state_transitions(req, SHOP)
        assert first.evidence_ids == second.evidence_ids


# --------------------------------------------------------------------------- #
# 12. Package assembly & capability registry
# --------------------------------------------------------------------------- #
class TestBusinessLogicPackageAssembly:
    def test_module_exports(self) -> None:
        import blackforge.business_logic as bl

        assert bl.BusinessLogicEngine is not None
        assert bl.MockBusinessLogicTransport is not None
        assert len(bl.BUSINESS_LOGIC_CAPABILITY_IDS) == 11
        for name in (
            "BusinessLogicCapability",
            "BusinessLogicMode",
            "BusinessLogicRequest",
            "BusinessLogicResult",
            "Observation",
        ):
            assert hasattr(bl, name), name

    def test_all_capabilities_present_in_engine(self) -> None:
        engine, _, _ = _engine()
        capabilities = {c.capability_id for c in engine.capabilities}
        assert capabilities == set(BUSINESS_LOGIC_CAPABILITY_IDS)

    def test_auth_and_business_logic_engines_coexist(self, tmp_path) -> None:
        from blackforge.auth.models import AuthMode, AuthRequest

        evidence = EvidenceStore(repository=InMemoryEvidenceRepository())
        world = WorldModelStore(repository=InMemoryWorldRepository())
        registry = CapabilityRegistry()
        registry.register_defaults()
        for cap in build_recon_capabilities():
            registry.register(cap)
        for cap in build_webapi_capabilities():
            registry.register(cap)
        auth_engine = AuthEngine(
            capability_registry=registry,
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        bl_engine = BusinessLogicEngine(
            capability_registry=registry,
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        assert len(registry.list_capabilities()) == 39
        scope = _scope(allowed_targets=[SHOP])
        auth_result = auth_engine.observe_authentication_surface(
            AuthRequest(
                mission_id=MID,
                scope=scope,
                session_id=SID,
                mode=AuthMode.ACTIVE,
                test_identities=["alice"],
            ),
            SHOP,
        )
        assert auth_result.status.value == "success"
        bl_result = bl_engine.discover_workflows(
            _request(scope=scope, test_identities=["alice"]), SHOP
        )
        assert bl_result.status == BusinessLogicStatus.SUCCESS
        assert evidence.list(limit=1000)


@pytest.fixture
def engine_and_stores() -> tuple[BusinessLogicEngine, EvidenceStore | None, WorldModelStore | None]:
    return _engine()
