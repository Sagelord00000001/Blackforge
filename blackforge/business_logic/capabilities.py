from __future__ import annotations

from pydantic import Field

from blackforge.business_logic.models import BusinessLogicMode, BusinessObservationKind
from blackforge.business_logic.normalization import (
    BusinessRuleAdapter,
    BusinessToolAdapter,
    HypothesisAdapter,
    OwnershipAdapter,
    RoleBoundaryAdapter,
    StateTransitionAdapter,
    ValidationAdapter,
    WorkflowConsistencyAdapter,
    WorkflowDiscoveryAdapter,
    WorkflowEvidenceAdapter,
    WorkflowModelingAdapter,
    WorkflowReplayAdapter,
)
from blackforge.business_logic.transport import MockBusinessLogicTransport
from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType

BUSINESS_LOGIC_CAPABILITY_IDS = [
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


class BusinessLogicCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for business logic capabilities."""

    category: str = "business_logic"
    mode: BusinessLogicMode = BusinessLogicMode.PASSIVE
    produces: list[BusinessObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    risk_level: RiskLevel,
    mode: BusinessLogicMode,
    supported_target_types: list[TargetType],
    produces: list[BusinessObservationKind],
    *,
    version: str = "1.0.0",
) -> BusinessLogicCapabilityMeta:
    return BusinessLogicCapabilityMeta(
        id=CapabilityID(capability_id),
        name=capability_id,
        description=description,
        version=version,
        risk_level=risk_level,
        authorization_required=True,
        supported_target_types=supported_target_types,
        input_schema={"target": {"type": "string"}, "params": {"type": "object"}},
        output_schema={"observations": {"type": "array"}},
        evidence_types_produced=["artifact", "observation"],
        mode=mode,
        produces=produces,
    )


def build_business_logic_meta() -> list[BusinessLogicCapabilityMeta]:
    """Metadata for all eleven typed business logic capabilities."""
    return [
        _meta(
            "business_logic.workflow_discovery",
            "Inventory business workflows exposed by the authorized target.",
            RiskLevel.LOW,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.WORKFLOW],
        ),
        _meta(
            "business_logic.workflow_modeling",
            "Model the states and lifecycle of a discovered workflow.",
            RiskLevel.LOW,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.STATE],
        ),
        _meta(
            "business_logic.state_transition_analysis",
            "Record observed state transition edges for workflow actions.",
            RiskLevel.LOW,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.STATE_TRANSITION],
        ),
        _meta(
            "business_logic.business_rule_analysis",
            "Record business rules/invariants and their observed enforcement state.",
            RiskLevel.LOW,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.BUSINESS_RULE],
        ),
        _meta(
            "business_logic.ownership_analysis",
            "Record resource ownership for explicitly authorized test identities.",
            RiskLevel.LOW,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.OWNERSHIP],
        ),
        _meta(
            "business_logic.role_boundary_analysis",
            "Compare observed role action outcomes against the modeled boundary.",
            RiskLevel.LOW,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.ROLE_BOUNDARY],
        ),
        _meta(
            "business_logic.workflow_consistency_analysis",
            "Check modeled invariants against the observed state machine.",
            RiskLevel.LOW,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.WORKFLOW_CONSISTENCY],
        ),
        _meta(
            "business_logic.controlled_workflow_replay",
            "Replay a bounded action sequence against the safety-gated paper model.",
            RiskLevel.MEDIUM,
            BusinessLogicMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.WORKFLOW_REPLAY],
        ),
        _meta(
            "business_logic.business_logic_hypothesis",
            "Form hypotheses about business logic behavior (never findings).",
            RiskLevel.MEDIUM,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.BUSINESS_LOGIC_HYPOTHESIS],
        ),
        _meta(
            "business_logic.business_logic_validation",
            "Validate a hypothesis through deterministic, bounded replay.",
            RiskLevel.MEDIUM,
            BusinessLogicMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.BUSINESS_LOGIC_VALIDATION],
        ),
        _meta(
            "business_logic.workflow_evidence_collection",
            "Harvest deterministic workflow evidence for downstream attribution.",
            RiskLevel.MEDIUM,
            BusinessLogicMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [BusinessObservationKind.WORKFLOW],
        ),
    ]


class BusinessLogicCapability(Capability):
    """A typed business logic capability bound to a mock transport method.

    ``execute`` runs the deterministic mock transport through the
    normalization adapter and returns normalized observations. It performs no
    authorization itself — the :class:`BusinessLogicEngine` enforces scope /
    authorization before any execution path reaches the mock.
    """

    def __init__(
        self,
        meta: BusinessLogicCapabilityMeta,
        tool_method: str,
        adapter: BusinessToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._transport = MockBusinessLogicTransport()

    def meta(self) -> BusinessLogicCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> BusinessToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        mode_param = params.get("mode") if params else None
        mode = BusinessLogicMode(mode_param) if mode_param else self._meta.mode
        tool_method = self._tool_method
        factory = self._transport
        if tool_method == "replay_workflow":
            raw = factory.replay_workflow(
                target,
                mode=mode,
                actions=_string_list_param(params, "actions"),
                start_state=_string_param(params, "start_state"),
                max_sequence_length=_int_param(params, "max_sequence_length", 8),
            )
        elif tool_method in {"analyze_ownership", "analyze_role_boundaries"}:
            test_identities = _string_list_param(params, "test_identities")
            raw = getattr(factory, tool_method)(
                target, mode=mode, test_identities=test_identities
            )
        else:
            raw = getattr(factory, tool_method)(target, mode=mode)
        normalized = self._adapter.adapt(raw, context={"target": target, "mode": mode})
        return CapabilityResult(
            success=True,
            output=[o.model_dump() for o in normalized.observations],
            metadata={
                "tool": tool_method,
                "mode": mode.value,
                "warnings": normalized.warnings,
                "error": normalized.error,
                "mock": True,
            },
        )


def _string_list_param(params: dict | None, key: str) -> list[str] | None:
    value = params.get(key) if params else None
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return None


def _string_param(params: dict | None, key: str) -> str | None:
    value = params.get(key) if params else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _int_param(params: dict | None, key: str, default: int) -> int:
    value = params.get(key) if params else None
    if isinstance(value, int):
        return value
    return default


def build_business_logic_capabilities() -> list[BusinessLogicCapability]:
    """Instantiate all eleven typed business logic capabilities (mock-backed)."""
    adapters = [
        WorkflowDiscoveryAdapter(),
        WorkflowModelingAdapter(),
        StateTransitionAdapter(),
        BusinessRuleAdapter(),
        OwnershipAdapter(),
        RoleBoundaryAdapter(),
        WorkflowConsistencyAdapter(),
        WorkflowReplayAdapter(),
        HypothesisAdapter(),
        ValidationAdapter(),
        WorkflowEvidenceAdapter(),
    ]
    tool_methods = [
        "discover_workflows",
        "model_workflow",
        "analyze_state_transitions",
        "analyze_business_rules",
        "analyze_ownership",
        "analyze_role_boundaries",
        "check_workflow_consistency",
        "replay_workflow",
        "hypothesize_business_logic",
        "validate_business_logic",
        "collect_workflow_evidence",
    ]
    return [
        BusinessLogicCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            build_business_logic_meta(),
            tool_methods,
            adapters,
            strict=True,
        )
    ]
