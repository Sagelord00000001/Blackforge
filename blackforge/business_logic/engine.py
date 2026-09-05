from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.business_logic.capabilities import (
    BusinessLogicCapability,
    build_business_logic_capabilities,
)
from blackforge.business_logic.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.business_logic.materializer import BusinessLogicWorldMaterializer
from blackforge.business_logic.models import (
    BusinessLogicMode,
    BusinessLogicRequest,
    BusinessLogicResult,
    BusinessLogicStatus,
    Observation,
    ReplaySafetyClass,
)
from blackforge.business_logic.transport import MockBusinessLogicTransport
from blackforge.core.errors import (
    AuthorizationError,
    BusinessLogicExecutionError,
    BusinessLogicNormalizationError,
    BusinessLogicTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.core.types import EvidenceStatus
from blackforge.evidence.models import EvidenceRelation

if TYPE_CHECKING:
    from blackforge.business_logic.normalization import BusinessToolAdapter
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.world_model.store import WorldModelStore

log = get_logger("business_logic.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "discover_workflows": "business_logic.workflow_discovery",
    "model_workflow": "business_logic.workflow_modeling",
    "analyze_state_transitions": "business_logic.state_transition_analysis",
    "analyze_business_rules": "business_logic.business_rule_analysis",
    "analyze_ownership": "business_logic.ownership_analysis",
    "analyze_role_boundaries": "business_logic.role_boundary_analysis",
    "check_workflow_consistency": "business_logic.workflow_consistency_analysis",
    "replay_workflow": "business_logic.controlled_workflow_replay",
    "hypothesize_business_logic": "business_logic.business_logic_hypothesis",
    "validate_business_logic": "business_logic.business_logic_validation",
    "collect_workflow_evidence": "business_logic.workflow_evidence_collection",
}

_ERROR_KIND_TO_STATUS: dict[str, BusinessLogicStatus] = {
    "rate_limited": BusinessLogicStatus.RATE_LIMITED,
    "unauthorized": BusinessLogicStatus.UNAUTHORIZED,
    "connection_refused": BusinessLogicStatus.REQUEST_FAILED,
    "malformed": BusinessLogicStatus.MALFORMED_RESPONSE,
    "malformed_response": BusinessLogicStatus.MALFORMED_RESPONSE,
    "timeout": BusinessLogicStatus.TIMEOUT,
    "replay_rejected": BusinessLogicStatus.REQUEST_FAILED,
}

_IDENTITY_CAPABILITIES = frozenset(
    {
        "business_logic.ownership_analysis",
        "business_logic.role_boundary_analysis",
    }
)


class BusinessLogicEngine:
    """Authorized, deterministic business logic observation.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> explicit test-identity enforcement ->
    fail-closed replay safety pre-check -> mock transport execution ->
    normalization -> evidence persistence (artifact + typed observations) ->
    world model materialization -> best-effort memory link.

    Observation-only by design: no free-form execution, no credential use, no
    destructive actions, and no autonomous identity discovery are possible
    through this surface. Replay runs only against the safety-gated paper
    model, and ownership/role-boundary analysis only ever evaluates explicitly
    authorized test identities.
    """

    def __init__(
        self,
        capability_registry: CapabilityRegistry | None = None,
        evidence_store: EvidenceStore | None = None,
        world_model: WorldModelStore | None = None,
        memory_bridge: EvidenceMemoryBridge | None = None,
        authorization: AuthorizationBoundary | None = None,
    ) -> None:
        self.capability_registry = capability_registry
        self.evidence_store = evidence_store
        self.world_model = world_model
        self.memory_bridge = memory_bridge
        self.authorization = authorization or AuthorizationBoundary()
        self._transport = MockBusinessLogicTransport()
        self._capabilities: dict[str, BusinessLogicCapability] = {
            cap.capability_id: cap for cap in build_business_logic_capabilities()
        }
        self._materializer = (
            BusinessLogicWorldMaterializer(world_model)
            if world_model is not None
            else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[BusinessLogicCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def discover_workflows(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "discover_workflows", params)

    def model_workflow(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "model_workflow", params)

    def analyze_state_transitions(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "analyze_state_transitions", params)

    def analyze_business_rules(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "analyze_business_rules", params)

    def analyze_ownership(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "analyze_ownership", params)

    def analyze_role_boundaries(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "analyze_role_boundaries", params)

    def check_workflow_consistency(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "check_workflow_consistency", params)

    def replay_workflow(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "replay_workflow", params)

    def hypothesize_business_logic(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "hypothesize_business_logic", params)

    def validate_business_logic(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "validate_business_logic", params)

    def collect_workflow_evidence(
        self, request: BusinessLogicRequest, target: str, **params: object
    ) -> BusinessLogicResult:
        return self._execute(request, target, "collect_workflow_evidence", params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: BusinessLogicRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> BusinessLogicResult:
        """Run a capability by its registry id (e.g. ``business_logic.ownership_analysis``)."""
        if not self.has_capability(capability_id):
            raise BusinessLogicExecutionError(
                f"unknown business logic capability: {capability_id}"
            )
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: BusinessLogicRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> BusinessLogicResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise BusinessLogicExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(request, capability_id, target, meta.risk_level)
        self._enforce_controlled_identities(request, capability_id, params)
        self._enforce_replay_safety(tool_method, target, params)

        raw = self._run_transport(
            tool_method,
            target,
            mode,
            request.timeout_seconds,
            params,
            list(request.test_identities) if request.test_identities else None,
        )
        normalized = self._normalize(adapter, raw, target, mode)
        observations = list(normalized.observations)
        warnings = list(normalized.warnings)
        error_document = normalized.error

        limited = False
        if len(observations) > request.max_observations:
            observations = observations[: request.max_observations]
            warnings.append(
                "observation limit reached; result truncated to "
                f"{request.max_observations}"
            )
            limited = True

        evidence_ids: list[EvidenceID] = []
        if self.evidence_store is not None:
            evidence_ids = self._persist_evidence(
                request, target, capability_id, mode, raw, observations
            )
        self._materialize_world(
            request, capability_id, mode, observations, evidence_ids
        )
        self._materialize_memory(evidence_ids)

        duration_ms = (time.time() - start) * 1000.0
        status = self._map_status(error_document, limited, observations, warnings)

        return BusinessLogicResult(
            mission_id=request.mission_id,
            session_id=request.session_id,
            target=target,
            capability_id=capability_id,
            mode=mode,
            status=status,
            observations=observations,
            evidence_ids=evidence_ids,
            raw_output=raw,
            warnings=warnings,
            error=self._error_message(error_document),
            duration_ms=round(duration_ms, 3),
            authorized=True,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _map_status(
        error_document: dict | None,
        limited: bool,
        observations: list[Observation],
        warnings: list[str],
    ) -> BusinessLogicStatus:
        if error_document is not None:
            kind = error_document.get("kind")
            return _ERROR_KIND_TO_STATUS.get(
                str(kind), BusinessLogicStatus.REQUEST_FAILED
            )
        if limited:
            return BusinessLogicStatus.LIMITED
        if not observations and warnings:
            return BusinessLogicStatus.NO_EVIDENCE
        if warnings:
            return BusinessLogicStatus.PARTIAL
        return BusinessLogicStatus.SUCCESS

    @staticmethod
    def _error_message(error_document: dict | None) -> str | None:
        if error_document is None:
            return None
        message = error_document.get("message")
        return str(message) if isinstance(message, str) else str(error_document)

    def _request_mode(
        self, request: BusinessLogicRequest, params: dict[str, object]
    ) -> BusinessLogicMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return BusinessLogicMode(param_mode)
            except ValueError as exc:
                raise BusinessLogicExecutionError(
                    f"invalid business logic mode: {param_mode}"
                ) from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta, target: str) -> bool | None:
        from blackforge.scope.models import detect_target_type

        return detect_target_type(target) in meta.supported_target_types

    @staticmethod
    def _enforce_controlled_identities(
        request: BusinessLogicRequest,
        capability_id: str,
        params: dict[str, object],
    ) -> None:
        """Identity-filtered capabilities require explicitly authorized identities.

        Ownership and role-boundary analysis never discover or guess
        identities: either the caller supplies ``test_identities`` that are
        within the request's authorized set, or the request itself carries an
        authorized set. Anything else is rejected before the transport runs.
        """
        if capability_id not in _IDENTITY_CAPABILITIES:
            return
        authorized = {str(i) for i in request.test_identities}
        param_identities = params.get("test_identities")
        supplied = (
            {str(i) for i in param_identities}
            if isinstance(param_identities, list)
            else set()
        )
        listed = supplied or authorized
        if not listed:
            raise BusinessLogicExecutionError(
                f"{capability_id} requires explicit authorized test identities"
            )
        if supplied and not supplied.issubset(authorized):
            raise BusinessLogicExecutionError(
                f"{capability_id} supplied identities are not authorized "
                f"for this mission"
            )

    def _enforce_replay_safety(
        self, tool_method: str, target: str, params: dict[str, object]
    ) -> None:
        """Fail-closed safety pre-check before any replay reaches the transport."""
        if tool_method not in {"replay_workflow", "validate_business_logic"}:
            return
        actions = params.get("actions")
        sequence = [str(a) for a in actions] if isinstance(actions, list) else []
        for action in sequence:
            if self._transport.safety_class_for(target, action) == ReplaySafetyClass.PROHIBITED:
                raise BusinessLogicExecutionError(
                    f"replay rejected: action {action} has safety class "
                    "PROHIBITED on target"
                )

    def _enforce_authorization(
        self,
        request: BusinessLogicRequest,
        capability_id: str,
        target: str,
        risk_level,
    ) -> None:
        decision = self.authorization.authorize(
            mission_id=request.mission_id,
            scope=request.scope,
            capability_name=capability_id,
            target_value=target,
            risk_level=risk_level,
        )
        if decision.value == "denied":
            raise AuthorizationError(
                f"business logic observation denied: {capability_id} is not "
                f"authorized for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"business logic observation requires approval: {capability_id} "
                f"exceeds the mission risk limit"
            )

    def _run_transport(
        self,
        tool_method: str,
        target: str,
        mode: BusinessLogicMode,
        timeout: float,
        params: dict[str, object],
        default_identities: list[str] | None = None,
    ) -> str:
        start = time.time()
        try:
            if tool_method == "replay_workflow":
                actions = params.get("actions")
                sequence = (
                    [str(a) for a in actions] if isinstance(actions, list) else None
                )
                raw = self._transport.replay_workflow(
                    target,
                    mode=mode,
                    actions=sequence,
                    start_state=_string_param(params, "start_state"),
                    max_sequence_length=_int_param(params, "max_sequence_length", 8),
                )
            elif tool_method in {"analyze_ownership", "analyze_role_boundaries"}:
                test_identities = params.get("test_identities")
                if isinstance(test_identities, list) and test_identities:
                    identities = [str(i) for i in test_identities]
                elif default_identities:
                    identities = list(default_identities)
                else:
                    identities = None
                raw = getattr(self._transport, tool_method)(
                    target, mode=mode, test_identities=identities
                )
            else:
                raw = getattr(self._transport, tool_method)(target, mode=mode)
        except BusinessLogicExecutionError:
            raise
        except Exception as exc:
            raise BusinessLogicExecutionError(
                f"business logic transport {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise BusinessLogicTimeoutError(
                f"business logic transport timed out: {tool_method}"
            )
        return raw

    def _normalize(
        self,
        adapter: BusinessToolAdapter,
        raw: str,
        target: str,
        mode: BusinessLogicMode,
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except BusinessLogicNormalizationError:
            raise
        except Exception as exc:
            raise BusinessLogicNormalizationError(
                f"failed to normalize business logic output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: BusinessLogicRequest,
        target: str,
        capability_id: str,
        mode: BusinessLogicMode,
        raw: str,
        observations: list[Observation],
    ) -> list[EvidenceID]:
        artifact = artifact_evidence(
            request.mission_id,
            target,
            capability_id,
            raw,
            session_id=request.session_id,
            mode=mode,
        )
        artifact_id = self._ensure_evidence(artifact)
        evidence_ids: list[EvidenceID] = [artifact_id]

        for observation in observations:
            obs_evidence = observation_evidence(
                request.mission_id,
                target,
                capability_id,
                observation,
                session_id=request.session_id,
                mode=mode,
            )
            obs_id = self._ensure_evidence(obs_evidence, derived_from=artifact_id)
            evidence_ids.append(obs_id)
        return evidence_ids

    def _ensure_evidence(
        self, evidence, derived_from: EvidenceID | None = None
    ) -> EvidenceID:
        existing = existing_evidence_id(self.evidence_store, evidence)
        if existing is not None:
            return existing
        via_validation = evidence.status == EvidenceStatus.VALIDATED
        stored = self.evidence_store.add(evidence, via_validation=via_validation)
        if (
            derived_from is not None
            and len(self.evidence_store.get_relationships(stored.id)) == 0
        ):
            self.evidence_store.add_relationship(
                stored.id, EvidenceRelation.DERIVED_FROM, derived_from
            )
        return stored.id

    def _materialize_world(
        self,
        request: BusinessLogicRequest,
        capability_id: str,
        mode: BusinessLogicMode,
        observations: list[Observation],
        evidence_ids: list[EvidenceID],
    ):
        if self.world_model is None or self._materializer is None:
            return None
        meta = self._capabilities[capability_id].meta()
        if not meta.world_model or not observations:
            return None
        artifact_id = evidence_ids[0] if evidence_ids else None
        tuples: list[tuple[Observation, EvidenceID, Confidence]] = []
        for index, observation in enumerate(observations):
            obs_id = evidence_ids[index + 1] if index + 1 < len(evidence_ids) else artifact_id
            if obs_id is None:
                continue
            confidence = observation_confidence(observation, mode)
            tuples.append((observation, obs_id, confidence))
        return self._materializer.materialize(
            request.mission_id,
            tuples,
            session_id=request.session_id,
        )

    def _materialize_memory(self, evidence_ids: list[EvidenceID]) -> None:
        if self.memory_bridge is None:
            return
        for evidence_id in evidence_ids[1:]:
            try:
                self.memory_bridge.materialize_memory(evidence_id)
            except Exception as exc:
                log.warning(
                    "business_logic_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise BusinessLogicExecutionError(
        f"unknown business logic capability: {capability_id}"
    )


def _string_param(params: dict[str, object], key: str) -> str | None:
    value = params.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _int_param(params: dict[str, object], key: str, default: int) -> int:
    value = params.get(key)
    if isinstance(value, int):
        return value
    return default
