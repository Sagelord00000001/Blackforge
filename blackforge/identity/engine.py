from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.core.errors import (
    AuthorizationError,
    IdentityExecutionError,
    IdentityNormalizationError,
    IdentityTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.evidence.models import EvidenceRelation
from blackforge.identity.capabilities import (
    IdentityCapability,
    build_identity_capabilities,
)
from blackforge.identity.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.identity.materializer import IdentityWorldMaterializer
from blackforge.identity.models import (
    IdentityMode,
    IdentityRequest,
    IdentityResult,
    IdentityStatus,
    Observation,
)
from blackforge.identity.transport import MockIdentityTransport

if TYPE_CHECKING:
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.identity.normalization import IdentityToolAdapter
    from blackforge.world_model.store import WorldModelStore

log = get_logger("identity.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "discover_directories": "identity.directory_discovery",
    "inventory_identities": "identity.identity_inventory",
    "inventory_groups": "identity.group_inventory",
    "inventory_roles": "identity.role_inventory",
    "inventory_permissions": "identity.permission_inventory",
    "inventory_resources": "identity.resource_inventory",
    "observe_membership": "identity.membership_observation",
    "observe_role_assignment": "identity.role_assignment_observation",
    "observe_permission_assignment": "identity.permission_assignment_observation",
    "analyze_relationships": "identity.relationship_analysis",
    "observe_metadata": "identity.metadata_observation",
}

_IDENTITY_LEVEL_TOOLS = frozenset(
    {
        "observe_membership",
        "observe_role_assignment",
        "observe_permission_assignment",
        "analyze_relationships",
        "observe_metadata",
    }
)

_ERROR_KIND_TO_STATUS: dict[str, IdentityStatus] = {
    "rate_limited": IdentityStatus.RATE_LIMITED,
    "unauthorized": IdentityStatus.UNAUTHORIZED,
    "malformed": IdentityStatus.MALFORMED_RESPONSE,
    "malformed_response": IdentityStatus.MALFORMED_RESPONSE,
    "timeout": IdentityStatus.TIMEOUT,
    "out_of_scope": IdentityStatus.OUT_OF_SCOPE,
    "unsupported_directory": IdentityStatus.UNSUPPORTED_DIRECTORY,
    "unknown_identity": IdentityStatus.NO_EVIDENCE,
    "unknown_reference": IdentityStatus.NO_EVIDENCE,
}


class IdentityEngine:
    """Authorized, deterministic identity & directory observation.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> identity resolution -> mock transport
    execution -> normalization -> evidence persistence (artifact + typed
    observations) -> world model materialization -> best-effort memory link.

    Observation-only by design: the transport is a fixed mock dataset, no
    real directory is ever queried or mutated, credential-like fields are
    redacted at the artifact boundary, relationship output is restricted to
    the structural edge vocabulary, and no offensive semantics are ever
    emitted.
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
        self._transport = MockIdentityTransport()
        self._capabilities: dict[str, IdentityCapability] = {
            cap.capability_id: cap for cap in build_identity_capabilities()
        }
        self._materializer = (
            IdentityWorldMaterializer(world_model)
            if world_model is not None
            else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[IdentityCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def discover_directories(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "discover_directories", params)

    def inventory_identities(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "inventory_identities", params)

    def inventory_groups(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "inventory_groups", params)

    def inventory_roles(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "inventory_roles", params)

    def inventory_permissions(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "inventory_permissions", params)

    def inventory_resources(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "inventory_resources", params)

    def observe_membership(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "observe_membership", params)

    def observe_role_assignment(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "observe_role_assignment", params)

    def observe_permission_assignment(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(
            request, target, "observe_permission_assignment", params
        )

    def analyze_relationships(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "analyze_relationships", params)

    def observe_metadata(
        self, request: IdentityRequest, target: str, **params: object
    ) -> IdentityResult:
        return self._execute(request, target, "observe_metadata", params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: IdentityRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> IdentityResult:
        """Run a capability by its registry id (e.g. ``identity.membership_observation``)."""
        if not self.has_capability(capability_id):
            raise IdentityExecutionError(
                f"unknown identity capability: {capability_id}"
            )
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: IdentityRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> IdentityResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise IdentityExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(request, capability_id, target, meta.risk_level)
        identity = self._resolve_identity(request, params)

        raw = self._run_transport(
            tool_method,
            target,
            mode,
            request.timeout_seconds,
            params,
            identity,
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

        return IdentityResult(
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
    ) -> IdentityStatus:
        if error_document is not None:
            kind = error_document.get("kind")
            return _ERROR_KIND_TO_STATUS.get(
                str(kind), IdentityStatus.REQUEST_FAILED
            )
        if limited:
            return IdentityStatus.LIMITED
        if not observations and warnings:
            return IdentityStatus.NO_EVIDENCE
        if warnings:
            return IdentityStatus.PARTIAL
        return IdentityStatus.SUCCESS

    @staticmethod
    def _error_message(error_document: dict | None) -> str | None:
        if error_document is None:
            return None
        message = error_document.get("message")
        return str(message) if isinstance(message, str) else str(error_document)

    def _request_mode(
        self, request: IdentityRequest, params: dict[str, object]
    ) -> IdentityMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return IdentityMode(param_mode)
            except ValueError as exc:
                raise IdentityExecutionError(
                    f"invalid identity mode: {param_mode}"
                ) from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta, target: str) -> bool | None:
        from blackforge.scope.models import detect_target_type

        return detect_target_type(target) in meta.supported_target_types

    def _resolve_identity(
        self, request: IdentityRequest, params: dict[str, object]
    ) -> str | None:
        """Resolve the explicit identity for identity-level capabilities.

        Precedence: capability params -> request.identity -> None (the
        transport derives the identity from the target string when possible,
        e.g. ``alice@aelionix-corp.local`` or ``AELIONIX-CORP\\alice``).
        """
        for candidate in (params.get("identity"), request.identity):
            if candidate is not None:
                if not isinstance(candidate, str) or not candidate.strip():
                    raise IdentityExecutionError(
                        "identity must be a non-empty string"
                    )
                return candidate.strip()
        return None

    def _enforce_authorization(
        self,
        request: IdentityRequest,
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
                f"identity observation denied: {capability_id} is not "
                f"authorized for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"identity observation requires approval: {capability_id} "
                f"exceeds the mission risk limit"
            )

    def _run_transport(
        self,
        tool_method: str,
        target: str,
        mode: IdentityMode,
        timeout: float,
        params: dict[str, object],
        identity: str | None,
    ) -> str:
        start = time.time()
        try:
            if tool_method in _IDENTITY_LEVEL_TOOLS:
                raw = getattr(self._transport, tool_method)(
                    target, mode=mode, identity=identity
                )
            else:
                raw = getattr(self._transport, tool_method)(target, mode=mode)
        except AuthorizationError:
            raise
        except IdentityExecutionError:
            raise
        except Exception as exc:
            raise IdentityExecutionError(
                f"identity transport {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise IdentityTimeoutError(
                f"identity transport timed out: {tool_method}"
            )
        return raw

    def _normalize(
        self,
        adapter: IdentityToolAdapter,
        raw: str,
        target: str,
        mode: IdentityMode,
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except IdentityNormalizationError:
            raise
        except Exception as exc:
            raise IdentityNormalizationError(
                f"failed to normalize identity output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: IdentityRequest,
        target: str,
        capability_id: str,
        mode: IdentityMode,
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
        stored = self.evidence_store.add(evidence, via_validation=False)
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
        request: IdentityRequest,
        capability_id: str,
        mode: IdentityMode,
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
            obs_id = (
                evidence_ids[index + 1]
                if index + 1 < len(evidence_ids)
                else artifact_id
            )
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
                    "identity_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise IdentityExecutionError(
        f"unknown identity capability: {capability_id}"
    )


__all__ = ["IdentityEngine"]
