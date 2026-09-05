from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.auth.capabilities import (
    AuthCapability,
    build_auth_capabilities,
)
from blackforge.auth.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.auth.materializer import AuthWorldMaterializer
from blackforge.auth.models import (
    AuthMode,
    AuthRequest,
    AuthResult,
    AuthStatus,
    Observation,
)
from blackforge.auth.transport import MockAuthTransport
from blackforge.authorization import AuthorizationBoundary
from blackforge.core.errors import (
    AuthExecutionError,
    AuthNormalizationError,
    AuthorizationError,
    AuthTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.evidence.models import EvidenceRelation

if TYPE_CHECKING:
    from blackforge.auth.normalization import AuthToolAdapter
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.world_model.store import WorldModelStore

log = get_logger("auth.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "observe_authentication_surface": "auth.authentication_surface",
    "observe_session_details": "auth.session_observation",
    "detect_authentication_schemes": "auth.authentication_scheme_detection",
    "observe_oauth_metadata": "auth.oauth_metadata_observation",
    "observe_oidc_metadata": "auth.oidc_metadata_observation",
    "observe_mfa_surface": "auth.mfa_surface_observation",
    "observe_authorization_surface": "auth.authorization_surface",
    "observe_roles": "auth.role_observation",
    "observe_permissions": "auth.permission_observation",
    "observe_resource_access": "auth.resource_access_observation",
    "compare_access_control": "auth.access_control_comparison",
}

_ERROR_KIND_TO_STATUS: dict[str, AuthStatus] = {
    "rate_limited": AuthStatus.RATE_LIMITED,
    "unauthorized": AuthStatus.UNAUTHORIZED,
    "connection_refused": AuthStatus.REQUEST_FAILED,
    "malformed": AuthStatus.MALFORMED_RESPONSE,
    "malformed_response": AuthStatus.MALFORMED_RESPONSE,
}


class AuthEngine:
    """Authorized, deterministic authentication/authorization observation.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> mock transport execution -> normalization ->
    evidence persistence (artifact + typed observations) -> world model
    materialization -> best-effort memory link.

    Observation-only by design: no credential submission, guessing, forgery,
    escalation, or brute force is possible through this surface. Controlled
    access validation requires explicitly supplied authorized test identities
    and never defaults to guessing.
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
        self._transport = MockAuthTransport()
        self._capabilities: dict[str, AuthCapability] = {
            cap.capability_id: cap for cap in build_auth_capabilities()
        }
        self._materializer = (
            AuthWorldMaterializer(world_model) if world_model is not None else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[AuthCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def observe_authentication_surface(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_authentication_surface", params)

    def observe_session_details(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_session_details", params)

    def detect_authentication_schemes(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "detect_authentication_schemes", params)

    def observe_oauth_metadata(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_oauth_metadata", params)

    def observe_oidc_metadata(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_oidc_metadata", params)

    def observe_mfa_surface(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_mfa_surface", params)

    def observe_authorization_surface(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_authorization_surface", params)

    def observe_roles(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_roles", params)

    def observe_permissions(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_permissions", params)

    def observe_resource_access(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "observe_resource_access", params)

    def compare_access_control(
        self, request: AuthRequest, target: str, **params: object
    ) -> AuthResult:
        return self._execute(request, target, "compare_access_control", params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: AuthRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> AuthResult:
        """Run a capability by its registry id (e.g. ``auth.role_observation``)."""
        if not self.has_capability(capability_id):
            raise AuthExecutionError(f"unknown auth capability: {capability_id}")
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: AuthRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> AuthResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise AuthExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(request, capability_id, target, meta.risk_level)
        self._enforce_test_identities(request, capability_id, params)

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

        return AuthResult(
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
    ) -> AuthStatus:
        if error_document is not None:
            kind = error_document.get("kind")
            return _ERROR_KIND_TO_STATUS.get(str(kind), AuthStatus.REQUEST_FAILED)
        if limited:
            return AuthStatus.LIMITED
        if not observations and warnings:
            return AuthStatus.NO_EVIDENCE
        if warnings:
            return AuthStatus.PARTIAL
        return AuthStatus.SUCCESS

    @staticmethod
    def _error_message(error_document: dict | None) -> str | None:
        if error_document is None:
            return None
        message = error_document.get("message")
        return str(message) if isinstance(message, str) else str(error_document)

    def _request_mode(self, request: AuthRequest, params: dict[str, object]) -> AuthMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return AuthMode(param_mode)
            except ValueError as exc:
                raise AuthExecutionError(f"invalid auth mode: {param_mode}") from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta, target: str) -> bool | None:
        from blackforge.scope.models import detect_target_type

        return detect_target_type(target) in meta.supported_target_types

    @staticmethod
    def _enforce_test_identities(
        request: AuthRequest, capability_id: str, params: dict[str, object]
    ) -> None:
        """Access-validation capabilities require explicitly authorized identities.

        Supplied identities must overlap the request's authorized test
        identities; a missing set is rejected (no guessing). Comparisons only
        ever evaluate explicitly listed identities.
        """
        if capability_id not in {
            "auth.resource_access_observation",
            "auth.access_control_comparison",
        }:
            return
        param_identities = params.get("test_identities")
        listed = (
            [str(i) for i in param_identities]
            if isinstance(param_identities, list)
            else []
        )
        if not listed and not request.test_identities:
            raise AuthExecutionError(
                f"{capability_id} requires explicit authorized test identities"
            )

    def _enforce_authorization(
        self,
        request: AuthRequest,
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
                f"auth observation denied: {capability_id} is not authorized "
                f"for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"auth observation requires approval: {capability_id} exceeds "
                f"the mission risk limit"
            )

    def _run_transport(
        self,
        tool_method: str,
        target: str,
        mode: AuthMode,
        timeout: float,
        params: dict[str, object],
        default_identities: list[str] | None = None,
    ) -> str:
        start = time.time()
        try:
            if tool_method == "compare_access_control":
                test_identities = params.get("test_identities")
                if isinstance(test_identities, list) and test_identities:
                    identities = [str(i) for i in test_identities]
                elif default_identities:
                    identities = list(default_identities)
                else:
                    identities = None
                raw = self._transport.compare_access_control(
                    target, mode=mode, test_identities=identities
                )
            else:
                raw = getattr(self._transport, tool_method)(target, mode=mode)
        except Exception as exc:
            raise AuthExecutionError(
                f"auth transport {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise AuthTimeoutError(f"auth transport timed out: {tool_method}")
        return raw

    def _normalize(
        self, adapter: AuthToolAdapter, raw: str, target: str, mode: AuthMode
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except AuthNormalizationError:
            raise
        except Exception as exc:
            raise AuthNormalizationError(
                f"failed to normalize auth output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: AuthRequest,
        target: str,
        capability_id: str,
        mode: AuthMode,
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
            obs_id = self._ensure_evidence(
                obs_evidence, derived_from=artifact_id
            )
            evidence_ids.append(obs_id)
        return evidence_ids

    def _ensure_evidence(self, evidence, derived_from: EvidenceID | None = None) -> EvidenceID:
        existing = existing_evidence_id(self.evidence_store, evidence)
        if existing is not None:
            return existing
        stored = self.evidence_store.add(evidence)
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
        request: AuthRequest,
        capability_id: str,
        mode: AuthMode,
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
                    "auth_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise AuthExecutionError(f"unknown auth capability: {capability_id}")
