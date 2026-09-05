from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.core.errors import (
    AuthorizationError,
    WebApiExecutionError,
    WebApiNormalizationError,
    WebApiTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.evidence.models import EvidenceRelation
from blackforge.webapi.capabilities import (
    WebApiCapability,
    build_webapi_capabilities,
)
from blackforge.webapi.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.webapi.materializer import WebWorldMaterializer
from blackforge.webapi.mock import MockWebTransport
from blackforge.webapi.models import (
    Observation,
    WebApiMode,
    WebApiRequest,
    WebApiResult,
    WebApiStatus,
)

if TYPE_CHECKING:
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.webapi.normalization import WebToolAdapter
    from blackforge.world_model.store import WorldModelStore

log = get_logger("webapi.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "discover_web_applications": "webapi.application_discovery",
    "enumerate_endpoints": "webapi.endpoint_enumeration",
    "identify_api_surfaces": "webapi.api_surface_discovery",
    "inspect_security_headers": "webapi.security_header_analysis",
    "inspect_cookies": "webapi.cookie_analysis",
    "analyze_cors": "webapi.cors_analysis",
    "inspect_authentication": "webapi.auth_surface_observation",
    "parse_openapi": "webapi.openapi_review",
    "discover_graphql": "webapi.graphql_discovery",
    "observe_request_response": "webapi.request_response_observation",
}

_ERROR_KIND_TO_STATUS: dict[str, WebApiStatus] = {
    "rate_limited": WebApiStatus.RATE_LIMITED,
    "unauthorized": WebApiStatus.UNAUTHORIZED,
    "malformed": WebApiStatus.MALFORMED_RESPONSE,
    "malformed_response": WebApiStatus.MALFORMED_RESPONSE,
}


class WebApiEngine:
    """Authorized, deterministic web/api security observation.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> mock transport execution -> normalization ->
    evidence persistence (artifact + typed observations) -> world model
    materialization -> best-effort memory link. The only execution surface is
    the typed capability contract; plain GET observation only, no payloads.
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
        self._transport = MockWebTransport()
        self._capabilities: dict[str, WebApiCapability] = {
            cap.capability_id: cap for cap in build_webapi_capabilities()
        }
        self._materializer = (
            WebWorldMaterializer(world_model) if world_model is not None else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[WebApiCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def discover_web_applications(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "discover_web_applications", params)

    def enumerate_endpoints(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "enumerate_endpoints", params)

    def identify_api_surfaces(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "identify_api_surfaces", params)

    def inspect_security_headers(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "inspect_security_headers", params)

    def inspect_cookies(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "inspect_cookies", params)

    def analyze_cors(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "analyze_cors", params)

    def inspect_authentication(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "inspect_authentication", params)

    def parse_openapi(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "parse_openapi", params)

    def discover_graphql(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "discover_graphql", params)

    def observe_request_response(
        self,
        request: WebApiRequest,
        target: str,
        **params: object,
    ) -> WebApiResult:
        return self._execute(request, target, "observe_request_response", params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: WebApiRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> WebApiResult:
        """Run a capability by its registry id (e.g. ``webapi.openapi_review``)."""
        if not self.has_capability(capability_id):
            raise WebApiExecutionError(f"unknown web api capability: {capability_id}")
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: WebApiRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> WebApiResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise WebApiExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(request, capability_id, target, meta.risk_level)

        raw = self._run_transport(tool_method, target, mode, request.timeout_seconds)
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
        status = self._map_status(
            error_document, limited, observations, warnings
        )

        return WebApiResult(
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
    ) -> WebApiStatus:
        if error_document is not None:
            kind = error_document.get("kind")
            return _ERROR_KIND_TO_STATUS.get(
                str(kind), WebApiStatus.REQUEST_FAILED
            )
        if limited:
            return WebApiStatus.LIMITED
        if not observations and warnings:
            return WebApiStatus.NO_EVIDENCE
        if warnings:
            return WebApiStatus.PARTIAL
        return WebApiStatus.SUCCESS

    @staticmethod
    def _error_message(error_document: dict | None) -> str | None:
        if error_document is None:
            return None
        message = error_document.get("message")
        return str(message) if isinstance(message, str) else str(error_document)

    def _request_mode(self, request: WebApiRequest, params: dict[str, object]) -> WebApiMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return WebApiMode(param_mode)
            except ValueError as exc:
                raise WebApiExecutionError(f"invalid web api mode: {param_mode}") from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta, target: str) -> bool | None:
        from blackforge.scope.models import detect_target_type

        return detect_target_type(target) in meta.supported_target_types

    def _enforce_authorization(
        self,
        request: WebApiRequest,
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
                f"web api observation denied: {capability_id} is not authorized "
                f"for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"web api observation requires approval: {capability_id} exceeds "
                f"the mission risk limit"
            )

    def _run_transport(
        self, tool_method: str, target: str, mode: WebApiMode, timeout: float
    ) -> str:
        start = time.time()
        try:
            raw = getattr(self._transport, tool_method)(target, mode=mode)
        except Exception as exc:
            raise WebApiExecutionError(
                f"web api transport {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise WebApiTimeoutError(f"web api transport timed out: {tool_method}")
        return raw

    def _normalize(
        self, adapter: WebToolAdapter, raw: str, target: str, mode: WebApiMode
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except WebApiNormalizationError:
            raise
        except Exception as exc:
            raise WebApiNormalizationError(
                f"failed to normalize web api output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: WebApiRequest,
        target: str,
        capability_id: str,
        mode: WebApiMode,
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
        """Store evidence, linking it to its raw artifact when new."""
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
        request: WebApiRequest,
        capability_id: str,
        mode: WebApiMode,
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
                    "webapi_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise WebApiExecutionError(f"unknown web api capability: {capability_id}")
