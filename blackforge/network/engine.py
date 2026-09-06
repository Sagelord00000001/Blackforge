from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.core.errors import (
    AuthorizationError,
    NetworkExecutionError,
    NetworkNormalizationError,
    NetworkTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.evidence.models import EvidenceRelation
from blackforge.network.capabilities import (
    NetworkCapability,
    build_network_capabilities,
)
from blackforge.network.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.network.materializer import NetworkWorldMaterializer
from blackforge.network.models import (
    NetworkMode,
    NetworkRequest,
    NetworkResult,
    NetworkStatus,
    Observation,
)
from blackforge.network.transport import MockNetworkTransport

if TYPE_CHECKING:
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.network.normalization import NetworkToolAdapter
    from blackforge.world_model.store import WorldModelStore

log = get_logger("network.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "discover_hosts": "network.host_discovery",
    "discover_ports": "network.port_discovery",
    "observe_services": "network.service_observation",
    "identify_protocols": "network.protocol_identification",
    "observe_banners": "network.banner_observation",
    "observe_dns": "network.dns_observation",
    "observe_tls": "network.tls_observation",
    "analyze_exposure": "network.network_exposure_analysis",
    "model_infrastructure": "network.infrastructure_modeling",
    "correlate_service_applications": "network.service_application_correlation",
    "collect_network_evidence": "network.network_evidence_collection",
}

_ERROR_KIND_TO_STATUS: dict[str, NetworkStatus] = {
    "rate_limited": NetworkStatus.RATE_LIMITED,
    "unauthorized": NetworkStatus.UNAUTHORIZED,
    "connection_refused": NetworkStatus.REQUEST_FAILED,
    "malformed": NetworkStatus.MALFORMED_RESPONSE,
    "malformed_response": NetworkStatus.MALFORMED_RESPONSE,
    "timeout": NetworkStatus.TIMEOUT,
    "filtered": NetworkStatus.FILTERED,
    "out_of_scope": NetworkStatus.OUT_OF_SCOPE,
}

_PORTS_CAPABILITIES = frozenset(
    {
        "network.port_discovery",
        "network.service_observation",
        "network.protocol_identification",
        "network.banner_observation",
        "network.tls_observation",
    }
)


class NetworkEngine:
    """Authorized, deterministic network observation.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> bounded port validation -> mock transport
    execution -> normalization -> evidence persistence (artifact + typed
    observations) -> world model materialization -> best-effort memory link.

    Observation-only by design: the transport is a fixed mock dataset, no real
    network traffic is ever produced, probe ports are bounded to 1..65535,
    banners are size-capped and credential-redacted, and no offensive edge
    semantics (EXPLOITS, CAN_COMPROMISE, LEADS_TO, ENABLES) are ever emitted.
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
        self._transport = MockNetworkTransport()
        self._capabilities: dict[str, NetworkCapability] = {
            cap.capability_id: cap for cap in build_network_capabilities()
        }
        self._materializer = (
            NetworkWorldMaterializer(world_model)
            if world_model is not None
            else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[NetworkCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def discover_hosts(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "discover_hosts", params)

    def discover_ports(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "discover_ports", params)

    def observe_services(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "observe_services", params)

    def identify_protocols(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "identify_protocols", params)

    def observe_banners(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "observe_banners", params)

    def observe_dns(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "observe_dns", params)

    def observe_tls(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "observe_tls", params)

    def analyze_exposure(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "analyze_exposure", params)

    def model_infrastructure(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "model_infrastructure", params)

    def correlate_service_applications(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "correlate_service_applications", params)

    def collect_network_evidence(
        self, request: NetworkRequest, target: str, **params: object
    ) -> NetworkResult:
        return self._execute(request, target, "collect_network_evidence", params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: NetworkRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> NetworkResult:
        """Run a capability by its registry id (e.g. ``network.port_discovery``)."""
        if not self.has_capability(capability_id):
            raise NetworkExecutionError(
                f"unknown network capability: {capability_id}"
            )
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: NetworkRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> NetworkResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise NetworkExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(request, capability_id, target, meta.risk_level)
        ports = self._bounded_ports(request, params, capability_id)

        raw = self._run_transport(
            tool_method,
            target,
            mode,
            request.timeout_seconds,
            params,
            ports,
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

        return NetworkResult(
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
    ) -> NetworkStatus:
        if error_document is not None:
            kind = error_document.get("kind")
            return _ERROR_KIND_TO_STATUS.get(
                str(kind), NetworkStatus.REQUEST_FAILED
            )
        if limited:
            return NetworkStatus.LIMITED
        if not observations and warnings:
            return NetworkStatus.NO_EVIDENCE
        if warnings:
            return NetworkStatus.PARTIAL
        return NetworkStatus.SUCCESS

    @staticmethod
    def _error_message(error_document: dict | None) -> str | None:
        if error_document is None:
            return None
        message = error_document.get("message")
        return str(message) if isinstance(message, str) else str(error_document)

    def _request_mode(
        self, request: NetworkRequest, params: dict[str, object]
    ) -> NetworkMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return NetworkMode(param_mode)
            except ValueError as exc:
                raise NetworkExecutionError(
                    f"invalid network mode: {param_mode}"
                ) from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta, target: str) -> bool | None:
        from blackforge.scope.models import detect_target_type

        return detect_target_type(target) in meta.supported_target_types

    def _bounded_ports(
        self,
        request: NetworkRequest,
        params: dict[str, object],
        capability_id: str,
    ) -> list[int] | None:
        """Validate and bound an explicit port list for probing capabilities.

        Ports must be integers in 1..65535; anything outside that range (or a
        non-list value) is rejected fail-closed before the transport runs.
        Explicit, excessive ranges are rejected rather than silently probed.
        """
        if capability_id not in _PORTS_CAPABILITIES:
            return None
        value = params.get("ports")
        if value is None:
            return None
        if not isinstance(value, list):
            raise NetworkExecutionError(
                f"{capability_id} requires an explicit list of ports"
            )
        ports: list[int] = []
        for item in value:
            if not isinstance(item, int):
                raise NetworkExecutionError(
                    f"{capability_id} port list must contain only integers"
                )
            if not 1 <= item <= 65535:
                raise NetworkExecutionError(
                    f"{capability_id} port {item} out of range 1..65535"
                )
            ports.append(item)
        if not ports:
            raise NetworkExecutionError(
                f"{capability_id} requires at least one explicit port"
            )
        if len(ports) > 65535:
            raise NetworkExecutionError(
                f"{capability_id} port range too large: {len(ports)}"
            )
        return ports

    def _enforce_authorization(
        self,
        request: NetworkRequest,
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
                f"network observation denied: {capability_id} is not "
                f"authorized for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"network observation requires approval: {capability_id} "
                f"exceeds the mission risk limit"
            )

    def _run_transport(
        self,
        tool_method: str,
        target: str,
        mode: NetworkMode,
        timeout: float,
        params: dict[str, object],
        ports: list[int] | None,
    ) -> str:
        start = time.time()
        try:
            if tool_method in _PORTS_CAPABILITIES:
                raw = getattr(self._transport, tool_method)(
                    target, mode=mode, ports=ports
                )
            else:
                raw = getattr(self._transport, tool_method)(target, mode=mode)
        except AuthorizationError:
            raise
        except NetworkExecutionError:
            raise
        except Exception as exc:
            raise NetworkExecutionError(
                f"network transport {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise NetworkTimeoutError(
                f"network transport timed out: {tool_method}"
            )
        return raw

    def _normalize(
        self,
        adapter: NetworkToolAdapter,
        raw: str,
        target: str,
        mode: NetworkMode,
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except NetworkNormalizationError:
            raise
        except Exception as exc:
            raise NetworkNormalizationError(
                f"failed to normalize network output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: NetworkRequest,
        target: str,
        capability_id: str,
        mode: NetworkMode,
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
        request: NetworkRequest,
        capability_id: str,
        mode: NetworkMode,
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
                    "network_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise NetworkExecutionError(
        f"unknown network capability: {capability_id}"
    )
