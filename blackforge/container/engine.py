from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.container.capabilities import (
    ContainerCapability,
    build_container_capabilities,
)
from blackforge.container.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.container.materializer import ContainerWorldMaterializer
from blackforge.container.models import (
    ContainerMode,
    ContainerObservation,
    ContainerRequest,
    ContainerResult,
    ContainerStatus,
)
from blackforge.container.transport import MockContainerTransport
from blackforge.core.errors import (
    AuthorizationError,
    ContainerExecutionError,
    ContainerNormalizationError,
    ContainerTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.core.types import TargetType
from blackforge.evidence.models import EvidenceRelation

if TYPE_CHECKING:
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.container.normalization import ContainerToolAdapter
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.world_model.store import WorldModelStore

log = get_logger("container.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "observe_clusters": "container.cluster_observation",
    "observe_nodes": "container.node_observation",
    "enumerate_namespaces": "container.namespace_enumeration",
    "observe_workloads": "container.workload_observation",
    "observe_pods": "container.pod_observation",
    "observe_containers": "container.container_observation",
    "observe_image_metadata": "container.image_metadata_observation",
    "observe_services": "container.service_observation",
    "observe_ingress": "container.ingress_exposure_observation",
    "observe_rbac": "container.rbac_observation",
    "observe_service_accounts": "container.service_account_observation",
    "observe_network_policies": "container.network_policy_observation",
    "observe_security_contexts": "container.security_context_observation",
    "observe_resource_configuration": "container.resource_configuration_observation",
}

_LEVEL_TOOLS = frozenset(METHOD_TO_CAPABILITY)

_ERROR_KIND_TO_STATUS: dict[str, ContainerStatus] = {
    "rate_limited": ContainerStatus.RATE_LIMITED,
    "unauthorized": ContainerStatus.UNAUTHORIZED,
    "malformed": ContainerStatus.MALFORMED_RESPONSE,
    "malformed_response": ContainerStatus.MALFORMED_RESPONSE,
    "timeout": ContainerStatus.TIMEOUT,
    "out_of_scope": ContainerStatus.OUT_OF_SCOPE,
    "unknown_cluster": ContainerStatus.UNKNOWN_CLUSTER,
    "unknown_namespace": ContainerStatus.UNKNOWN_CLUSTER,
    "unsupported_cluster": ContainerStatus.UNSUPPORTED_CLUSTER,
}


class ContainerEngine:
    """Authorized, deterministic container / Kubernetes security observation.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> cluster/namespace resolution -> mock
    transport execution -> normalization -> evidence persistence (artifact +
    typed observations) -> world model materialization -> best-effort memory
    link.

    Observation-only by design: the transport is a fixed mock dataset, no real
    cluster API is ever queried or mutated, credential-like fields are redacted
    at the artifact boundary, and no attack-graph edges or exploitation
    semantics are ever emitted. Observing a cluster posture is never reported
    as a vulnerability.
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
        self._transport = MockContainerTransport()
        self._capabilities: dict[str, ContainerCapability] = {
            cap.capability_id: cap for cap in build_container_capabilities()
        }
        self._materializer = (
            ContainerWorldMaterializer(world_model)
            if world_model is not None
            else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[ContainerCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def observe_clusters(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_clusters", params)

    def observe_nodes(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_nodes", params)

    def enumerate_namespaces(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "enumerate_namespaces", params)

    def observe_workloads(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_workloads", params)

    def observe_pods(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_pods", params)

    def observe_containers(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_containers", params)

    def observe_image_metadata(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_image_metadata", params)

    def observe_services(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_services", params)

    def observe_ingress(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_ingress", params)

    def observe_rbac(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_rbac", params)

    def observe_service_accounts(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_service_accounts", params)

    def observe_network_policies(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_network_policies", params)

    def observe_security_contexts(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(request, target, "observe_security_contexts", params)

    def observe_resource_configuration(
        self, request: ContainerRequest, target: str, **params: object
    ) -> ContainerResult:
        return self._execute(
            request, target, "observe_resource_configuration", params
        )

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: ContainerRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> ContainerResult:
        """Run a capability by its registry id (e.g. ``container.pod_observation``)."""
        if not self.has_capability(capability_id):
            raise ContainerExecutionError(
                f"unknown container capability: {capability_id}"
            )
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: ContainerRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> ContainerResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise ContainerExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(
            request, capability_id, target, meta.risk_level
        )

        raw = self._run_transport(
            tool_method, target, mode, request.timeout_seconds
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

        return ContainerResult(
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
        observations: list[ContainerObservation],
        warnings: list[str],
    ) -> ContainerStatus:
        if error_document is not None:
            kind = error_document.get("kind")
            return _ERROR_KIND_TO_STATUS.get(
                str(kind), ContainerStatus.REQUEST_FAILED
            )
        if limited:
            return ContainerStatus.LIMITED
        if not observations and warnings:
            return ContainerStatus.NO_EVIDENCE
        if warnings:
            return ContainerStatus.PARTIAL
        return ContainerStatus.SUCCESS

    @staticmethod
    def _error_message(error_document: dict | None) -> str | None:
        if error_document is None:
            return None
        message = error_document.get("message")
        return str(message) if isinstance(message, str) else str(error_document)

    def _request_mode(
        self, request: ContainerRequest, params: dict[str, object]
    ) -> ContainerMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return ContainerMode(param_mode)
            except ValueError as exc:
                raise ContainerExecutionError(
                    f"invalid container mode: {param_mode}"
                ) from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta, target: str) -> bool | None:
        from blackforge.container.addressing import cluster_for_target
        from blackforge.scope.models import detect_target_type

        detected = detect_target_type(target)
        if detected in meta.supported_target_types:
            return True
        if TargetType.CLOUD in meta.supported_target_types:
            cluster = cluster_for_target(target)
            if cluster is not None:
                return True
        return False

    def _enforce_authorization(
        self,
        request: ContainerRequest,
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
                f"container observation denied: {capability_id} is not "
                f"authorized for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"container observation requires approval: {capability_id} "
                f"exceeds the mission risk limit"
            )

    def _run_transport(
        self,
        tool_method: str,
        target: str,
        mode: ContainerMode,
        timeout: float,
    ) -> str:
        start = time.time()
        try:
            raw = getattr(self._transport, tool_method)(target, mode=mode)
        except AuthorizationError:
            raise
        except ContainerExecutionError:
            raise
        except Exception as exc:
            raise ContainerExecutionError(
                f"container transport {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise ContainerTimeoutError(
                f"container transport timed out: {tool_method}"
            )
        return raw

    def _normalize(
        self,
        adapter: ContainerToolAdapter,
        raw: str,
        target: str,
        mode: ContainerMode,
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except ContainerNormalizationError:
            raise
        except Exception as exc:
            raise ContainerNormalizationError(
                f"failed to normalize container output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: ContainerRequest,
        target: str,
        capability_id: str,
        mode: ContainerMode,
        raw: str,
        observations: list[ContainerObservation],
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
        request: ContainerRequest,
        capability_id: str,
        mode: ContainerMode,
        observations: list[ContainerObservation],
        evidence_ids: list[EvidenceID],
    ):
        if self.world_model is None or self._materializer is None:
            return None
        meta = self._capabilities[capability_id].meta()
        if not meta.world_model or not observations:
            return None
        artifact_id = evidence_ids[0] if evidence_ids else None
        tuples: list[tuple[ContainerObservation, EvidenceID, Confidence]] = []
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
                    "container_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise ContainerExecutionError(
        f"unknown container capability: {capability_id}"
    )


__all__ = ["ContainerEngine"]
