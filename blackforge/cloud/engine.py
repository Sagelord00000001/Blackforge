from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.cloud.capabilities import (
    CloudCapability,
    build_cloud_capabilities,
)
from blackforge.cloud.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.cloud.materializer import CloudWorldMaterializer
from blackforge.cloud.models import (
    CloudMode,
    CloudObservation,
    CloudRequest,
    CloudResult,
    CloudStatus,
)
from blackforge.cloud.transport import MockCloudTransport
from blackforge.core.errors import (
    AuthorizationError,
    CloudExecutionError,
    CloudNormalizationError,
    CloudTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.core.types import TargetType
from blackforge.evidence.models import EvidenceRelation

if TYPE_CHECKING:
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.cloud.normalization import CloudToolAdapter
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.world_model.store import WorldModelStore

log = get_logger("cloud.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "discover_providers": "cloud.provider_discovery",
    "inventory_accounts": "cloud.account_inventory",
    "inventory_projects": "cloud.project_inventory",
    "inventory_resources": "cloud.resource_inventory",
    "observe_compute": "cloud.compute_observation",
    "observe_storage": "cloud.storage_observation",
    "observe_databases": "cloud.database_observation",
    "observe_networks": "cloud.network_observation",
    "analyze_public_exposure": "cloud.public_exposure_analysis",
    "observe_security_configuration": "cloud.security_configuration_observation",
    "observe_secret_references": "cloud.secret_reference_observation",
    "observe_iam_identities": "cloud.iam_identity_observation",
    "observe_iam_roles": "cloud.iam_role_observation",
    "observe_iam_permissions": "cloud.iam_permission_observation",
    "analyze_resource_relationships": "cloud.resource_relationship_analysis",
    "observe_containers": "cloud.container_observation",
    "observe_clusters": "cloud.cluster_observation",
    "observe_edge_architecture": "cloud.edge_architecture_observation",
    "analyze_origin_candidates": "cloud.origin_candidate_analysis",
    "observe_transport_security": "cloud.transport_security_observation",
}

_LEVEL_TOOLS = frozenset(METHOD_TO_CAPABILITY)

_ERROR_KIND_TO_STATUS: dict[str, CloudStatus] = {
    "rate_limited": CloudStatus.RATE_LIMITED,
    "unauthorized": CloudStatus.UNAUTHORIZED,
    "malformed": CloudStatus.MALFORMED_RESPONSE,
    "malformed_response": CloudStatus.MALFORMED_RESPONSE,
    "timeout": CloudStatus.TIMEOUT,
    "out_of_scope": CloudStatus.OUT_OF_SCOPE,
    "unsupported_provider": CloudStatus.UNSUPPORTED_PROVIDER,
    "unknown_provider": CloudStatus.UNKNOWN_PROVIDER,
}


class CloudEngine:
    """Authorized, deterministic cloud security observation.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> provider/container resolution -> mock
    transport execution -> normalization -> evidence persistence (artifact +
    typed observations) -> world model materialization -> best-effort memory
    link.

    Observation-only by design: the transport is a fixed mock dataset, no
    real provider is ever queried or mutated, credential-like fields are
    redacted at the artifact boundary, relationship output is restricted to
    the structural edge vocabulary, and no offensive semantics are emitted.
    Observing a cloud posture is never reported as a vulnerability.
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
        self._transport = MockCloudTransport()
        self._capabilities: dict[str, CloudCapability] = {
            cap.capability_id: cap for cap in build_cloud_capabilities()
        }
        self._materializer = (
            CloudWorldMaterializer(world_model)
            if world_model is not None
            else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[CloudCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def discover_providers(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "discover_providers", params)

    def inventory_accounts(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "inventory_accounts", params)

    def inventory_projects(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "inventory_projects", params)

    def inventory_resources(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "inventory_resources", params)

    def observe_compute(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_compute", params)

    def observe_storage(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_storage", params)

    def observe_databases(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_databases", params)

    def observe_networks(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_networks", params)

    def analyze_public_exposure(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "analyze_public_exposure", params)

    def observe_security_configuration(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(
            request, target, "observe_security_configuration", params
        )

    def observe_secret_references(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_secret_references", params)

    def observe_iam_identities(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_iam_identities", params)

    def observe_iam_roles(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_iam_roles", params)

    def observe_iam_permissions(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_iam_permissions", params)

    def analyze_resource_relationships(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(
            request, target, "analyze_resource_relationships", params
        )

    def observe_containers(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_containers", params)

    def observe_clusters(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_clusters", params)

    def observe_edge_architecture(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_edge_architecture", params)

    def analyze_origin_candidates(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "analyze_origin_candidates", params)

    def observe_transport_security(
        self, request: CloudRequest, target: str, **params: object
    ) -> CloudResult:
        return self._execute(request, target, "observe_transport_security", params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: CloudRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> CloudResult:
        """Run a capability by its registry id (e.g. ``cloud.compute_observation``)."""
        if not self.has_capability(capability_id):
            raise CloudExecutionError(
                f"unknown cloud capability: {capability_id}"
            )
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: CloudRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> CloudResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise CloudExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(request, capability_id, target, meta.risk_level)

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

        return CloudResult(
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
        observations: list[CloudObservation],
        warnings: list[str],
    ) -> CloudStatus:
        if error_document is not None:
            kind = error_document.get("kind")
            return _ERROR_KIND_TO_STATUS.get(
                str(kind), CloudStatus.REQUEST_FAILED
            )
        if limited:
            return CloudStatus.LIMITED
        if not observations and warnings:
            return CloudStatus.NO_EVIDENCE
        if warnings:
            return CloudStatus.PARTIAL
        return CloudStatus.SUCCESS

    @staticmethod
    def _error_message(error_document: dict | None) -> str | None:
        if error_document is None:
            return None
        message = error_document.get("message")
        return str(message) if isinstance(message, str) else str(error_document)

    def _request_mode(
        self, request: CloudRequest, params: dict[str, object]
    ) -> CloudMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return CloudMode(param_mode)
            except ValueError as exc:
                raise CloudExecutionError(
                    f"invalid cloud mode: {param_mode}"
                ) from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta, target: str) -> bool | None:
        from blackforge.cloud.providers import provider_for_target
        from blackforge.scope.models import detect_target_type

        detected = detect_target_type(target)
        if detected in meta.supported_target_types:
            return True
        if TargetType.CLOUD in meta.supported_target_types:
            provider = provider_for_target(target)
            if provider is not None and provider.value != "unknown":
                return True
        return False

    def _enforce_authorization(
        self,
        request: CloudRequest,
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
                f"cloud observation denied: {capability_id} is not "
                f"authorized for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"cloud observation requires approval: {capability_id} "
                f"exceeds the mission risk limit"
            )

    def _run_transport(
        self,
        tool_method: str,
        target: str,
        mode: CloudMode,
        timeout: float,
    ) -> str:
        start = time.time()
        try:
            raw = getattr(self._transport, tool_method)(target, mode=mode)
        except AuthorizationError:
            raise
        except CloudExecutionError:
            raise
        except Exception as exc:
            raise CloudExecutionError(
                f"cloud transport {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise CloudTimeoutError(
                f"cloud transport timed out: {tool_method}"
            )
        return raw

    def _normalize(
        self,
        adapter: CloudToolAdapter,
        raw: str,
        target: str,
        mode: CloudMode,
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except CloudNormalizationError:
            raise
        except Exception as exc:
            raise CloudNormalizationError(
                f"failed to normalize cloud output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: CloudRequest,
        target: str,
        capability_id: str,
        mode: CloudMode,
        raw: str,
        observations: list[CloudObservation],
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
        request: CloudRequest,
        capability_id: str,
        mode: CloudMode,
        observations: list[CloudObservation],
        evidence_ids: list[EvidenceID],
    ):
        if self.world_model is None or self._materializer is None:
            return None
        meta = self._capabilities[capability_id].meta()
        if not meta.world_model or not observations:
            return None
        artifact_id = evidence_ids[0] if evidence_ids else None
        tuples: list[tuple[CloudObservation, EvidenceID, Confidence]] = []
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
                    "cloud_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise CloudExecutionError(
        f"unknown cloud capability: {capability_id}"
    )


__all__ = ["CloudEngine"]
