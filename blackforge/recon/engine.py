from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.core.errors import (
    AuthorizationError,
    ReconExecutionError,
    ReconNormalizationError,
    ReconTimeoutError,
)
from blackforge.core.logging import get_logger
from blackforge.evidence.models import EvidenceRelation
from blackforge.recon.capabilities import (
    ReconCapability,
    build_recon_capabilities,
)
from blackforge.recon.evidence import (
    artifact_evidence,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
)
from blackforge.recon.materializer import (
    MaterializeReport,
    ReconWorldMaterializer,
)
from blackforge.recon.mock import MockReconTool
from blackforge.recon.models import (
    Observation,
    ReconMode,
    ReconRequest,
    ReconResult,
    ReconStatus,
)

if TYPE_CHECKING:
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.core.types import Confidence, EvidenceID
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.recon.normalization import ToolAdapter
    from blackforge.world_model.store import WorldModelStore

log = get_logger("recon.engine")

METHOD_TO_CAPABILITY: dict[str, str] = {
    "discover_hosts": "recon.host_discovery",
    "enumerate_services": "recon.service_discovery",
    "identify_technologies": "recon.technology_identification",
    "inspect_dns": "recon.dns",
    "inspect_http_metadata": "recon.http_metadata",
    "inspect_tls": "recon.tls_metadata",
}


class ReconEngine:
    """Authorized, deterministic reconnaissance execution.

    Every typed capability runs the same pipeline: request validation ->
    scope/authorization check -> mock tool execution -> normalization ->
    evidence persistence (artifact + typed observations) -> world model
    materialization -> best-effort memory link. No generic shell executor
    exists; the only execution surface is the typed capability contract.
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
        self._tool = MockReconTool()
        self._capabilities: dict[str, ReconCapability] = {
            cap.capability_id: cap for cap in build_recon_capabilities()
        }
        self._materializer = (
            ReconWorldMaterializer(world_model) if world_model is not None else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list[ReconCapability]:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    # ------------------------------------------------------------------
    # Typed capability contracts
    # ------------------------------------------------------------------
    def discover_hosts(
        self,
        request: ReconRequest,
        target: str,
        **params: object,
    ) -> ReconResult:
        return self._execute(request, target, "discover_hosts", params)

    def enumerate_services(
        self,
        request: ReconRequest,
        target: str,
        **params: object,
    ) -> ReconResult:
        return self._execute(request, target, "enumerate_services", params)

    def identify_technologies(
        self,
        request: ReconRequest,
        target: str,
        **params: object,
    ) -> ReconResult:
        return self._execute(request, target, "identify_technologies", params)

    def inspect_dns(
        self,
        request: ReconRequest,
        target: str,
        **params: object,
    ) -> ReconResult:
        return self._execute(request, target, "inspect_dns", params)

    def inspect_http_metadata(
        self,
        request: ReconRequest,
        target: str,
        **params: object,
    ) -> ReconResult:
        return self._execute(request, target, "inspect_http_metadata", params)

    def inspect_tls(
        self,
        request: ReconRequest,
        target: str,
        **params: object,
    ) -> ReconResult:
        return self._execute(request, target, "inspect_tls", params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------
    def run(
        self,
        request: ReconRequest,
        capability_id: str,
        target: str,
        **params: object,
    ) -> ReconResult:
        """Run a capability by its registry id (e.g. ``recon.dns``)."""
        if not self.has_capability(capability_id):
            raise ReconExecutionError(f"unknown reconnaissance capability: {capability_id}")
        tool_method = _capability_tool_method(capability_id)
        return self._execute(request, target, tool_method, params)

    # ------------------------------------------------------------------
    # Shared pipeline
    # ------------------------------------------------------------------
    def _execute(
        self,
        request: ReconRequest,
        target: str,
        tool_method: str,
        params: dict[str, object],
    ) -> ReconResult:
        start = time.time()
        capability_id = METHOD_TO_CAPABILITY[tool_method]
        meta = self._capabilities[capability_id].meta()
        adapter = self._capabilities[capability_id].adapter

        mode = self._request_mode(request, params)
        if self._target_type_allowed(meta, target) is False:
            raise ReconExecutionError(
                f"{capability_id} does not support target: {target}"
            )
        self._enforce_authorization(request, capability_id, target, meta.risk_level)

        raw = self._run_tool(tool_method, target, mode, request.timeout_seconds)
        normalized = self._normalize(adapter, raw, target, mode)
        observations = list(normalized.observations)
        warnings = list(normalized.warnings)

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
        if limited:
            status = ReconStatus.LIMITED
        elif warnings:
            status = ReconStatus.PARTIAL
        else:
            status = ReconStatus.SUCCESS

        return ReconResult(
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
            duration_ms=round(duration_ms, 3),
            authorized=True,
        )

    # ------------------------------------------------------------------
    def _request_mode(self, request: ReconRequest, params: dict[str, object]) -> ReconMode:
        param_mode = params.get("mode")
        if param_mode is not None:
            try:
                return ReconMode(param_mode)
            except ValueError as exc:
                raise ReconExecutionError(f"invalid recon mode: {param_mode}") from exc
        return request.mode

    @staticmethod
    def _target_type_allowed(meta: ReconCapability, target: str) -> bool | None:
        from blackforge.scope.models import detect_target_type

        return detect_target_type(target) in meta.supported_target_types

    def _enforce_authorization(
        self,
        request: ReconRequest,
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
                f"reconnaissance denied: {capability_id} is not authorized "
                f"for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"reconnaissance requires approval: {capability_id} exceeds "
                f"the mission risk limit"
            )

    def _run_tool(self, tool_method: str, target: str, mode: ReconMode, timeout: float) -> str:
        start = time.time()
        try:
            raw = getattr(self._tool, tool_method)(target, mode=mode)
        except Exception as exc:
            raise ReconExecutionError(
                f"reconnaissance tool {tool_method} failed: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            raise ReconTimeoutError(f"reconnaissance tool timed out: {tool_method}")
        return raw

    def _normalize(
        self, adapter: ToolAdapter, raw: str, target: str, mode: ReconMode
    ):
        try:
            return adapter.adapt(raw, context={"target": target, "mode": mode})
        except ReconNormalizationError:
            raise
        except Exception as exc:
            raise ReconNormalizationError(
                f"failed to normalize tool output for {target}: {exc}"
            ) from exc

    def _persist_evidence(
        self,
        request: ReconRequest,
        target: str,
        capability_id: str,
        mode: ReconMode,
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
        request: ReconRequest,
        capability_id: str,
        mode: ReconMode,
        observations: list[Observation],
        evidence_ids: list[EvidenceID],
    ) -> MaterializeReport | None:
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
                    "recon_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )


def _capability_tool_method(capability_id: str) -> str:
    for method, cap_id in METHOD_TO_CAPABILITY.items():
        if cap_id == capability_id:
            return method
    raise ReconExecutionError(f"unknown reconnaissance capability: {capability_id}")
