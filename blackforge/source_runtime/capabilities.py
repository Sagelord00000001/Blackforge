from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType
from blackforge.source_runtime.models import (
    CorrelationResult,
    SourceRuntimeRequest,
    SourceRuntimeResult,
    SourceRuntimeStatus,
)

if TYPE_CHECKING:
    from blackforge.source_runtime.engine import SourceRuntimeEngine

SOURCE_RUNTIME_CAPABILITY_IDS = [
    "source_runtime.container_configuration_correlation",
    "source_runtime.image_runtime_correlation",
    "source_runtime.workload_manifest_correlation",
    "source_runtime.service_exposure_correlation",
    "source_runtime.ingress_runtime_correlation",
    "source_runtime.network_policy_correlation",
    "source_runtime.cloud_resource_correlation",
    "source_runtime.api_surface_correlation",
    "source_runtime.application_configuration_correlation",
    "source_runtime.rbac_manifest_correlation",
]


class SourceRuntimeCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for source & runtime correlation capabilities."""

    category: str = "source_runtime"
    mode: str = "controlled"
    compares: list[CorrelationResult] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    *,
    version: str = "1.0.0",
    supported_target_types: list[TargetType] | None = None,
) -> SourceRuntimeCapabilityMeta:
    return SourceRuntimeCapabilityMeta(
        id=CapabilityID(capability_id),
        name=capability_id,
        description=description,
        version=version,
        risk_level=RiskLevel.LOW,
        authorization_required=True,
        supported_target_types=supported_target_types
        or [TargetType.ASSET, TargetType.CLOUD, TargetType.APPLICATION],
        input_schema={
            "mission_id": {"type": "string"},
            "target": {"type": "string"},
            "params": {"type": "object"},
        },
        output_schema={"result": {"type": "object"}},
        evidence_types_produced=["source_analysis", "observation"],
        compares=[
            CorrelationResult.MATCH,
            CorrelationResult.DISCREPANCY,
            CorrelationResult.CONTRADICTION,
            CorrelationResult.UNKNOWN,
            CorrelationResult.INSUFFICIENT_EVIDENCE,
            CorrelationResult.NOT_COMPARABLE,
        ],
    )


SRO = "source_runtime."


def build_source_runtime_meta() -> list[SourceRuntimeCapabilityMeta]:
    """Metadata for all ten source & runtime correlation capabilities."""
    return [
        _meta(
            SRO + "container_configuration_correlation",
            "Correlate declared container configuration against observed runtime "
            "container configuration and record MATCH / DISCREPANCY / UNKNOWN.",
        ),
        _meta(
            SRO + "image_runtime_correlation",
            "Correlate the declared container image digest with the observed "
            "runtime image digest, preferring the immutable digest over a tag.",
        ),
        _meta(
            SRO + "workload_manifest_correlation",
            "Correlate declared workload manifests against observed running "
            "workloads (replicas, image, namespace, service account).",
        ),
        _meta(
            SRO + "service_exposure_correlation",
            "Correlate declared service exposure (type / port) against the "
            "observed service exposure.",
        ),
        _meta(
            SRO + "ingress_runtime_correlation",
            "Correlate declared ingress routes / paths against observed routing.",
        ),
        _meta(
            SRO + "network_policy_correlation",
            "Correlate declared network policy against observed policy state.",
        ),
        _meta(
            SRO + "cloud_resource_correlation",
            "Correlate declared cloud resource configuration against observed "
            "cloud resource state (engine, version, public exposure, backups).",
        ),
        _meta(
            SRO + "api_surface_correlation",
            "Correlate the declared api surface with the observed api surface.",
        ),
        _meta(
            SRO + "application_configuration_correlation",
            "Correlate declared application configuration (env, secrets, "
            "feature flags) against observed runtime configuration.",
        ),
        _meta(
            SRO + "rbac_manifest_correlation",
            "Correlate declared service-account / role bindings against the "
            "observed runtime identity bindings.",
        ),
    ]


class SourceRuntimeCorrelationCapability(Capability):
    """Base capability that runs a deterministic source/runtime correlation."""

    capability_id = "source_runtime.correlation"
    scope_kind = "cluster"

    def __init__(
        self,
        capability_id: str,
        description: str,
        engine: SourceRuntimeEngine,
        *,
        version: str = "1.0.0",
    ) -> None:
        self.capability_id = capability_id
        self._description = description
        self._version = version
        self._engine = engine

    def meta(self) -> SourceRuntimeCapabilityMeta:
        return _meta(self.capability_id, self._description, version=self._version)

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        params = params or {}
        mission_id = params.get("mission_id")
        scope = params.get("scope")
        if not mission_id or not scope:
            return CapabilityResult(
                success=False,
                output=SourceRuntimeResult(
                    mission_id=str(mission_id or ""),
                    session_id=params.get("session_id"),
                    target=target,
                    capability_id=self.capability_id,
                    mode=params.get("mode")
                    if isinstance(params.get("mode"), str)
                    else "controlled",
                    status=SourceRuntimeStatus.REQUEST_FAILED,
                    error="mission_id and scope are required",
                ).model_dump(mode="json"),
                error="mission_id and scope are required",
            )
        request = SourceRuntimeRequest(
            mission_id=mission_id,
            scope=scope,
            session_id=params.get("session_id"),
        )
        result = self._engine.run(
            capability_id=self.capability_id, request=request, target=target
        )
        return CapabilityResult(
            success=result.status in {
                SourceRuntimeStatus.SUCCESS,
                SourceRuntimeStatus.PARTIAL,
            },
            output=result.model_dump(mode="json"),
            metadata={"result": result.result if hasattr(result, "result") else None},
        )


def build_capabilities(
    engine: SourceRuntimeEngine,
) -> list[SourceRuntimeCorrelationCapability]:
    """Construct all ten correlation capabilities bound to a shared engine."""
    descriptions = {}
    for meta in build_source_runtime_meta():
        descriptions[meta.name] = meta.description

    capabilities = []
    for capability_id in SOURCE_RUNTIME_CAPABILITY_IDS:
        capabilities.append(
            SourceRuntimeCorrelationCapability(
                capability_id=capability_id,
                description=descriptions.get(capability_id, ""),
                engine=engine,
            )
        )
    return capabilities


__all__ = [
    "SOURCE_RUNTIME_CAPABILITY_IDS",
    "SourceRuntimeCapabilityMeta",
    "SourceRuntimeCorrelationCapability",
    "build_capabilities",
    "build_source_runtime_meta",
]
