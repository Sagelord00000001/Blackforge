from __future__ import annotations

from pydantic import Field

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType
from blackforge.recon.mock import MockReconTool
from blackforge.recon.models import ObservationKind, ReconMode
from blackforge.recon.normalization import (
    DNSInspectionAdapter,
    HostDiscoveryAdapter,
    HTTPMetadataAdapter,
    ServiceDiscoveryAdapter,
    TechnologyIdentificationAdapter,
    TLSInspectionAdapter,
    ToolAdapter,
)

RECON_CAPABILITY_IDS = [
    "recon.host_discovery",
    "recon.service_discovery",
    "recon.technology_identification",
    "recon.dns",
    "recon.http_metadata",
    "recon.tls_metadata",
]


class ReconCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for reconnaissance capabilities."""

    category: str = "reconnaissance"
    mode: ReconMode = ReconMode.ACTIVE
    produces: list[ObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    risk_level: RiskLevel,
    mode: ReconMode,
    supported_target_types: list[TargetType],
    produces: list[ObservationKind],
    *,
    version: str = "1.0.0",
) -> ReconCapabilityMeta:
    return ReconCapabilityMeta(
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


def build_recon_meta() -> list[ReconCapabilityMeta]:
    """Metadata for all typed reconnaissance capabilities."""
    return [
        _meta(
            "recon.host_discovery",
            "Discover hosts and network segments related to the authorized target.",
            RiskLevel.LOW,
            ReconMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.CIDR],
            [ObservationKind.HOST, ObservationKind.NETWORK],
        ),
        _meta(
            "recon.service_discovery",
            "Enumerate open TCP/UDP services on the authorized target.",
            RiskLevel.MEDIUM,
            ReconMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP],
            [ObservationKind.PORT, ObservationKind.SERVICE],
        ),
        _meta(
            "recon.technology_identification",
            "Fingerprint technologies/frameworks running on the target.",
            RiskLevel.LOW,
            ReconMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [ObservationKind.TECHNOLOGY],
        ),
        _meta(
            "recon.dns",
            "Collect passive DNS records for the target hostname.",
            RiskLevel.LOW,
            ReconMode.PASSIVE,
            [TargetType.DOMAIN],
            [ObservationKind.DNS],
        ),
        _meta(
            "recon.http_metadata",
            "Collect HTTP metadata (status, server, headers) from the target.",
            RiskLevel.MEDIUM,
            ReconMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.URL],
            [ObservationKind.HTTP],
        ),
        _meta(
            "recon.tls_metadata",
            "Inspect TLS certificate and protocol metadata on the target.",
            RiskLevel.LOW,
            ReconMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP],
            [ObservationKind.TLS],
        ),
    ]


class ReconCapability(Capability):
    """A typed reconnaissance capability bound to a mock tool method.

    ``execute`` runs the deterministic mock tool through the normalization
    adapter and returns normalized observations. It performs no authorization
    itself — the :class:`ReconEngine` enforces scope/authorization before any
    execution path reaches the tool.
    """

    def __init__(
        self,
        meta: ReconCapabilityMeta,
        tool_method: str,
        adapter: ToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._tool = MockReconTool()

    def meta(self) -> ReconCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> ToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        mode_param = params.get("mode") if params else None
        mode = ReconMode(mode_param) if mode_param else self._meta.mode
        raw = getattr(self._tool, self._tool_method)(target, mode=mode)
        normalized = self._adapter.adapt(raw, context={"target": target, "mode": mode})
        return CapabilityResult(
            success=True,
            output=[o.model_dump() for o in normalized.observations],
            metadata={
                "tool": self._tool_method,
                "mode": mode.value,
                "warnings": normalized.warnings,
                "mock": True,
            },
        )


def build_recon_capabilities() -> list[ReconCapability]:
    """Instantiate all six typed reconnaissance capabilities (mock-backed)."""
    adapters = [
        HostDiscoveryAdapter(),
        ServiceDiscoveryAdapter(),
        TechnologyIdentificationAdapter(),
        DNSInspectionAdapter(),
        HTTPMetadataAdapter(),
        TLSInspectionAdapter(),
    ]
    tool_methods = [
        "discover_hosts",
        "enumerate_services",
        "identify_technologies",
        "inspect_dns",
        "inspect_http_metadata",
        "inspect_tls",
    ]
    return [
        ReconCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            build_recon_meta(), tool_methods, adapters, strict=True
        )
    ]
