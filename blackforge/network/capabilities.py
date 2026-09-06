from __future__ import annotations

from pydantic import Field

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType
from blackforge.network.models import NetworkMode, NetworkObservationKind
from blackforge.network.normalization import (
    BannerObservationAdapter,
    DnsObservationAdapter,
    ExposureAnalysisAdapter,
    HostDiscoveryAdapter,
    InfrastructureModelingAdapter,
    NetworkEvidenceAdapter,
    NetworkToolAdapter,
    PortDiscoveryAdapter,
    ProtocolIdentificationAdapter,
    ServiceApplicationAdapter,
    ServiceObservationAdapter,
    TlsObservationAdapter,
)
from blackforge.network.transport import MockNetworkTransport

NETWORK_CAPABILITY_IDS = [
    "network.host_discovery",
    "network.port_discovery",
    "network.service_observation",
    "network.protocol_identification",
    "network.banner_observation",
    "network.dns_observation",
    "network.tls_observation",
    "network.network_exposure_analysis",
    "network.infrastructure_modeling",
    "network.service_application_correlation",
    "network.network_evidence_collection",
]


class NetworkCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for network capabilities."""

    category: str = "network"
    mode: NetworkMode = NetworkMode.PASSIVE
    produces: list[NetworkObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    risk_level: RiskLevel,
    mode: NetworkMode,
    supported_target_types: list[TargetType],
    produces: list[NetworkObservationKind],
    *,
    version: str = "1.0.0",
) -> NetworkCapabilityMeta:
    return NetworkCapabilityMeta(
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


def build_network_meta() -> list[NetworkCapabilityMeta]:
    """Metadata for all eleven typed network capabilities."""
    scan = [TargetType.DOMAIN, TargetType.IP, TargetType.URL, TargetType.CIDR]
    scan = [TargetType.DOMAIN, TargetType.IP, TargetType.URL, TargetType.CIDR]
    rest = [TargetType.DOMAIN, TargetType.IP, TargetType.URL]
    return [
        _meta(
            "network.host_discovery",
            "Discover hosts reachable within the authorized network.",
            RiskLevel.LOW,
            NetworkMode.PASSIVE,
            scan,
            [NetworkObservationKind.HOST],
        ),
        _meta(
            "network.port_discovery",
            "Probe and classify ports on an authorized target (bounded, mock).",
            RiskLevel.MEDIUM,
            NetworkMode.ACTIVE,
            scan,
            [NetworkObservationKind.PORT],
        ),
        _meta(
            "network.service_observation",
            "Identify services running on open ports of the mock target.",
            RiskLevel.MEDIUM,
            NetworkMode.ACTIVE,
            rest,
            [NetworkObservationKind.SERVICE],
        ),
        _meta(
            "network.protocol_identification",
            "Identify the protocol in use on observed ports.",
            RiskLevel.MEDIUM,
            NetworkMode.ACTIVE,
            rest,
            [NetworkObservationKind.PROTOCOL],
        ),
        _meta(
            "network.banner_observation",
            "Capture bounded, credential-redacted service banners.",
            RiskLevel.MEDIUM,
            NetworkMode.ACTIVE,
            rest,
            [NetworkObservationKind.BANNER],
        ),
        _meta(
            "network.dns_observation",
            "Observe DNS records for the authorized domain/server.",
            RiskLevel.LOW,
            NetworkMode.PASSIVE,
            rest,
            [NetworkObservationKind.DNS],
        ),
        _meta(
            "network.tls_observation",
            "Observe TLS negotiation metadata on SSL/TLS services.",
            RiskLevel.MEDIUM,
            NetworkMode.ACTIVE,
            rest,
            [NetworkObservationKind.TLS],
        ),
        _meta(
            "network.network_exposure_analysis",
            "Analyze host interface exposure and internet-routability posture.",
            RiskLevel.LOW,
            NetworkMode.PASSIVE,
            rest,
            [NetworkObservationKind.EXPOSURE],
        ),
        _meta(
            "network.infrastructure_modeling",
            "Model network infrastructure segments and devices in the topology.",
            RiskLevel.LOW,
            NetworkMode.PASSIVE,
            scan,
            [NetworkObservationKind.INFRASTRUCTURE],
        ),
        _meta(
            "network.service_application_correlation",
            "Correlate observed services to the applications they back.",
            RiskLevel.LOW,
            NetworkMode.PASSIVE,
            rest,
            [NetworkObservationKind.SERVICE_APPLICATION],
        ),
        _meta(
            "network.network_evidence_collection",
            "Assemble deterministic network evidence for downstream attribution.",
            RiskLevel.MEDIUM,
            NetworkMode.PASSIVE,
            rest,
            [NetworkObservationKind.NETWORK_EVIDENCE],
        ),
    ]


class NetworkCapability(Capability):
    """A typed network capability bound to a mock transport method.

    ``execute`` runs the deterministic mock transport through the
    normalization adapter and returns normalized observations. It performs no
    authorization itself — the :class:`NetworkEngine` enforces scope /
    authorization before any execution path reaches the mock.
    """

    def __init__(
        self,
        meta: NetworkCapabilityMeta,
        tool_method: str,
        adapter: NetworkToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._transport = MockNetworkTransport()

    def meta(self) -> NetworkCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> NetworkToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        mode_param = params.get("mode") if params else None
        mode = NetworkMode(mode_param) if mode_param else self._meta.mode
        method = self._tool_method
        ports = _int_list_param(params, "ports")
        if method in {
            "discover_ports",
            "observe_services",
            "identify_protocols",
            "observe_banners",
            "observe_tls",
        }:
            raw = getattr(self._transport, method)(target, mode=mode, ports=ports)
        else:
            raw = getattr(self._transport, method)(target, mode=mode)
        normalized = self._adapter.adapt(raw, context={"target": target, "mode": mode})
        return CapabilityResult(
            success=True,
            output=[o.model_dump() for o in normalized.observations],
            metadata={
                "tool": method,
                "mode": mode.value,
                "warnings": normalized.warnings,
                "error": normalized.error,
                "mock": True,
            },
        )


def _int_list_param(params: dict | None, key: str) -> list[int] | None:
    value = params.get(key) if params else None
    if isinstance(value, list):
        result: list[int] = []
        for item in value:
            if isinstance(item, int):
                result.append(item)
        return result
    return None


def build_network_capabilities() -> list[NetworkCapability]:
    """Instantiate all eleven typed network capabilities (mock-backed)."""
    adapters = [
        HostDiscoveryAdapter(),
        PortDiscoveryAdapter(),
        ServiceObservationAdapter(),
        ProtocolIdentificationAdapter(),
        BannerObservationAdapter(),
        DnsObservationAdapter(),
        TlsObservationAdapter(),
        ExposureAnalysisAdapter(),
        InfrastructureModelingAdapter(),
        ServiceApplicationAdapter(),
        NetworkEvidenceAdapter(),
    ]
    tool_methods = [
        "discover_hosts",
        "discover_ports",
        "observe_services",
        "identify_protocols",
        "observe_banners",
        "observe_dns",
        "observe_tls",
        "analyze_exposure",
        "model_infrastructure",
        "correlate_service_applications",
        "collect_network_evidence",
    ]
    return [
        NetworkCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            build_network_meta(),
            tool_methods,
            adapters,
            strict=True,
        )
    ]
