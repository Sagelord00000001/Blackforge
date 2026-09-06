from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.core.errors import NetworkNormalizationError
from blackforge.network.models import (
    BannerObservation,
    DnsObservation,
    ExposureObservation,
    HostObservation,
    InfrastructureObservation,
    NetworkEvidenceObservation,
    Observation,
    PortObservation,
    PortState,
    ProtocolObservation,
    ServiceApplicationObservation,
    ServiceObservation,
    TlsObservation,
)
from blackforge.network.redaction import (
    redact_banner_text,
)
from blackforge.world_model.canonical import normalize_hostname

_MAX_REDACTED_BANNER_CHARS = 400


class NetworkNormalizedOutput(BaseModel):
    """Network adapter result with optional transport error metadata.

    An ``error`` document is a *handled* negative outcome (rate limited,
    unreachable, throttled, filtered, malformed) — it becomes a network
    status, never a crash.
    """

    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: dict | None = None


class NetworkToolAdapter(ABC):
    """Boundary between mock raw output and typed network observations."""

    tool: str = "unknown"

    @abstractmethod
    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise NetworkNormalizationError(
                f"tool produced malformed JSON: {exc}"
            ) from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise NetworkNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise NetworkNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _require_int(document: dict[str, Any], field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int):
        raise NetworkNormalizationError(f"missing or invalid int field: {field}")
    return value


def _require_ip(document: dict[str, Any]) -> str:
    from blackforge.world_model.canonical import normalize_ip

    try:
        return normalize_ip(_require_string(document, "ip"))
    except (ValueError, NetworkNormalizationError) as exc:
        raise NetworkNormalizationError(f"invalid ip: {exc}") from exc


def _require_host(document: dict[str, Any]) -> str:
    try:
        return normalize_hostname(_require_string(document, "host"))
    except (ValueError, NetworkNormalizationError) as exc:
        raise NetworkNormalizationError(f"invalid host: {exc}") from exc


def _require_port(document: dict[str, Any], field: str = "port") -> int:
    port = _require_int(document, field)
    if not 1 <= port <= 65535:
        raise NetworkNormalizationError(f"{field} out of range")
    return port


def _port_state(value: object) -> PortState:
    if not isinstance(value, str):
        return PortState.UNKNOWN
    try:
        return PortState(value.strip().lower())
    except ValueError:
        return PortState.UNKNOWN


def _base_output(
    document: dict[str, Any],
    *,
    observations: list[Observation],
    warnings: list[str],
) -> NetworkNormalizedOutput:
    if document.get("error") is not None:
        error = document["error"]
        if not isinstance(error, dict):
            raise NetworkNormalizationError("tool error must be an object")
    return NetworkNormalizedOutput(observations=observations, warnings=warnings)


def _error_output(document: dict[str, Any]) -> NetworkNormalizedOutput:
    error = document.get("error")
    if not isinstance(error, dict):
        raise NetworkNormalizationError("tool error must be an object")
    return NetworkNormalizedOutput(observations=[], warnings=[], error=dict(error))


def _yield_observations(document: dict[str, Any]) -> list[dict[str, Any]]:
    observations = document.get("observations", [])
    if not isinstance(observations, list):
        raise NetworkNormalizationError("observations must be a list")
    return observations


class HostDiscoveryAdapter(NetworkToolAdapter):
    """Parses ``discover_hosts`` output."""

    tool = "discover_hosts"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError(
                "host discovery output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded host entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded host entry: {exc}")
                continue
            observations.append(
                HostObservation(
                    host=host,
                    ip=ip,
                    domain=_optional_string(item.get("domain")),
                    is_network_device=bool(item.get("is_network_device", False)),
                    role=_optional_string(item.get("role")),
                    operating_system=_optional_string(item.get("operating_system")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append(
                _optional_string(document.get("note")) or "no hosts discovered"
            )
        return _base_output(document, observations=observations, warnings=warnings)


class PortDiscoveryAdapter(NetworkToolAdapter):
    """Parses ``discover_ports`` output."""

    tool = "discover_ports"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError("port discovery output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded port entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
                port = _require_port(item)
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded port entry: {exc}")
                continue
            observations.append(
                PortObservation(
                    host=host,
                    ip=ip,
                    port=port,
                    transport=_optional_string(item.get("transport")) or "tcp",
                    state=_port_state(item.get("state")),
                    service=_optional_string(item.get("service")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append(
                _optional_string(document.get("note")) or "no ports documented"
            )
        return _base_output(document, observations=observations, warnings=warnings)


class ServiceObservationAdapter(NetworkToolAdapter):
    """Parses ``observe_services`` output."""

    tool = "observe_services"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError("service observation output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded service entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
                port = _require_port(item)
                service = _require_string(item, "service")
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded service entry: {exc}")
                continue
            observations.append(
                ServiceObservation(
                    host=host,
                    ip=ip,
                    port=port,
                    transport=_optional_string(item.get("transport")) or "tcp",
                    service=service,
                    version=_optional_string(item.get("version")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no services observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ProtocolIdentificationAdapter(NetworkToolAdapter):
    """Parses ``identify_protocols`` output."""

    tool = "identify_protocols"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError("protocol identification output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded protocol entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
                port = _require_port(item)
                protocol = _require_string(item, "protocol")
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded protocol entry: {exc}")
                continue
            observations.append(
                ProtocolObservation(
                    host=host,
                    ip=ip,
                    port=port,
                    transport=_optional_string(item.get("transport")) or "tcp",
                    protocol=protocol,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no protocols identified")
        return _base_output(document, observations=observations, warnings=warnings)


class BannerObservationAdapter(NetworkToolAdapter):
    """Parses ``observe_banners`` output.

    JSON banners are credential-redacted at parse time; non-JSON banners are
    returned bounded and unchanged (they are already stress-test safe).
    """

    tool = "observe_banners"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError("banner observation output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded banner entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
                port = _require_port(item)
                banner_value = item.get("banner")
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded banner entry: {exc}")
                continue
            if not isinstance(banner_value, str):
                warnings.append("discarded banner entry: banner is not a string")
                continue
            if item.get("banner_is_json"):
                redacted = redact_banner_text(banner_value)
            else:
                redacted = banner_value
            truncated = len(redacted) > _MAX_REDACTED_BANNER_CHARS
            if truncated:
                redacted = redacted[:_MAX_REDACTED_BANNER_CHARS]
            observations.append(
                BannerObservation(
                    host=host,
                    ip=ip,
                    port=port,
                    transport=_optional_string(item.get("transport")) or "tcp",
                    service=_optional_string(item.get("service")),
                    banner=redacted,
                    truncated=truncated,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no banners observed")
        return _base_output(document, observations=observations, warnings=warnings)


class DnsObservationAdapter(NetworkToolAdapter):
    """Parses ``observe_dns`` output."""

    tool = "observe_dns"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError("dns observation output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        warnings: list[str] = []
        observations: list[Observation] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded dns entry: not an object")
                continue
            try:
                server = normalize_hostname(
                    _require_string(item, "server")
                )
                name = _optional_string(item.get("name")) or ""
                record_type = _require_string(item, "record_type")
                value = _require_string(item, "value")
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded dns entry: {exc}")
                continue
            observations.append(
                DnsObservation(
                    server=server,
                    name=name,
                    record_type=record_type,
                    value=value,
                    ttl=item.get("ttl") if isinstance(item.get("ttl"), int) else 0,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no dns records observed")
        return _base_output(document, observations=observations, warnings=warnings)


class TlsObservationAdapter(NetworkToolAdapter):
    """Parses ``observe_tls`` output."""

    tool = "observe_tls"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError("tls observation output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded tls entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
                port = _require_port(item)
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded tls entry: {exc}")
                continue
            observations.append(
                TlsObservation(
                    host=host,
                    ip=ip,
                    port=port,
                    version=_optional_string(item.get("version")) or "unknown",
                    certificate_subject=_optional_string(item.get("certificate_subject")),
                    certificate_issuer=_optional_string(item.get("certificate_issuer")),
                    certificate_expiry=_optional_string(item.get("certificate_expiry")),
                    cipher_suite=_optional_string(item.get("cipher_suite")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append(
                _optional_string(document.get("note")) or "no tls services observed"
            )
        return _base_output(document, observations=observations, warnings=warnings)


class ExposureAnalysisAdapter(NetworkToolAdapter):
    """Parses ``analyze_exposure`` output."""

    tool = "analyze_exposure"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError("exposure analysis output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded exposure entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded exposure entry: {exc}")
                continue
            observations.append(
                ExposureObservation(
                    host=host,
                    ip=ip,
                    interface=_optional_string(item.get("interface")),
                    exposed=bool(item.get("exposed", False)),
                    public=bool(item.get("public", False)),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no exposure observations recorded")
        return _base_output(document, observations=observations, warnings=warnings)


class InfrastructureModelingAdapter(NetworkToolAdapter):
    """Parses ``model_infrastructure`` output."""

    tool = "model_infrastructure"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError(
                "infrastructure modeling output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded infrastructure entry: not an object")
                continue
            try:
                host = _require_host(item)
                infrastructure = _require_string(item, "infrastructure")
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded infrastructure entry: {exc}")
                continue
            observations.append(
                InfrastructureObservation(
                    host=host,
                    infrastructure=infrastructure,
                    role=_optional_string(item.get("role")),
                    network_device=bool(item.get("network_device", False)),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no infrastructure context recorded")
        return _base_output(document, observations=observations, warnings=warnings)


class ServiceApplicationAdapter(NetworkToolAdapter):
    """Parses ``correlate_service_applications`` output."""

    tool = "correlate_service_applications"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError(
                "service application correlation output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded service application entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
                service = _require_string(item, "service")
                application = _require_string(item, "application")
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded service application entry: {exc}")
                continue
            port = item.get("port")
            observations.append(
                ServiceApplicationObservation(
                    host=host,
                    ip=ip,
                    service=service,
                    application=application,
                    transport=_optional_string(item.get("transport")),
                    port=port if isinstance(port, int) and 1 <= port <= 65535 else None,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no service-application correlations recorded")
        return _base_output(document, observations=observations, warnings=warnings)


class NetworkEvidenceAdapter(NetworkToolAdapter):
    """Parses ``collect_network_evidence`` output."""

    tool = "collect_network_evidence"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> NetworkNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise NetworkNormalizationError(
                "network evidence collection output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded network evidence entry: not an object")
                continue
            try:
                host = _require_host(item)
                ip = _require_ip(item)
            except NetworkNormalizationError as exc:
                warnings.append(f"discarded network evidence entry: {exc}")
                continue
            observations.append(
                NetworkEvidenceObservation(
                    host=host,
                    ip=ip,
                    detail=_optional_string(item.get("detail")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no network evidence collected")
        return _base_output(document, observations=observations, warnings=warnings)


def adapter_for_tool(tool: str) -> NetworkToolAdapter:
    """Return the adapter registered for a network tool name."""
    mapping: dict[str, NetworkToolAdapter] = {
        "discover_hosts": HostDiscoveryAdapter(),
        "discover_ports": PortDiscoveryAdapter(),
        "observe_services": ServiceObservationAdapter(),
        "identify_protocols": ProtocolIdentificationAdapter(),
        "observe_banners": BannerObservationAdapter(),
        "observe_dns": DnsObservationAdapter(),
        "observe_tls": TlsObservationAdapter(),
        "analyze_exposure": ExposureAnalysisAdapter(),
        "model_infrastructure": InfrastructureModelingAdapter(),
        "correlate_service_applications": ServiceApplicationAdapter(),
        "collect_network_evidence": NetworkEvidenceAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise NetworkNormalizationError(f"no adapter for tool: {tool}")
    return adapter
