from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.core.errors import ReconNormalizationError
from blackforge.recon.models import (
    DNSObservation,
    HostObservation,
    HTTPObservation,
    NetworkObservation,
    Observation,
    ServiceObservation,
    TechnologyObservation,
    TLSObservation,
)
from blackforge.world_model.canonical import (
    normalize_hostname,
    normalize_hostname_or_ip,
    normalize_ip,
    normalize_network,
    normalize_port,
    normalize_url,
)

_PORT_PROTOCOLS = {"tcp", "udp"}


class NormalizedOutput(BaseModel):
    """Adapter result: valid observations plus discarded-item warnings."""

    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ToolAdapter(ABC):
    """Boundary between untrusted tool output and typed observations.

    Every adapter parses raw output, drops or rejects invalid entries, and
    normalizes canonical names (hosts/IPs, ports, URLs, CIDRs) so observations
    line up with world-model canonical keys. Raw output is treated as data,
    never executable.
    """

    tool: str = "unknown"

    @abstractmethod
    def adapt(self, raw_output: object, *, context: dict | None = None) -> NormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise ReconNormalizationError(f"tool produced malformed JSON: {exc}") from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise ReconNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ReconNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _require_int(document: dict[str, Any], field: str) -> int:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReconNormalizationError(f"invalid integer field: {field}")
    return value


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ReconNormalizationError(f"invalid list field: {field}")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ReconNormalizationError(f"invalid entry in {field}")
        result.append(item.strip())
    return result


class HostDiscoveryAdapter(ToolAdapter):
    """Parses ``discover_hosts`` output into host and network observations."""

    tool = "discover_hosts"

    def adapt(self, raw_output: object, *, context: dict | None = None) -> NormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ReconNormalizationError("host discovery output must be a dict")
        observations: list[Observation] = []
        warnings: list[str] = []

        for item in document.get("hosts", []):
            if not isinstance(item, dict):
                warnings.append("discarded host entry: not an object")
                continue
            try:
                host = normalize_hostname_or_ip(_require_string(item, "host"))
                ip_addresses = [
                    normalize_ip(addr)
                    for addr in _string_list(item.get("ip_addresses"), "ip_addresses")
                ]
            except (ReconNormalizationError, ValueError) as exc:
                warnings.append(f"discarded host entry: {exc}")
                continue
            observations.append(
                HostObservation(
                    host=host,
                    ip_addresses=ip_addresses,
                    os=item.get("os") if isinstance(item.get("os"), str) else None,
                    status=item.get("status") or "up",
                    notes=[
                        n for n in item.get("notes", []) if isinstance(n, str)
                    ],
                )
            )

        for item in document.get("networks", []):
            if not isinstance(item, dict):
                warnings.append("discarded network entry: not an object")
                continue
            try:
                cidr = normalize_network(_require_string(item, "cidr"))
            except (ReconNormalizationError, ValueError) as exc:
                warnings.append(f"discarded network entry: {exc}")
                continue
            observations.append(
                NetworkObservation(
                    cidr=cidr,
                    network_name=(
                        item.get("name")
                        if isinstance(item.get("name"), str)
                        else None
                    ),
                    hosts=[h for h in item.get("hosts", []) if isinstance(h, str)],
                    exposure=item.get("exposure") or "unknown",
                )
            )
        return NormalizedOutput(observations=observations, warnings=warnings)


class ServiceDiscoveryAdapter(ToolAdapter):
    """Parses ``enumerate_services`` output into port/service observations."""

    tool = "enumerate_services"

    def adapt(self, raw_output: object, *, context: dict | None = None) -> NormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ReconNormalizationError("service discovery output must be a dict")
        try:
            host = normalize_hostname_or_ip(_require_string(document, "host"))
        except (ReconNormalizationError, ValueError) as exc:
            raise ReconNormalizationError(f"service discovery host invalid: {exc}") from exc

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("services", []):
            if not isinstance(item, dict):
                warnings.append("discarded service entry: not an object")
                continue
            try:
                port = normalize_port(_require_int(item, "port"))
                protocol = _require_string(item, "protocol").lower()
                if protocol not in _PORT_PROTOCOLS:
                    raise ReconNormalizationError(f"invalid protocol: {protocol}")
                service = _require_string(item, "service")
            except (ReconNormalizationError, ValueError) as exc:
                warnings.append(f"discarded service entry: {exc}")
                continue
            observations.append(
                ServiceObservation(
                    host=host,
                    port=int(port),
                    protocol=protocol,
                    service=service,
                    version=(
                        item.get("version")
                        if isinstance(item.get("version"), str)
                        else None
                    ),
                    banner=(
                        item.get("banner")
                        if isinstance(item.get("banner"), str)
                        else None
                    ),
                    state=item.get("state") or "open",
                )
            )
        return NormalizedOutput(observations=observations, warnings=warnings)


class TechnologyIdentificationAdapter(ToolAdapter):
    """Parses ``identify_technologies`` output into technology observations."""

    tool = "identify_technologies"

    def adapt(self, raw_output: object, *, context: dict | None = None) -> NormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ReconNormalizationError("technology identification output must be a dict")
        try:
            host = normalize_hostname_or_ip(_require_string(document, "host"))
        except (ReconNormalizationError, ValueError) as exc:
            raise ReconNormalizationError(f"technology host invalid: {exc}") from exc

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("technologies", []):
            if not isinstance(item, dict):
                warnings.append("discarded technology entry: not an object")
                continue
            try:
                technology = _require_string(item, "name").strip().lower()
                category = _require_string(item, "category").strip().lower()
                port = item.get("port")
                if port is not None and not isinstance(port, int):
                    raise ReconNormalizationError("invalid technology port")
            except ReconNormalizationError as exc:
                warnings.append(f"discarded technology entry: {exc}")
                continue
            observations.append(
                TechnologyObservation(
                    host=host,
                    technology=technology,
                    category=category,
                    version=(
                        item.get("version")
                        if isinstance(item.get("version"), str)
                        else None
                    ),
                    port=port,
                    detection_confidence=(
                        item.get("confidence")
                        if isinstance(item.get("confidence"), str)
                        else "medium"
                    ),
                )
            )
        return NormalizedOutput(observations=observations, warnings=warnings)


class DNSInspectionAdapter(ToolAdapter):
    """Parses ``inspect_dns`` output into DNS observations."""

    tool = "inspect_dns"

    def adapt(self, raw_output: object, *, context: dict | None = None) -> NormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ReconNormalizationError("DNS inspection output must be a dict")
        try:
            host = normalize_hostname(_require_string(document, "host"))
        except (ReconNormalizationError, ValueError) as exc:
            raise ReconNormalizationError(f"DNS host invalid: {exc}") from exc

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("records", []):
            if not isinstance(item, dict):
                warnings.append("discarded DNS record: not an object")
                continue
            try:
                record_type = _require_string(item, "type").upper()
                answers = _string_list(item.get("answers"), "answers")
            except ReconNormalizationError as exc:
                warnings.append(f"discarded DNS record: {exc}")
                continue
            observations.append(
                DNSObservation(
                    host=host, record_type=record_type, answers=answers
                )
            )
        return NormalizedOutput(observations=observations, warnings=warnings)


class HTTPMetadataAdapter(ToolAdapter):
    """Parses ``inspect_http_metadata`` output into HTTP observations."""

    tool = "inspect_http_metadata"

    def adapt(self, raw_output: object, *, context: dict | None = None) -> NormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ReconNormalizationError("HTTP metadata output must be a dict")
        try:
            host = normalize_hostname_or_ip(_require_string(document, "host"))
        except (ReconNormalizationError, ValueError) as exc:
            raise ReconNormalizationError(f"HTTP host invalid: {exc}") from exc

        entry = document.get("http")
        if entry is None:
            return NormalizedOutput(
                observations=[], warnings=["no HTTP endpoint observed"]
            )
        if not isinstance(entry, dict):
            raise ReconNormalizationError("HTTP metadata entry must be a dict")
        try:
            url = normalize_url(_require_string(entry, "url"))
        except (ReconNormalizationError, ValueError) as exc:
            raise ReconNormalizationError(f"HTTP url invalid: {exc}") from exc
        if not url.startswith(("http://", "https://")):
            raise ReconNormalizationError("HTTP url must be http(s)")
        status_code = _require_int(entry, "status_code")
        if not 100 <= status_code <= 599:
            raise ReconNormalizationError("invalid HTTP status code")
        port = entry.get("port")
        if port is not None and (not isinstance(port, int) or not 1 <= port <= 65535):
            raise ReconNormalizationError("invalid HTTP port")
        headers = (
            entry.get("headers")
            if isinstance(entry.get("headers"), dict)
            else {}
        )
        return NormalizedOutput(
            observations=[
                HTTPObservation(
                    url=url,
                    host=host,
                    port=port,
                    status_code=status_code,
                    server_header=(
                        entry.get("server")
                        if isinstance(entry.get("server"), str)
                        else None
                    ),
                    title=(
                        entry.get("title")
                        if isinstance(entry.get("title"), str)
                        else None
                    ),
                    redirect_location=(
                        entry.get("redirect_location")
                        if isinstance(entry.get("redirect_location"), str)
                        else None
                    ),
                    headers=headers,
                )
            ]
        )


class TLSInspectionAdapter(ToolAdapter):
    """Parses ``inspect_tls`` output into TLS observations."""

    tool = "inspect_tls"

    def adapt(self, raw_output: object, *, context: dict | None = None) -> NormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ReconNormalizationError("TLS inspection output must be a dict")
        try:
            host = normalize_hostname_or_ip(_require_string(document, "host"))
        except (ReconNormalizationError, ValueError) as exc:
            raise ReconNormalizationError(f"TLS host invalid: {exc}") from exc

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("certificates", []):
            if not isinstance(item, dict):
                warnings.append("discarded TLS entry: not an object")
                continue
            cert = item.get("certificate")
            if not isinstance(cert, dict):
                warnings.append("discarded TLS entry: missing certificate")
                continue
            try:
                port = normalize_port(_require_int(item, "port"))
                subject = _require_string(cert, "subject")
                issuer = _require_string(cert, "issuer")
                not_before = _require_string(cert, "not_before")
                not_after = _require_string(cert, "not_after")
                tls_version = _require_string(item, "tls_version")
                cipher = _require_string(item, "cipher")
            except (ReconNormalizationError, ValueError) as exc:
                warnings.append(f"discarded TLS entry: {exc}")
                continue
            observations.append(
                TLSObservation(
                    host=host,
                    port=int(port),
                    certificate_subject=subject,
                    certificate_issuer=issuer,
                    not_before=not_before,
                    not_after=not_after,
                    tls_version=tls_version,
                    cipher=cipher,
                    sni_required=bool(item.get("sni_required", False)),
                    hostname_matches=bool(item.get("hostname_matches", False)),
                )
            )
        return NormalizedOutput(observations=observations, warnings=warnings)


def adapter_for_tool(tool: str) -> ToolAdapter:
    """Return the adapter registered for a tool name."""
    mapping: dict[str, ToolAdapter] = {
        "discover_hosts": HostDiscoveryAdapter(),
        "enumerate_services": ServiceDiscoveryAdapter(),
        "identify_technologies": TechnologyIdentificationAdapter(),
        "inspect_dns": DNSInspectionAdapter(),
        "inspect_http_metadata": HTTPMetadataAdapter(),
        "inspect_tls": TLSInspectionAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise ReconNormalizationError(f"no adapter for tool: {tool}")
    return adapter
