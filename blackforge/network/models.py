from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class NetworkMode(str, Enum):
    """How network observation operates on a target.

    * ``PASSIVE`` — inference only: data that does not require touching the
      target (DNS records, exposure posture, topology). No connection is ever
      opened.
    * ``ACTIVE`` — deterministic observation against the (authorized) mock
      target: bounded port/service/banner/TLS probing of a mock dataset. No
      real network traffic is ever produced.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class NetworkStatus(str, Enum):
    """Failure-aware outcomes for a network capability execution.

    Every run terminates in one of these states; negative outcomes (target
    unreachable, rate limited, filtered, no evidence) are recorded as
    structured results rather than silent failures. Failure states never
    become findings.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    LIMITED = "limited"
    NO_EVIDENCE = "no_evidence"
    REQUEST_FAILED = "request_failed"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"
    OUT_OF_SCOPE = "out_of_scope"
    MALFORMED_RESPONSE = "malformed_response"
    TIMEOUT = "timeout"
    FILTERED = "filtered"
    FAILED = "failed"


class PortState(str, Enum):
    """Observed state of a single port.

    * ``OPEN`` — the mock target answers on the port.
    * ``CLOSED`` — the port is reachable but refuses connections.
    * ``FILTERED`` — no response is observed (the mock filtering profile).
    * ``UNKNOWN`` — no probe was performed or the result was indeterminate.
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class NetworkObservationKind(str, Enum):
    """Typed kinds of network observations."""

    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    PROTOCOL = "protocol"
    BANNER = "banner"
    DNS = "dns"
    TLS = "tls"
    EXPOSURE = "exposure"
    INFRASTRUCTURE = "infrastructure"
    SERVICE_APPLICATION = "service_application"
    NETWORK_EVIDENCE = "network_evidence"


class HostObservation(BaseModel):
    """A host discovered on the authorized network (mock dataset)."""

    kind: Literal["host"] = "host"
    host: str
    ip: str
    domain: str | None = None
    is_network_device: bool = False
    role: str | None = None
    operating_system: str | None = None
    note: str | None = None


class PortObservation(BaseModel):
    """A single port probe result for a host.

    ``state`` carries the full deterministic outcome (OPEN, CLOSED, FILTERED,
    UNKNOWN) so ``FILTERED`` is never conflated with ``CLOSED``.
    """

    kind: Literal["port"] = "port"
    host: str
    ip: str
    port: int
    transport: str = "tcp"
    state: PortState = PortState.UNKNOWN
    service: str | None = None
    note: str | None = None


class ServiceObservation(BaseModel):
    """A service observed on an open port (mock dataset)."""

    kind: Literal["service"] = "service"
    host: str
    ip: str
    port: int
    transport: str = "tcp"
    service: str
    version: str | None = None
    note: str | None = None


class ProtocolObservation(BaseModel):
    """A protocol identified on a port (mock dataset)."""

    kind: Literal["protocol"] = "protocol"
    host: str
    ip: str
    port: int
    transport: str = "tcp"
    protocol: str
    note: str | None = None


class BannerObservation(BaseModel):
    """A bounded, redacted banner returned by a service probe.

    Banner text is capped and credential-like fields are redacted before the
    observation is ever materialized or persisted.
    """

    kind: Literal["banner"] = "banner"
    host: str
    ip: str
    port: int
    transport: str = "tcp"
    service: str | None = None
    banner: str
    truncated: bool = False
    note: str | None = None


class DnsObservation(BaseModel):
    """A DNS record observation (DNS records captured from the mock dataset)."""

    kind: Literal["dns"] = "dns"
    server: str
    name: str
    record_type: str
    value: str
    ttl: int = 0
    note: str | None = None


class TlsObservation(BaseModel):
    """TLS negotiation metadata observed on an SSL/TLS service."""

    kind: Literal["tls"] = "tls"
    host: str
    ip: str
    port: int
    version: str = "unknown"
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_expiry: str | None = None
    cipher_suite: str | None = None
    note: str | None = None


class ExposureObservation(BaseModel):
    """Exposure posture of a host interface.

    ``exposed`` records that the interface answers network client traffic;
    ``public`` records whether that interface is internet-routable in the
    mock topology. Both are observations, never automatic findings.
    """

    kind: Literal["exposure"] = "exposure"
    host: str
    ip: str
    interface: str | None = None
    exposed: bool = False
    public: bool = False
    note: str | None = None


class InfrastructureObservation(BaseModel):
    """Infrastructure context for a host or network device (mock topology)."""

    kind: Literal["infrastructure"] = "infrastructure"
    host: str
    infrastructure: str
    role: str | None = None
    network_device: bool = False
    note: str | None = None


class ServiceApplicationObservation(BaseModel):
    """Correlation of a service to the application it backs."""

    kind: Literal["service_application"] = "service_application"
    host: str
    ip: str
    service: str
    application: str
    transport: str | None = None
    port: int | None = None
    note: str | None = None


class NetworkEvidenceObservation(BaseModel):
    """A host-level network evidence summary (evidence collection)."""

    kind: Literal["network_evidence"] = "network_evidence"
    host: str
    ip: str
    detail: str | None = None
    note: str | None = None


Observation = Annotated[
    HostObservation
    | PortObservation
    | ServiceObservation
    | ProtocolObservation
    | BannerObservation
    | DnsObservation
    | TlsObservation
    | ExposureObservation
    | InfrastructureObservation
    | ServiceApplicationObservation
    | NetworkEvidenceObservation,
    Field(discriminator="kind"),
]


class NetworkRequest(BaseModel):
    """Authorized network observation request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    ``ports`` (where supported by the capability) must be an explicit,
    bounded list of ports in 1..65535.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: NetworkMode = NetworkMode.ACTIVE
    ports: list[int] = Field(default_factory=list)
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)


class NetworkResult(BaseModel):
    """Structured, deterministic outcome of a network execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: NetworkMode
    status: NetworkStatus = NetworkStatus.SUCCESS
    observations: list[Observation] = Field(default_factory=list)
    evidence_ids: list[EvidenceID] = Field(default_factory=list)
    raw_output: str | None = None
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0
    authorized: bool = True
    created_at: float = Field(default_factory=time.time)

    @property
    def observation_count(self) -> int:
        return len(self.observations)
