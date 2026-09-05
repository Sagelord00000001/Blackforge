from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class ReconMode(str, Enum):
    """How reconnaissance operates on a target.

    * ``PASSIVE`` — inference only: DNS resolution, banners, fingerprints and
      other data the target machine does not directly probe.
    * ``ACTIVE`` — direct observations: connection/service enumeration and
      metadata collection against the (authorized) target.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class ObservationKind(str, Enum):
    """Typed kinds of reconnaissance observations."""

    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    NETWORK = "network"


class ReconStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    LIMITED = "limited"
    TIMEOUT = "timeout"
    FAILED = "failed"


class HostObservation(BaseModel):
    """A discovered host (hostname or IP literal) and its addresses."""

    kind: Literal["host"] = "host"
    host: str
    ip_addresses: list[str] = Field(default_factory=list)
    os: str | None = None
    status: str = "up"
    notes: list[str] = Field(default_factory=list)


class PortObservation(BaseModel):
    """A single observed port with transport state."""

    kind: Literal["port"] = "port"
    host: str
    port: int
    state: str = "open"
    protocol: str = "tcp"


class ServiceObservation(BaseModel):
    """A detected network service bound to a host:port."""

    kind: Literal["service"] = "service"
    host: str
    port: int
    protocol: str = "tcp"
    service: str
    version: str | None = None
    banner: str | None = None
    state: str = "open"


class TechnologyObservation(BaseModel):
    """A technology/framework fingerprint observed on a host."""

    kind: Literal["technology"] = "technology"
    host: str
    technology: str
    category: str = "unknown"
    version: str | None = None
    port: int | None = None
    detection_confidence: str = "high"


class DNSObservation(BaseModel):
    """A DNS record observation for a hostname."""

    kind: Literal["dns"] = "dns"
    host: str
    record_type: str
    answers: list[str] = Field(default_factory=list)


class HTTPObservation(BaseModel):
    """HTTP service metadata observed on a reachable URL."""

    kind: Literal["http"] = "http"
    url: str
    host: str
    port: int | None = None
    status_code: int
    server_header: str | None = None
    title: str | None = None
    redirect_location: str | None = None
    headers: dict = Field(default_factory=dict)


class TLSObservation(BaseModel):
    """TLS/certificate metadata observed on a host:port."""

    kind: Literal["tls"] = "tls"
    host: str
    port: int
    certificate_subject: str
    certificate_issuer: str
    not_before: str
    not_after: str
    tls_version: str
    cipher: str
    sni_required: bool = False
    hostname_matches: bool = False


class NetworkObservation(BaseModel):
    """A network segment / CIDR with hosts claimed to be inside it."""

    kind: Literal["network"] = "network"
    cidr: str
    network_name: str | None = None
    hosts: list[str] = Field(default_factory=list)
    exposure: str = "unknown"


Observation = Annotated[
    HostObservation
    | PortObservation
    | ServiceObservation
    | TechnologyObservation
    | DNSObservation
    | HTTPObservation
    | TLSObservation
    | NetworkObservation,
    Field(discriminator="kind"),
]


class ReconRequest(BaseModel):
    """Authorized reconnaissance request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: ReconMode = ReconMode.ACTIVE
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)


class ReconResult(BaseModel):
    """Structured, deterministic outcome of a reconnaissance execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: ReconMode
    status: ReconStatus = ReconStatus.SUCCESS
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
