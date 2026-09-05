from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class WebApiMode(str, Enum):
    """How web/api observation operates on a target.

    * ``PASSIVE`` — inference only: document/banner-derived analysis never
      interactions with the target beyond the observation source.
    * ``ACTIVE`` — direct observation against the (authorized) target: app
      discovery, endpoint enumeration, and plain GET request/response
      capture. Never sends payloads, credentials, or mutating requests.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class WebObservationKind(str, Enum):
    """Typed kinds of web/api security observations."""

    APPLICATION = "application"
    ENDPOINT = "endpoint"
    API = "api"
    SECURITY_HEADER = "security_header"
    COOKIE = "cookie"
    CORS = "cors"
    AUTH_SURFACE = "auth_surface"
    OPENAPI = "openapi"
    GRAPHQL = "graphql"
    REQUEST_RESPONSE = "request_response"


class WebApiStatus(str, Enum):
    """Failure-aware outcomes for a web/api capability execution.

    Every run terminates in one of these states; negative outcomes (target
    unreachable, rate limited, no evidence) are recorded as structured
    results rather than silent failures.
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
    FAILED = "failed"


class WebApplicationObservation(BaseModel):
    """A web application observed on an authorized target."""

    kind: Literal["application"] = "application"
    url: str
    host: str
    title: str | None = None
    technologies: list[str] = Field(default_factory=list)
    scheme: str = "https"
    tls_version: str | None = None


class EndpointObservation(BaseModel):
    """A single reachable web endpoint (path/method pair)."""

    kind: Literal["endpoint"] = "endpoint"
    url: str
    host: str
    method: str = "GET"
    status_code: int
    content_type: str | None = None
    title: str | None = None
    scheme: str = "https"
    tls_version: str | None = None
    http_version: str | None = None


class ApiObservation(BaseModel):
    """An API surface (REST, OpenAPI/Swagger, or GraphQL)."""

    kind: Literal["api"] = "api"
    url: str
    host: str
    style: str = "rest"
    kind_label: str | None = None
    docs_url: str | None = None


class SecurityHeaderObservation(BaseModel):
    """Presence/finding for one security-relevant response header."""

    kind: Literal["security_header"] = "security_header"
    url: str
    host: str
    header_name: str
    present: bool
    finding: str = "missing"
    value: str | None = None


class CookieObservation(BaseModel):
    """A cookie captured without ever storing its raw value.

    ``value_hashed`` is the one-way digest of the cookie value; the plaintext
    is not persisted anywhere in the evidence, memory, or world model layers.
    """

    kind: Literal["cookie"] = "cookie"
    url: str
    host: str
    name: str
    value_hashed: str | None = None
    domain: str | None = None
    path: str | None = None
    flags: list[str] = Field(default_factory=list)
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None


class CorsObservation(BaseModel):
    """Observed CORS configuration (never exercised cross-origin)."""

    kind: Literal["cors"] = "cors"
    url: str
    host: str
    allow_origins: list[str] = Field(default_factory=list)
    allow_methods: list[str] = Field(default_factory=list)
    allow_headers: list[str] = Field(default_factory=list)
    expose_headers: list[str] = Field(default_factory=list)
    allow_credentials: bool = False
    wildcard_origin: bool = False
    note: str | None = None


class AuthSurfaceObservation(BaseModel):
    """An authentication/authorization surface observed — never exercised.

    Recording which schemes a surface *exposes* is defensive observation;
    probing, guessing, or bypassing credentials is explicitly out of scope.
    """

    kind: Literal["auth_surface"] = "auth_surface"
    url: str
    host: str
    scheme: str
    scheme_type: str | None = None
    parameter_name: str | None = None
    note: str | None = None


class OpenApiObservation(BaseModel):
    """A parsed OpenAPI/Swagger document summary (never re-exercised)."""

    kind: Literal["openapi"] = "openapi"
    url: str
    host: str
    spec_version: str | None = None
    document_title: str | None = None
    operation_count: int = 0
    path_count: int = 0
    security_schemes: list[str] = Field(default_factory=list)


class GraphQlObservation(BaseModel):
    """Observed GraphQL surface metadata (schema shape, not content)."""

    kind: Literal["graphql"] = "graphql"
    url: str
    host: str
    introspection_enabled: bool = False
    type_count: int = 0
    query_count: int = 0
    mutation_count: int = 0
    operation_names: list[str] = Field(default_factory=list)


class RequestOutcomeObservation(BaseModel):
    """A captured plain GET request/response pair (headers redacted)."""

    kind: Literal["request_response"] = "request_response"
    url: str
    host: str
    method: str = "GET"
    status_code: int | None = None
    http_version: str | None = None
    tls_version: str | None = None
    server_header: str | None = None
    content_type: str | None = None
    rtt_ms: int | None = None
    redacted_headers: dict = Field(default_factory=dict)


Observation = Annotated[
    WebApplicationObservation
    | EndpointObservation
    | ApiObservation
    | SecurityHeaderObservation
    | CookieObservation
    | CorsObservation
    | AuthSurfaceObservation
    | OpenApiObservation
    | GraphQlObservation
    | RequestOutcomeObservation,
    Field(discriminator="kind"),
]


class WebApiRequest(BaseModel):
    """Authorized web/api observation request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: WebApiMode = WebApiMode.ACTIVE
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)


class WebApiResult(BaseModel):
    """Structured, deterministic outcome of a web/api capability execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: WebApiMode
    status: WebApiStatus = WebApiStatus.SUCCESS
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
