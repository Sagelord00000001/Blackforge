from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class AuthMode(str, Enum):
    """How authentication/authorization observation operates on a target.

    * ``PASSIVE`` — inference only: metadata/document-derived analysis that
      never interacts with the target beyond the observation source.
    * ``ACTIVE`` — direct observation against the (authorized) target:
      surface inventory, session property inspection, and controlled access
      validation using explicitly authorized test identities. Never submits,
      guesses, or brute-forces credentials.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class AuthStatus(str, Enum):
    """Failure-aware outcomes for an authentication capability execution.

    Every run terminates in one of these states; negative outcomes (target
    unreachable, rate limited, no evidence) are recorded as structured
    results rather than silent failures. Failure states never become findings.
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


class AuthAccess(str, Enum):
    """Controlled access-validation outcome for a resource.

    * ``ALLOWED`` — a validated, authorized test identity demonstrably has
      access (never inferred from a redirect or a redirect alone).
    * ``DENIED`` — a validated identity was explicitly refused. DENIED is
      NEVER inferred from a network error, timeout, or malformed response.
    * ``UNKNOWN`` — no controlled identity was supplied for this resource.
    * ``ERROR`` — the validation probe itself errored (unreachable, 5xx).
    * ``NOT_TESTED`` — access was never exercised for this combination.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_TESTED = "not_tested"


class MfaStatus(str, Enum):
    """Observed multi-factor authentication posture."""

    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


class AuthObservationKind(str, Enum):
    """Typed kinds of authentication/authorization observations."""

    AUTH_SURFACE = "auth_surface"
    AUTH_SCHEME = "auth_scheme"
    SESSION = "session"
    OAUTH_METADATA = "oauth_metadata"
    OIDC_METADATA = "oidc_metadata"
    MFA_SURFACE = "mfa_surface"
    AUTHORIZATION_SURFACE = "authorization_surface"
    ROLE = "role"
    PERMISSION = "permission"
    RESOURCE_ACCESS = "resource_access"
    ACCESS_CONTROL = "access_control"


class AuthSurfaceObservation(BaseModel):
    """An authentication surface exposed by a target — observed, never probed.

    ``parameter_name`` is metadata only (a header/cookie *name*, which is not
    a secret). When the mock reports a name that looks secret-like the value
    is hashed by the redaction boundary before it ever reaches this model.
    """

    kind: Literal["auth_surface"] = "auth_surface"
    url: str
    host: str
    scheme: str
    scheme_type: str | None = None
    parameter_name: str | None = None
    note: str | None = None


class AuthenticationSchemeObservation(BaseModel):
    """A detected authentication scheme and its observable policy properties.

    Password policy is recorded only when it is publicly exposed; policy
    fields are never populated from credential material. ``session_timeout``
    is metadata, not a secret.
    """

    kind: Literal["auth_scheme"] = "auth_scheme"
    url: str
    host: str
    scheme: str
    present: bool = True
    password_policy: str | None = None
    password_policy_observed: bool = False
    session_timeout_minutes: int | None = None
    note: str | None = None


class SessionObservation(BaseModel):
    """Session properties captured without ever storing the session value.

    ``value_hashed`` is the one-way digest of the session value; the
    plaintext is never persisted in evidence, memory, or world model layers.
    """

    kind: Literal["session"] = "session"
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
    expires: str | None = None
    note: str | None = None


class OAuthMetadataObservation(BaseModel):
    """Observed OAuth2 authorization-server metadata (never re-exercised)."""

    kind: Literal["oauth_metadata"] = "oauth_metadata"
    url: str
    host: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    grant_types: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    pkce_supported: bool = False
    note: str | None = None


class OidcMetadataObservation(BaseModel):
    """Observed OpenID Connect discovery metadata (never re-exercised)."""

    kind: Literal["oidc_metadata"] = "oidc_metadata"
    url: str
    host: str
    issuer: str | None = None
    jwks_uri: str | None = None
    discovery_url: str | None = None
    userinfo_endpoint: str | None = None
    subject_type: str | None = None
    id_token_signing_alg: str | None = None
    note: str | None = None


class MfaSurfaceObservation(BaseModel):
    """Observed multi-factor authentication posture for the target."""

    kind: Literal["mfa_surface"] = "mfa_surface"
    url: str
    host: str
    mfa_status: MfaStatus = MfaStatus.UNKNOWN
    factors: list[str] = Field(default_factory=list)
    prompt_observed: bool | None = None
    note: str | None = None


class AuthorizationSurfaceObservation(BaseModel):
    """Observed authorization model (how access decisions are expressed)."""

    kind: Literal["authorization_surface"] = "authorization_surface"
    url: str
    host: str
    authz_model: str = "unknown"
    enforcement: str | None = None
    note: str | None = None


class RoleObservation(BaseModel):
    """A role observed on a target. Role assignment is descriptive."""

    kind: Literal["role"] = "role"
    url: str
    host: str
    role: str
    description: str | None = None
    scope: str | None = None
    note: str | None = None


class PermissionObservation(BaseModel):
    """An observed permission grant for an identity through a role.

    ``credential_value`` is always the literal ``REDACTED``; the raw
    credential material that authorized the check is never represented.
    """

    kind: Literal["permission"] = "permission"
    url: str
    host: str
    identity: str | None = None
    role: str | None = None
    permission: str
    resource: str | None = None
    granted: bool
    credential_used: bool = False
    credential_type: str | None = None
    credential_value: str = "REDACTED"
    note: str | None = None


class ResourceAccessObservation(BaseModel):
    """A controlled access check outcome for an authorized test identity.

    ``access`` defaults never to ALLOWED by redirect: only an explicitly
    validated outcome grants ALLOWED/DENIED; everything else is UNKNOWN,
    ERROR, or NOT_TESTED. ``credential_value`` is always the literal
    ``REDACTED``.
    """

    kind: Literal["resource_access"] = "resource_access"
    url: str
    host: str
    identity: str | None = None
    role: str | None = None
    resource: str | None = None
    access: AuthAccess = AuthAccess.UNKNOWN
    credential_used: bool = False
    credential_type: str | None = None
    credential_value: str = "REDACTED"
    note: str | None = None


class AccessControlObservation(BaseModel):
    """Expected-vs-observed access comparison for a controlled identity.

    Requires explicitly supplied authorized test identities; unmatched
    expectations are recorded as NOT_TESTED, never assumed. ``consistent`` is
    True only when expected matches observed.
    """

    kind: Literal["access_control"] = "access_control"
    url: str
    host: str
    identity: str | None = None
    role: str | None = None
    resource: str | None = None
    access: AuthAccess = AuthAccess.UNKNOWN
    expected_access: AuthAccess = AuthAccess.NOT_TESTED
    consistent: bool = False
    credential_used: bool = False
    credential_type: str | None = None
    credential_value: str = "REDACTED"
    note: str | None = None


Observation = Annotated[
    AuthSurfaceObservation
    | AuthenticationSchemeObservation
    | SessionObservation
    | OAuthMetadataObservation
    | OidcMetadataObservation
    | MfaSurfaceObservation
    | AuthorizationSurfaceObservation
    | RoleObservation
    | PermissionObservation
    | ResourceAccessObservation
    | AccessControlObservation,
    Field(discriminator="kind"),
]


class AuthRequest(BaseModel):
    """Authorized authentication/authorization observation request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    Controlled test identities (``test_identities``) are required for
    access-validation capabilities and never default to guessing.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: AuthMode = AuthMode.ACTIVE
    test_identities: list[str] = Field(default_factory=list)
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)


class AuthResult(BaseModel):
    """Structured, deterministic outcome of an auth capability execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: AuthMode
    status: AuthStatus = AuthStatus.SUCCESS
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
