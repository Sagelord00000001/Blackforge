from __future__ import annotations

import time
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from blackforge.core.types import EvidenceID, MissionID, SessionID  # noqa: TC001
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class IdentityMode(str, Enum):
    """How identity observation operates on a directory.

    * ``PASSIVE`` — inference only: metadata, correlated membership posture,
      and descriptive privilege classification. No directory record is
      touched.
    * ``CONTROLLED`` — deterministic, bounded observation against the
      (authorized) mock directory dataset: membership, role assignment,
      permission assignment, and resource attribution records. No real
      directory is ever queried and no mutation is ever issued.
    """

    PASSIVE = "passive"
    CONTROLLED = "controlled"


class IdentityStatus(str, Enum):
    """Failure-aware outcomes for an identity capability execution.

    Every run terminates in one of these states; negative outcomes (unknown
    directory, unknown identity, rate limited, malformed) are recorded as
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
    UNSUPPORTED_DIRECTORY = "unsupported_directory"
    FAILED = "failed"


class IdentityObservationKind(str, Enum):
    """Typed kinds of identity & directory observations."""

    DIRECTORY = "directory"
    IDENTITY = "identity"
    GROUP = "group"
    ROLE = "role"
    PERMISSION = "permission"
    RESOURCE = "resource"
    MEMBERSHIP = "membership"
    ROLE_ASSIGNMENT = "role_assignment"
    PERMISSION_ASSIGNMENT = "permission_assignment"
    RELATIONSHIP = "relationship"
    METADATA = "metadata"


class DirectoryObservation(BaseModel):
    """A directory discovered/observed on the authorized estate."""

    kind: Literal["directory"] = "directory"
    directory: str
    dns_name: str | None = None
    directory_type: str | None = None
    forest: str | None = None
    note: str | None = None


class IdentityObservation(BaseModel):
    """A single identity record observed in a directory.

    ``privilege_level`` is a *descriptive* directory classification
    (standard/elevated/administrator/service) — never an automatic
    vulnerability claim and never derived from offensive analysis.
    """

    kind: Literal["identity"] = "identity"
    directory: str
    identity: str
    principal_type: str | None = None
    display_name: str | None = None
    email: str | None = None
    enabled: bool | None = None
    locked: bool | None = None
    privilege_level: str | None = None
    note: str | None = None


class GroupObservation(BaseModel):
    """A security/distribution group observed in a directory."""

    kind: Literal["group"] = "group"
    directory: str
    group: str
    scope_type: str | None = None
    membership_count: int | None = None
    note: str | None = None


class RoleObservation(BaseModel):
    """A role (authorization container) observed in a directory."""

    kind: Literal["role"] = "role"
    directory: str
    role: str
    privilege_level: str | None = None
    note: str | None = None


class PermissionObservation(BaseModel):
    """A permission right observed in a directory."""

    kind: Literal["permission"] = "permission"
    directory: str
    permission: str
    note: str | None = None


class ResourceObservation(BaseModel):
    """A resource that permissions apply to (descriptive, structural)."""

    kind: Literal["resource"] = "resource"
    directory: str
    resource: str
    resource_type: str | None = None
    note: str | None = None


class MembershipObservation(BaseModel):
    """An identity's group membership record.

    ``resolved`` is False (with a warning) when the observation references a
    group that does not exist in the directory; no relationship is
    materialized from an unresolved membership.
    """

    kind: Literal["membership"] = "membership"
    directory: str
    identity: str
    group: str
    resolved: bool = True
    missing_reference: str | None = None
    note: str | None = None


class RoleAssignmentObservation(BaseModel):
    """A role assignment observed on an identity."""

    kind: Literal["role_assignment"] = "role_assignment"
    directory: str
    identity: str
    role: str
    note: str | None = None


class PermissionAssignmentObservation(BaseModel):
    """A permission right assigned to a role."""

    kind: Literal["permission_assignment"] = "permission_assignment"
    directory: str
    role: str
    permission: str
    note: str | None = None


class RelationshipObservation(BaseModel):
    """A derived, descriptive relationship resolved for an identity.

    ``relationship_type`` is restricted to the world model's structural edge
    vocabulary (member_of / has_role / has_permission / applies_to). Offensive
    edges (EXPLOITS, CAN_COMPROMISE, LEADS_TO, ENABLES) are never produced.
    """

    kind: Literal["relationship"] = "relationship"
    directory: str
    relationship_type: str
    source: str
    target: str
    note: str | None = None


class MetadataObservation(BaseModel):
    """A metadata attribute observed for an identity.

    ``source`` distinguishes authoritative primary records (``directory``)
    from correlated feeds; ``resolved`` is False when the referenced value
    points at a record that does not exist in the directory.
    """

    kind: Literal["metadata"] = "metadata"
    directory: str
    identity: str
    attribute_key: str
    attribute_value: str
    source: str | None = None
    resolved: bool = True
    missing_reference: str | None = None
    note: str | None = None


Observation = Annotated[
    DirectoryObservation
    | IdentityObservation
    | GroupObservation
    | RoleObservation
    | PermissionObservation
    | ResourceObservation
    | MembershipObservation
    | RoleAssignmentObservation
    | PermissionAssignmentObservation
    | RelationshipObservation
    | MetadataObservation,
    Field(discriminator="kind"),
]


class IdentityRequest(BaseModel):
    """Authorized identity observation request context.

    The scope travels with the request so every capability invocation is
    checked against the same authorization boundary regardless of caller.
    ``identity`` is an optional explicit identity name for identity-level
    capabilities; when omitted it is derived from the target string
    (``dir\\name``, ``name@dir``, or a bare name).
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: IdentityMode = IdentityMode.CONTROLLED
    identity: str | None = None
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)


class IdentityResult(BaseModel):
    """Structured, deterministic outcome of an identity execution."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: IdentityMode
    status: IdentityStatus = IdentityStatus.SUCCESS
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
