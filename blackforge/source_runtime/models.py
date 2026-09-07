from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, Field

from blackforge.core.types import (  # noqa: TC001  # pydantic fields
    Confidence,  # noqa: TC001  # pydantic fields
    EvidenceID,  # noqa: TC001  # pydantic fields
    MissionID,  # noqa: TC001  # pydantic fields
    SessionID,  # noqa: TC001  # pydantic fields
)
from blackforge.scope.models import TargetScope  # noqa: TC001  # pydantic fields


class SourceRuntimeMode(str, Enum):
    """How source & runtime correlation operates.

    * ``PASSIVE`` — inference only: correlation runs against already-persisted
      source/runtime evidence (never against a live transport fixture) and
      never collects a new observation.
    * ``CONTROLLED`` — deterministic, bounded correlation against the
      (authorized) mock source & runtime fixture datasets.
    """

    PASSIVE = "passive"
    CONTROLLED = "controlled"


class CorrelationResult(str, Enum):
    """Outcome of a deterministic source/runtime comparison.

    Definitions (deliberately conservative — a mismatch is an observed
    difference, never automatically a vulnerability or finding):

    * ``MATCH`` — both comparable observations exist and agree per a rule.
    * ``DISCREPANCY`` — both comparable observations exist but differ. This is
      an observed difference only.
    * ``CONTRADICTION`` — evidence records make mutually incompatible claims
      about the same comparable property. Both records are preserved; neither
      is silently chosen.
    * ``UNKNOWN`` — the comparison cannot be determined reliably; the missing
      side is never inferred.
    * ``INSUFFICIENT_EVIDENCE`` — not enough evidence to run the requested
      comparison.
    * ``NOT_COMPARABLE`` — both records exist but do not describe the same
      canonical identity (or the same comparable property).
    """

    MATCH = "match"
    DISCREPANCY = "discrepancy"
    CONTRADICTION = "contradiction"
    UNKNOWN = "unknown"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_COMPARABLE = "not_comparable"


class SourceRuntimeStatus(str, Enum):
    """Failure-aware outcomes for a source/runtime correlation execution.

    Every run terminates in one of these states; negative outcomes (out of
    scope, unsupported target, unknown capability, source/runtime missing,
    insufficient evidence) are recorded as structured results rather than
    silent failures and never become findings.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    NO_EVIDENCE = "no_evidence"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_COMPARABLE = "not_comparable"
    OUT_OF_SCOPE = "out_of_scope"
    UNSUPPORTED_TARGET = "unsupported_target"
    UNKNOWN_CAPABILITY = "unknown_capability"
    REQUEST_FAILED = "request_failed"
    FAILED = "failed"


class Side(str, Enum):
    """Which side of a correlation a fact originates from.

    ``SOURCE`` is the declared / static / specification side; ``RUNTIME`` is
    the observed / live side. They are intentionally independent: a
    correlation never makes one side stand in for the other.
    """

    SOURCE = "source"
    RUNTIME = "runtime"


class SourceValue(BaseModel):
    """A single normalized, comparable value on one side of a comparison."""

    side: Side
    property: str
    normalized_value: str | None = None
    present: bool = False


class CorrelationProperty(BaseModel):
    """A normalized, comparable property with both sides present."""

    property: str
    source_value: SourceValue
    runtime_value: SourceValue
    comparable: bool = False


class CorrelatedIdentity(BaseModel):
    """Canonical identity that both sides must agree on to be comparable.

    Two records are only comparable when they resolve to the same canonical
    identity. Same-named resources in different scopes never match.
    """

    scope_kind: str
    identity: str  # deterministic canonical key (never raw secrets)
    keys: dict[str, str] = Field(default_factory=dict)


class RuleReference(BaseModel):
    """Identity + version of the deterministic rule that produced a result."""

    rule_id: str
    version: str


class CorrelationComparison(BaseModel):
    """One deterministic per-property comparison within a capability run."""

    property: str
    result: CorrelationResult
    source_value: str | None = None
    runtime_value: str | None = None
    rule: RuleReference
    note: str | None = None


class CorrelationOutcome(BaseModel):
    """Final typed result of a correlation capability execution."""

    capability_id: str
    identity: CorrelatedIdentity
    result: CorrelationResult
    confidence: Confidence
    comparisons: list[CorrelationComparison] = Field(default_factory=list)
    source_evidence_id: EvidenceID | None = None
    runtime_evidence_id: EvidenceID | None = None
    correlation_evidence_id: EvidenceID | None = None
    disclaimer: str = (
        "A discrepancy is an observed difference between declared and observed "
        "state. It is not automatically a vulnerability, exploit, or finding."
    )


class SourceRuntimeRequest(BaseModel):
    """Authorized source & runtime correlation request context.

    ``max_observations`` bounds the number of captured observations; the scope
    travels with the request so every capability invocation is checked against
    the same authorization boundary regardless of caller.
    """

    mission_id: MissionID
    scope: TargetScope
    session_id: SessionID | None = None
    mode: SourceRuntimeMode = SourceRuntimeMode.CONTROLLED
    max_observations: int = Field(default=500, ge=1, le=10_000)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_comparisons: int = Field(default=1000, ge=1, le=10_000)


class SourceRuntimeResult(BaseModel):
    """Structured, deterministic outcome of a source/runtime correlation run."""

    mission_id: MissionID
    session_id: SessionID | None
    target: str
    capability_id: str
    mode: SourceRuntimeMode
    status: SourceRuntimeStatus = SourceRuntimeStatus.SUCCESS
    outcomes: list[CorrelationOutcome] = Field(default_factory=list)
    evidence_ids: list[EvidenceID] = Field(default_factory=list)
    raw_output: str | None = None
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0
    authorized: bool = True
    created_at: float = Field(default_factory=time.time)

    @property
    def observation_count(self) -> int:
        return len(self.outcomes)


__all__ = [
    "CorrelatedIdentity",
    "CorrelationComparison",
    "CorrelationOutcome",
    "CorrelationProperty",
    "CorrelationResult",
    "RuleReference",
    "Side",
    "SourceRuntimeMode",
    "SourceRuntimeRequest",
    "SourceRuntimeResult",
    "SourceRuntimeStatus",
    "SourceValue",
]
