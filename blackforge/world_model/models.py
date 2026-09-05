from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, Field

from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    MissionID,
    SessionID,
    WorldAssertionID,
    WorldEntityID,
    WorldRelationshipID,
)


class EntityType(str, Enum):
    """Typed, extensible world model entity kinds.

    These cover the Phase 4 foundation; the enum can grow without changing
    the persistence or query layers. Attack-graph-only concepts (e.g. an
    ``EXPLOIT``) are deliberately absent.
    """

    ASSET = "asset"
    SERVICE = "service"
    APPLICATION = "application"
    ENDPOINT = "endpoint"
    API = "api"
    IDENTITY = "identity"
    ROLE = "role"
    PERMISSION = "permission"
    RESOURCE = "resource"
    AUTHENTICATION = "authentication"
    TECHNOLOGY = "technology"
    NETWORK = "network"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    SOURCE_COMPONENT = "source_component"
    DATA_STORE = "data_store"
    TRUST_RELATION = "trust_relation"


class RelationshipType(str, Enum):
    """Typed, directional relationships between world model entities.

    Deliberately limited to descriptive/structural edges. Offensive
    semantics (LEADS_TO, ENABLES, CAN_COMPROMISE, EXPLOITS,
    PRIVILEGE_ESCALATION_PATH) belong to a future Attack-Graph layer and are
    NOT accepted here.
    """

    HOSTS = "hosts"
    EXPOSES = "exposes"
    RUNS = "runs"
    DEPENDS_ON = "depends_on"
    CALLS = "calls"
    CONNECTS_TO = "connects_to"
    AUTHENTICATES_TO = "authenticates_to"
    AUTHORIZED_FOR = "authorized_for"
    HAS_ROLE = "has_role"
    HAS_PERMISSION = "has_permission"
    APPLIES_TO = "applies_to"
    REQUIRES = "requires"
    BELONGS_TO = "belongs_to"
    CONTAINS = "contains"
    USES = "uses"
    LOCATED_IN = "located_in"
    TRUSTS = "trusts"
    ASSOCIATED_WITH = "associated_with"


class WorldLifecycle(str, Enum):
    """Lifecycle of a world model record.

    ``WorldLifecycle`` answers *what is the record's state in the model*,
    distinct from its epistemic status (``EvidenceStatus``: how we know).
    A record can be OBSERVED yet later SUPERSEDED; history stays visible.
    """

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ARCHIVED = "archived"


class WorldMutation(str, Enum):
    """Outcome of a world model mutation.

    * ``CREATED`` — a brand-new entity/relationship.
    * ``CORROBORATED`` — same identity + same content; evidence merged.
    * ``SUPERSEDED`` — newer authoritative observation replaced the previous
      record; history preserved.
    * ``CONTRADICTION_RECORDED`` — a weaker/hypothetical input conflicted with
      the authoritative record; the claim was stored as an assertion instead
      of silently overwriting.
    * ``NOOP`` — nothing to do (evidence already attached).
    """

    CREATED = "created"
    CORROBORATED = "corroborated"
    SUPERSEDED = "superseded"
    CONTRADICTION_RECORDED = "contradiction_recorded"
    NOOP = "noop"


class WorldEntity(BaseModel):
    """A single modeled entity.

    Identity is a deterministic canonical key scoped to
    ``(mission_id, entity_type, namespace, normalized_name)``; the internal
    ``id`` is only a storage handle, never the dedup basis.
    """

    id: WorldEntityID = Field(default_factory=WorldEntityID)
    mission_id: MissionID
    session_id: SessionID | None = None
    entity_type: EntityType
    namespace: str | None = None
    canonical_key: str
    dedup_key: str | None = None
    name: str
    properties: dict = Field(default_factory=dict)
    epistemic_status: EvidenceStatus = EvidenceStatus.OBSERVED
    lifecycle: WorldLifecycle = WorldLifecycle.ACTIVE
    confidence: Confidence = Confidence.MEDIUM
    version: int = 1
    supersedes: WorldEntityID | None = None
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)
    updated_at: float | None = None


class WorldRelationship(BaseModel):
    """A typed, directional edge between two world model entities."""

    id: WorldRelationshipID = Field(default_factory=WorldRelationshipID)
    mission_id: MissionID
    session_id: SessionID | None = None
    relationship_type: RelationshipType
    source_entity_id: WorldEntityID
    target_entity_id: WorldEntityID
    dedup_key: str | None = None
    note: str | None = None
    lifecycle: WorldLifecycle = WorldLifecycle.ACTIVE
    confidence: Confidence = Confidence.MEDIUM
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)
    updated_at: float | None = None


class WorldAssertion(BaseModel):
    """A property-level belief bound to an existing entity.

    Used to record *weaker* claims (INFERRED/HYPOTHESIZED) that conflict with
    the authoritative current state, so the conflict is preserved without
    overwriting the observed fact. Also usable for standalone property
    observations.
    """

    id: WorldAssertionID = Field(default_factory=WorldAssertionID)
    mission_id: MissionID
    session_id: SessionID | None = None
    entity_id: WorldEntityID
    property_key: str
    property_value: str | None = None
    epistemic_status: EvidenceStatus = EvidenceStatus.HYPOTHESIZED
    lifecycle: WorldLifecycle = WorldLifecycle.ACTIVE
    confidence: Confidence = Confidence.LOW
    dedup_key: str | None = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float | None = None


class EvidenceLinkRef(BaseModel):
    """A property-level evidence reference bound to an entity or relationship.

    ``property_key``/``property_value`` are optional: they enable precise
    provenance (e.g. ``port=443`` supported by evidence ``E1``). When absent
    the reference is a row-level support link.
    """

    evidence_id: EvidenceID
    property_key: str | None = None
    property_value: str | None = None
    note: str | None = None


class EntitySpec(BaseModel):
    """Planned entity mutation accepted by :class:`WorldModelStore`."""

    mission_id: MissionID
    session_id: SessionID | None = None
    entity_type: EntityType
    name: str
    namespace: str | None = None
    properties: dict = Field(default_factory=dict)
    epistemic_status: EvidenceStatus = EvidenceStatus.OBSERVED
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[EvidenceLinkRef] = Field(default_factory=list)


class RelationshipSpec(BaseModel):
    """Planned relationship mutation accepted by :class:`WorldModelStore`."""

    mission_id: MissionID
    session_id: SessionID | None = None
    relationship_type: RelationshipType
    source_entity_id: WorldEntityID
    target_entity_id: WorldEntityID
    note: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[EvidenceLinkRef] = Field(default_factory=list)


class AssertionSpec(BaseModel):
    """Planned assertion bound to an existing entity."""

    mission_id: MissionID
    session_id: SessionID | None = None
    entity_id: WorldEntityID
    property_key: str
    property_value: str | None = None
    epistemic_status: EvidenceStatus = EvidenceStatus.HYPOTHESIZED
    confidence: Confidence = Confidence.LOW
    evidence: list[EvidenceLinkRef] = Field(default_factory=list)


class EntityMutationResult(BaseModel):
    """Outcome record for an entity mutation."""

    action: WorldMutation
    entity: WorldEntity
    previous: WorldEntity | None = None
    assertion: WorldAssertion | None = None


class RelationshipMutationResult(BaseModel):
    """Outcome record for a relationship mutation."""

    action: WorldMutation
    relationship: WorldRelationship
    previous: WorldRelationship | None = None


class AssertionMutationResult(BaseModel):
    """Outcome record for an assertion mutation."""

    action: WorldMutation
    assertion: WorldAssertion
    previous: WorldAssertion | None = None
