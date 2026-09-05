from pydantic import BaseModel, Field

from blackforge.core.types import (
    EvidenceStatus,
    MissionID,
    SessionID,
)
from blackforge.world_model.models import (
    EntityType,
    RelationshipType,
    WorldEntity,
    WorldLifecycle,
    WorldRelationship,
)


class WorldQuery(BaseModel):
    """Deterministic world model query filters.

    ``mission_id`` is the mandatory isolation boundary — no operation may
    observe records from another mission without an explicit mission context.
    Session is an optional narrowing filter within the mission.
    """

    mission_id: MissionID
    entity_type: EntityType | None = None
    session_id: SessionID | None = None
    namespace: str | None = None
    epistemic_status: EvidenceStatus | None = None
    lifecycle: WorldLifecycle | None = None
    name_contains: str | None = None
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class RelationshipQuery(BaseModel):
    """Relationship filters; the mission is the isolation boundary."""

    mission_id: MissionID
    relationship_type: RelationshipType | None = None
    source_entity_id: str | None = None
    target_entity_id: str | None = None
    lifecycle: WorldLifecycle | None = None
    limit: int = Field(default=50, ge=1, le=1000)


class NeighborhoodResult(BaseModel):
    """Bounded one-hop (up to ``max_depth``) view around an entity.

    Offensive pathfinding is explicitly out of scope: results are a
    deterministic, bounded set of entities and typed relationships, sorted by
    ``(relationship_type, canonical_key, id)``.
    """

    entity: WorldEntity
    depth: int
    entities: list[WorldEntity] = Field(default_factory=list)
    relationships: list[WorldRelationship] = Field(default_factory=list)
