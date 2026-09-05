from blackforge.world_model.canonical import (
    build_entity_canonical_key,
    build_relationship_canonical_key,
    compute_entity_dedup_key,
    compute_relationship_dedup_key,
    normalize_entity_name,
    normalize_hostname_or_ip,
    normalize_network,
)
from blackforge.world_model.materializer import EntityFact, RelationshipFact, WorldMaterializer
from blackforge.world_model.models import (
    EntitySpec,
    EntityType,
    EvidenceLinkRef,
    RelationshipSpec,
    RelationshipType,
    WorldAssertion,
    WorldEntity,
    WorldLifecycle,
    WorldMutation,
    WorldRelationship,
)
from blackforge.world_model.query import (
    NeighborhoodResult,
    RelationshipQuery,
    WorldQuery,
)
from blackforge.world_model.repository import (
    InMemoryWorldRepository,
    SQLiteWorldRepository,
    WorldRepository,
)
from blackforge.world_model.store import WorldModelStore

__all__ = [
    "EntityFact",
    "EntitySpec",
    "EntityType",
    "EvidenceLinkRef",
    "InMemoryWorldRepository",
    "NeighborhoodResult",
    "RelationshipFact",
    "RelationshipQuery",
    "RelationshipSpec",
    "RelationshipType",
    "SQLiteWorldRepository",
    "WorldAssertion",
    "WorldEntity",
    "WorldLifecycle",
    "WorldMaterializer",
    "WorldModelStore",
    "WorldMutation",
    "WorldQuery",
    "WorldRelationship",
    "WorldRepository",
    "build_entity_canonical_key",
    "build_relationship_canonical_key",
    "compute_entity_dedup_key",
    "compute_relationship_dedup_key",
    "normalize_entity_name",
    "normalize_hostname_or_ip",
    "normalize_network",
]
