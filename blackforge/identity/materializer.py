from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    MissionID,
    SessionID,
)
from blackforge.identity.models import (
    DirectoryObservation,
    GroupObservation,
    IdentityObservation,
    MembershipObservation,
    MetadataObservation,
    Observation,
    PermissionAssignmentObservation,
    PermissionObservation,
    RelationshipObservation,
    ResourceObservation,
    RoleAssignmentObservation,
    RoleObservation,
)
from blackforge.identity.redaction import redact_identity_document  # noqa: F401
from blackforge.world_model.materializer import (
    EntityFact,
    RelationshipFact,
    WorldMaterializer,
)
from blackforge.world_model.models import (
    AssertionSpec,
    EntityType,
    EvidenceLinkRef,
    RelationshipType,
    WorldEntity,
    WorldLifecycle,
)

if TYPE_CHECKING:
    from blackforge.world_model.store import WorldModelStore

_OBSERVED = [EvidenceStatus.OBSERVED]

_RELATIONSHIP_CONTAINS = RelationshipType.CONTAINS


def _ref(evidence_id: EvidenceID, **properties: str | None) -> EvidenceLinkRef:
    return EvidenceLinkRef(
        evidence_id=evidence_id,
        property_key=properties.get("property_key"),
        property_value=properties.get("property_value"),
    )


class IdentityMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class IdentityMaterializeReport(BaseModel):
    entries: list[IdentityMaterializeEntry] = Field(default_factory=list)
    relationships_created: int = 0
    relationships_corroborated: int = 0
    assertions_created: int = 0
    assertions_corroborated: int = 0
    assertions_contradicted: int = 0

    @property
    def entities_created(self) -> int:
        return sum(1 for e in self.entries if e.action == "created")

    @property
    def entities_updated(self) -> int:
        return len(self.entries) - self.entities_created


class IdentityWorldMaterializer:
    """Maps typed identity observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text.
    Identity-bearing entities are namespaced by directory so same-named
    principals across directories (or across assets) stay distinct:

    * DIRECTORY --CONTAINS--> GROUP / IDENTITY / ROLE / PERMISSION / RESOURCE
    * IDENTITY --MEMBER_OF--> GROUP
    * IDENTITY --HAS_ROLE--> ROLE
    * ROLE --HAS_PERMISSION--> PERMISSION
    * PERMISSION --APPLIES_TO--> RESOURCE
    * Metadata becomes an assertion on the identity entity; correlated feeds
      are recorded at INFERRED status so a weak claim never silently
      overwrites an authoritative record (contradiction is surfaced, not
      hidden).

    All edges are descriptive/structural. No offensive semantics (EXPLOITS,
    CAN_COMPROMISE, LEADS_TO, ENABLES) are ever produced here.
    """

    def __init__(self, store: WorldModelStore) -> None:
        self._store = store
        self._materializer = WorldMaterializer(store)

    @property
    def store(self) -> WorldModelStore:
        return self._store

    def materialize(
        self,
        mission_id: MissionID,
        observations: list[tuple[Observation, EvidenceID, Confidence]],
        *,
        session_id: SessionID | None = None,
    ) -> IdentityMaterializeReport:
        report = IdentityMaterializeReport()
        for observation, evidence_id, confidence in observations:
            self._materialize_one(
                mission_id,
                observation,
                evidence_id,
                confidence,
                report,
                session_id=session_id,
            )
        return report

    # ------------------------------------------------------------------
    # Per-kind mapping
    # ------------------------------------------------------------------
    def _materialize_one(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: IdentityMaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        mapper = {
            DirectoryObservation: self._materialize_directory,
            IdentityObservation: self._materialize_identity,
            GroupObservation: self._materialize_group,
            RoleObservation: self._materialize_role,
            PermissionObservation: self._materialize_permission,
            ResourceObservation: self._materialize_resource,
            MembershipObservation: self._materialize_membership,
            RoleAssignmentObservation: self._materialize_role_assignment,
            PermissionAssignmentObservation: self._materialize_permission_assignment,
            RelationshipObservation: self._materialize_relationship,
            MetadataObservation: self._materialize_metadata,
        }
        materializer = mapper.get(type(observation))
        if materializer is not None:
            materializer(
                mission_id,
                observation,
                evidence_id,
                confidence,
                report,
                session_id=session_id,
            )

    # ------------------------------------------------------------------
    # Inventory records
    # ------------------------------------------------------------------
    def _materialize_directory(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        directory, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.DIRECTORY,
                name=obs.directory,
                namespace=None,
                properties={
                    "directory": obs.directory,
                    "dns_name": obs.dns_name,
                    "directory_type": obs.directory_type,
                    "forest": obs.forest,
                    "source": "identity.directory_discovery",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        report.entries.append(
            IdentityMaterializeEntry(
                entity_type="directory",
                name=directory.name,
                namespace=None,
                entity_id=str(directory.id),
                action=action,
            )
        )

    def _materialize_identity(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.IDENTITY,
                name=obs.identity,
                namespace=obs.directory,
                properties={
                    "identity": obs.identity,
                    "principal_type": obs.principal_type,
                    "display_name": obs.display_name,
                    "email": obs.email,
                    "enabled": obs.enabled,
                    "locked": obs.locked,
                    "privilege_level": obs.privilege_level,
                    "source": "identity.identity_inventory",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        directory = self._ensure_directory(
            mission_id, obs.directory, evidence_id, confidence, session_id
        )
        if directory is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=_RELATIONSHIP_CONTAINS,
                    source_entity_id=str(directory.id),
                    target_entity_id=str(entity.id),
                    note="directory contains identity",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            IdentityMaterializeEntry(
                entity_type="identity",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_group(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.GROUP,
                name=obs.group,
                namespace=obs.directory,
                properties={
                    "group": obs.group,
                    "scope_type": obs.scope_type,
                    "membership_count": obs.membership_count,
                    "source": "identity.group_inventory",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        directory = self._ensure_directory(
            mission_id, obs.directory, evidence_id, confidence, session_id
        )
        if directory is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=_RELATIONSHIP_CONTAINS,
                    source_entity_id=str(directory.id),
                    target_entity_id=str(entity.id),
                    note="directory contains group",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            IdentityMaterializeEntry(
                entity_type="group",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_role(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ROLE,
                name=obs.role,
                namespace=obs.directory,
                properties={
                    "role": obs.role,
                    "privilege_level": obs.privilege_level,
                    "source": "identity.role_inventory",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        directory = self._ensure_directory(
            mission_id, obs.directory, evidence_id, confidence, session_id
        )
        if directory is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=_RELATIONSHIP_CONTAINS,
                    source_entity_id=str(directory.id),
                    target_entity_id=str(entity.id),
                    note="directory contains role",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            IdentityMaterializeEntry(
                entity_type="role",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_permission(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.PERMISSION,
                name=obs.permission,
                namespace=obs.directory,
                properties={
                    "permission": obs.permission,
                    "source": "identity.permission_inventory",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        directory = self._ensure_directory(
            mission_id, obs.directory, evidence_id, confidence, session_id
        )
        if directory is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=_RELATIONSHIP_CONTAINS,
                    source_entity_id=str(directory.id),
                    target_entity_id=str(entity.id),
                    note="directory contains permission",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            IdentityMaterializeEntry(
                entity_type="permission",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_resource(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.RESOURCE,
                name=obs.resource,
                namespace=obs.directory,
                properties={
                    "resource": obs.resource,
                    "resource_type": obs.resource_type,
                    "source": "identity.resource_inventory",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        directory = self._ensure_directory(
            mission_id, obs.directory, evidence_id, confidence, session_id
        )
        if directory is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=_RELATIONSHIP_CONTAINS,
                    source_entity_id=str(directory.id),
                    target_entity_id=str(entity.id),
                    note="directory contains resource",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            IdentityMaterializeEntry(
                entity_type="resource",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    # ------------------------------------------------------------------
    # Identity-level records
    # ------------------------------------------------------------------
    def _materialize_membership(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        if not obs.resolved:
            return
        identity = self._ensure_endpoint(
            mission_id,
            EntityType.IDENTITY,
            obs.identity,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.membership_observation",
        )
        group = self._ensure_endpoint(
            mission_id,
            EntityType.GROUP,
            obs.group,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.membership_observation",
        )
        if identity is None or group is None:
            return
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.MEMBER_OF,
                source_entity_id=str(identity.id),
                target_entity_id=str(group.id),
                note="identity member of group",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    def _materialize_role_assignment(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        identity = self._ensure_endpoint(
            mission_id,
            EntityType.IDENTITY,
            obs.identity,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.role_assignment_observation",
        )
        role = self._ensure_endpoint(
            mission_id,
            EntityType.ROLE,
            obs.role,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.role_assignment_observation",
        )
        if identity is None or role is None:
            return
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_ROLE,
                source_entity_id=str(identity.id),
                target_entity_id=str(role.id),
                note="identity has role",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    def _materialize_permission_assignment(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        role = self._ensure_endpoint(
            mission_id,
            EntityType.ROLE,
            obs.role,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.permission_assignment_observation",
        )
        permission = self._ensure_endpoint(
            mission_id,
            EntityType.PERMISSION,
            obs.permission,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.permission_assignment_observation",
        )
        if role is None or permission is None:
            return
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_PERMISSION,
                source_entity_id=str(role.id),
                target_entity_id=str(permission.id),
                note="role has permission",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    def _materialize_relationship(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        source_type, target_type, relationship_type = _relationship_contract(obs)
        if relationship_type is None:
            return
        source = self._ensure_endpoint(
            mission_id,
            source_type,
            obs.source,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.relationship_analysis",
        )
        target = self._ensure_endpoint(
            mission_id,
            target_type,
            obs.target,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.relationship_analysis",
        )
        if source is None or target is None:
            return
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=relationship_type,
                source_entity_id=str(source.id),
                target_entity_id=str(target.id),
                note="relationship analysis edge",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    def _materialize_metadata(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        identity = self._ensure_endpoint(
            mission_id,
            EntityType.IDENTITY,
            obs.identity,
            obs.directory,
            evidence_id,
            confidence,
            session_id,
            "identity.metadata_observation",
        )
        if identity is None:
            return
        authoritative = obs.source == "directory"
        status = EvidenceStatus.OBSERVED if authoritative else EvidenceStatus.INFERRED
        self._add_metadata_assertion(
            mission_id,
            session_id,
            identity,
            obs.attribute_key,
            obs.attribute_value,
            obs.source,
            status,
            confidence,
            evidence_id,
            report,
        )

    def _add_metadata_assertion(
        self,
        mission_id: MissionID,
        session_id: SessionID | None,
        entity: WorldEntity,
        key: str,
        value: str | None,
        source: str | None,
        status: EvidenceStatus,
        confidence: Confidence,
        evidence_id: EvidenceID,
        report: IdentityMaterializeReport,
    ) -> None:
        existing = self._store.list_assertions(str(entity.id), lifecycle=WorldLifecycle.ACTIVE)
        conflicts = [
            assertion
            for assertion in existing
            if assertion.property_key == key
            and assertion.property_value != value
        ]
        result = self._store.add_assertion(
            AssertionSpec(
                mission_id=mission_id,
                session_id=session_id,
                entity_id=entity.id,
                property_key=key,
                property_value=value,
                epistemic_status=status,
                confidence=confidence,
                evidence=[_ref(evidence_id, property_key=key, property_value=value)],
            )
        )
        if result.action.value == "created":
            if conflicts:
                report.assertions_contradicted += 1
            else:
                report.assertions_created += 1
        else:
            report.assertions_corroborated += 1

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _link_report(self, mission_id, fact, report, session_id) -> None:
        result = self._materializer.materialize_relationship(mission_id, fact, session_id)
        if result.action.value == "created":
            report.relationships_created += 1
        else:
            report.relationships_corroborated += 1

    def _upsert_entity(self, mission_id, fact, session_id) -> tuple[WorldEntity, str]:
        result = self._materializer.materialize_entity(
            mission_id, fact, _OBSERVED, session_id
        )
        return result.entity, result.action.value

    def _ensure_endpoint(
        self,
        mission_id: MissionID,
        entity_type: EntityType,
        name: str,
        directory: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
        source: str,
    ) -> WorldEntity | None:
        found = self._store.find_entity(
            mission_id, entity_type, name, namespace=directory
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=entity_type,
                name=name,
                namespace=directory,
                properties={"source": source},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _ensure_directory(
        self,
        mission_id: MissionID,
        directory: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        found = self._store.find_entity(mission_id, EntityType.DIRECTORY, directory)
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.DIRECTORY,
                name=directory,
                namespace=None,
                properties={"directory": directory, "source": "identity"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity


def _relationship_contract(
    obs: RelationshipObservation,
) -> tuple[EntityType, EntityType, RelationshipType | None]:
    """Deterministic entity-type and edge contract for a relationship row."""
    if obs.relationship_type == "member_of":
        return EntityType.IDENTITY, EntityType.GROUP, RelationshipType.MEMBER_OF
    if obs.relationship_type == "has_role":
        return EntityType.IDENTITY, EntityType.ROLE, RelationshipType.HAS_ROLE
    if obs.relationship_type == "has_permission":
        return EntityType.ROLE, EntityType.PERMISSION, RelationshipType.HAS_PERMISSION
    if obs.relationship_type == "applies_to":
        return EntityType.PERMISSION, EntityType.RESOURCE, RelationshipType.APPLIES_TO
    return EntityType.ASSET, EntityType.ASSET, None


__all__ = [
    "IdentityMaterializeEntry",
    "IdentityMaterializeReport",
    "IdentityWorldMaterializer",
]
