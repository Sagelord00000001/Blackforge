from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from blackforge.cloud.addressing import AddressType, classify_address
from blackforge.cloud.canonical import cloud_namespace
from blackforge.cloud.models import (
    AccountObservation,
    CloudObservation,
    CloudResourceObservation,
    CloudResourceType,
    ClusterObservation,
    ComputeObservation,
    ContainerObservation,
    DatabaseObservation,
    EdgeArchitectureObservation,
    IamIdentityObservation,
    IamPermissionObservation,
    IamRoleObservation,
    NetworkObservation,
    OriginCandidateObservation,
    ProjectObservation,
    ProviderObservation,
    PublicExposureObservation,
    ResourceRelationshipObservation,
    SecretReferenceObservation,
    SecurityConfigurationObservation,
    StorageObservation,
    TransportSecurityObservation,
)
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    MissionID,
    SessionID,
)
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

_CLOUD_TYPE_ENTITY: dict[CloudResourceType, EntityType] = {
    CloudResourceType.ACCOUNT: EntityType.CLOUD_ACCOUNT,
    CloudResourceType.SUBSCRIPTION: EntityType.CLOUD_ACCOUNT,
    CloudResourceType.ORGANIZATION: EntityType.CLOUD_RESOURCE,
    CloudResourceType.PROJECT: EntityType.CLOUD_PROJECT,
    CloudResourceType.REGION: EntityType.CLOUD_REGION,
    CloudResourceType.COMPUTE_INSTANCE: EntityType.CLOUD_COMPUTE,
    CloudResourceType.STORAGE_BUCKET: EntityType.CLOUD_STORAGE,
    CloudResourceType.STORAGE_DISK: EntityType.CLOUD_STORAGE,
    CloudResourceType.DATABASE: EntityType.CLOUD_DATABASE,
    CloudResourceType.VIRTUAL_NETWORK: EntityType.CLOUD_NETWORK,
    CloudResourceType.SUBNET: EntityType.CLOUD_NETWORK,
    CloudResourceType.SECURITY_GROUP: EntityType.CLOUD_NETWORK,
    CloudResourceType.FIREWALL_RULE: EntityType.CLOUD_NETWORK,
    CloudResourceType.LOAD_BALANCER: EntityType.CLOUD_NETWORK,
    CloudResourceType.CONTAINER: EntityType.CLOUD_CONTAINER,
    CloudResourceType.CLUSTER: EntityType.CLOUD_CLUSTER,
    CloudResourceType.SECRET: EntityType.CLOUD_SECRET,
    CloudResourceType.UNKNOWN: EntityType.CLOUD_RESOURCE,
}

_SECURITY_ENTITY_MAP: dict[str, EntityType] = {
    "provider": EntityType.CLOUD_PROVIDER,
    "account": EntityType.CLOUD_ACCOUNT,
    "subscription": EntityType.CLOUD_ACCOUNT,
    "project": EntityType.CLOUD_PROJECT,
    "region": EntityType.CLOUD_REGION,
    "compute": EntityType.CLOUD_COMPUTE,
    "storage": EntityType.CLOUD_STORAGE,
    "database": EntityType.CLOUD_DATABASE,
    "network": EntityType.CLOUD_NETWORK,
    "cluster": EntityType.CLOUD_CLUSTER,
    "container": EntityType.CLOUD_CONTAINER,
    "secret": EntityType.CLOUD_SECRET,
    "iam_identity": EntityType.IDENTITY,
    "iam_role": EntityType.ROLE,
    "iam_permission": EntityType.PERMISSION,
}

_RELATIONSHIP_CONTRACT: dict[str, RelationshipType] = {
    "contains": RelationshipType.CONTAINS,
    "uses": RelationshipType.USES,
    "depends_on": RelationshipType.DEPENDS_ON,
    "connects_to": RelationshipType.CONNECTS_TO,
    "applies_to": RelationshipType.APPLIES_TO,
    "hosts": RelationshipType.HOSTS,
    "located_in": RelationshipType.LOCATED_IN,
    "belongs_to": RelationshipType.BELONGS_TO,
    "has_role": RelationshipType.HAS_ROLE,
    "has_permission": RelationshipType.HAS_PERMISSION,
    "associated_with": RelationshipType.ASSOCIATED_WITH,
}


def _endpoint_entity_name(endpoint: str) -> str:
    """Canonical URL-form name for a transport endpoint.

    World-model ENDPOINT names normalize as URLs; a bare hostname is
    promoted to ``https://`` so repeated references merge deterministically.
    """
    value = str(endpoint or "").strip()
    if not value:
        raise ValueError("empty transport endpoint")
    if "://" in value:
        return value
    return f"https://{value}"


def _ref(evidence_id: EvidenceID, **properties: str | None) -> EvidenceLinkRef:
    return EvidenceLinkRef(
        evidence_id=evidence_id,
        property_key=properties.get("property_key"),
        property_value=properties.get("property_value"),
    )


class CloudMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class CloudMaterializeReport(BaseModel):
    entries: list[CloudMaterializeEntry] = Field(default_factory=list)
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


class CloudWorldMaterializer:
    """Maps typed cloud observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text.
    Cloud entities are namespaced by ``provider/container`` so same-named
    resources across providers or accounts stay distinct:

    * PROVIDER --CONTAINS--> ACCOUNT --CONTAINS--> PROJECT
    * ACCOUNT --CONTAINS--> COMPUTE / STORAGE / DATABASE / NETWORK /
      CLUSTER / CONTAINER / SECRET / IDENTITY / ROLE / PERMISSION
    * resource --LOCATED_IN--> REGION
    * IAM entities reuse the shared IDENTITY / ROLE / PERMISSION kinds,
      namespaced per provider/account.
    * Public exposure and security configuration map to assertions on the
      referenced entity; correlated feeds are INFERRED so a weak claim
      never silently overwrites an authoritative record (contradiction is
      surfaced, not hidden).

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
        observations: list[tuple[CloudObservation, EvidenceID, Confidence]],
        *,
        session_id: SessionID | None = None,
    ) -> CloudMaterializeReport:
        report = CloudMaterializeReport()
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
        observation: CloudObservation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: CloudMaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        mapper = {
            ProviderObservation: self._materialize_provider,
            AccountObservation: self._materialize_account,
            ProjectObservation: self._materialize_project,
            CloudResourceObservation: self._materialize_cloud_resource,
            ComputeObservation: self._materialize_resource,
            StorageObservation: self._materialize_resource,
            DatabaseObservation: self._materialize_resource,
            NetworkObservation: self._materialize_resource,
            ClusterObservation: self._materialize_resource,
            ContainerObservation: self._materialize_resource,
            SecretReferenceObservation: self._materialize_secret_reference,
            IamIdentityObservation: self._materialize_iam_identity,
            IamRoleObservation: self._materialize_iam_role,
            IamPermissionObservation: self._materialize_iam_permission,
            PublicExposureObservation: self._materialize_public_exposure,
            SecurityConfigurationObservation: self._materialize_security_config,
            ResourceRelationshipObservation: self._materialize_relationship,
            EdgeArchitectureObservation: self._materialize_edge_architecture,
            OriginCandidateObservation: self._materialize_origin_candidate,
            TransportSecurityObservation: self._materialize_transport_security,
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

    def _container_namespace(self, obs: CloudObservation) -> str:
        container = getattr(obs, "project", None) or obs.account
        return cloud_namespace(obs.provider.value, container or "root")

    def _container_entity_type(self, obs: CloudObservation) -> EntityType:
        if getattr(obs, "project", None):
            return EntityType.CLOUD_PROJECT
        return EntityType.CLOUD_ACCOUNT

    # ------------------------------------------------------------------
    # Containment backbone
    # ------------------------------------------------------------------
    def _materialize_provider(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLOUD_PROVIDER,
                name=obs.provider.value,
                namespace=None,
                properties={
                    "provider": obs.provider.value,
                    "container_type": obs.container_type,
                    "accounts": obs.accounts,
                    "source": "cloud.provider_discovery",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="cloud_provider",
                name=entity.name,
                namespace=None,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_account(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLOUD_ACCOUNT,
                name=obs.account,
                namespace=obs.provider.value,
                properties={
                    "account": obs.account,
                    "container_type": obs.container_type,
                    "account_id": obs.account_id,
                    "source": "cloud.account_inventory",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        provider = self._ensure_provider(
            mission_id, obs.provider.value, evidence_id, confidence, session_id
        )
        if provider is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(provider.id),
                    target_entity_id=str(entity.id),
                    note="provider contains account",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="cloud_account",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_project(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = cloud_namespace(
            obs.provider.value, obs.account or obs.project
        )
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLOUD_PROJECT,
                name=obs.project,
                namespace=namespace,
                properties={
                    "project": obs.project,
                    "project_type": obs.project_type,
                    "source": "cloud.project_inventory",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        account = self._ensure_account(
            mission_id, obs, obs.account, evidence_id, confidence, session_id
        )
        if account is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(account.id),
                    target_entity_id=str(entity.id),
                    note="account contains project",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="cloud_project",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_cloud_resource(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity_type = _CLOUD_TYPE_ENTITY.get(
            obs.resource_type, EntityType.CLOUD_RESOURCE
        )
        self._materialize_named_resource(
            mission_id,
            obs,
            entity_type,
            obs.name,
            evidence_id,
            confidence,
            report,
            session_id,
            properties={
                "name": obs.name,
                "resource_type": obs.resource_type.value,
                "source": "cloud.resource_inventory",
            },
        )

    def _materialize_resource(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity_type = {
            ComputeObservation: EntityType.CLOUD_COMPUTE,
            StorageObservation: EntityType.CLOUD_STORAGE,
            DatabaseObservation: EntityType.CLOUD_DATABASE,
            NetworkObservation: EntityType.CLOUD_NETWORK,
            ClusterObservation: EntityType.CLOUD_CLUSTER,
            ContainerObservation: EntityType.CLOUD_CONTAINER,
        }[type(obs)]
        kind = obs.kind
        self._materialize_named_resource(
            mission_id,
            obs,
            entity_type,
            obs.name,
            evidence_id,
            confidence,
            report,
            session_id,
            properties={
                "name": obs.name,
                "kind": kind,
                "source": f"cloud.{kind}",
            },
        )

    def _materialize_named_resource(
        self,
        mission_id,
        obs,
        entity_type,
        name,
        evidence_id,
        confidence,
        report,
        session_id,
        *,
        properties,
    ):
        namespace = self._container_namespace(obs)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=entity_type,
                name=name,
                namespace=namespace,
                properties=properties,
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        container = self._ensure_container(
            mission_id, obs, evidence_id, confidence, session_id
        )
        if container is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(container.id),
                    target_entity_id=str(entity.id),
                    note="container contains resource",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        region = self._ensure_region(
            mission_id, obs, evidence_id, confidence, session_id
        )
        if region is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.LOCATED_IN,
                    source_entity_id=str(entity.id),
                    target_entity_id=str(region.id),
                    note="resource located in region",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type=entity_type.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_secret_reference(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLOUD_SECRET,
                name=obs.name,
                namespace=self._container_namespace(obs),
                properties={
                    "name": obs.name,
                    "secret_kind": obs.secret_kind,
                    "reference": obs.reference,
                    "source": "cloud.secret_reference_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        container = self._ensure_container(
            mission_id, obs, evidence_id, confidence, session_id
        )
        if container is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(container.id),
                    target_entity_id=str(entity.id),
                    note="container contains secret",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="cloud_secret",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    # ------------------------------------------------------------------
    # IAM records (reuse shared entity kinds)
    # ------------------------------------------------------------------
    def _materialize_iam_identity(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = cloud_namespace(obs.provider.value, obs.account)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.IDENTITY,
                name=obs.identity,
                namespace=namespace,
                properties={
                    "identity": obs.identity,
                    "principal_type": obs.principal_type,
                    "enabled": obs.enabled,
                    "mfa_enabled": obs.mfa_enabled,
                    "source": "cloud.iam_identity_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        container = self._ensure_container(
            mission_id, obs, evidence_id, confidence, session_id
        )
        if container is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(container.id),
                    target_entity_id=str(entity.id),
                    note="container contains identity",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="identity",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_iam_role(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = cloud_namespace(obs.provider.value, obs.account)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ROLE,
                name=obs.role,
                namespace=namespace,
                properties={
                    "role": obs.role,
                    "description": obs.description,
                    "source": "cloud.iam_role_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        container = self._ensure_container(
            mission_id, obs, evidence_id, confidence, session_id
        )
        if container is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(container.id),
                    target_entity_id=str(entity.id),
                    note="container contains role",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="role",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_iam_permission(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = cloud_namespace(obs.provider.value, obs.account)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.PERMISSION,
                name=obs.permission,
                namespace=namespace,
                properties={
                    "permission": obs.permission,
                    "effect": obs.effect,
                    "action": obs.action,
                    "source": "cloud.iam_permission_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        container = self._ensure_container(
            mission_id, obs, evidence_id, confidence, session_id
        )
        if container is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(container.id),
                    target_entity_id=str(entity.id),
                    note="container contains permission",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="permission",
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    # ------------------------------------------------------------------
    # Derived records
    # ------------------------------------------------------------------
    def _materialize_public_exposure(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity_type = _CLOUD_TYPE_ENTITY.get(
            obs.resource_type, EntityType.CLOUD_RESOURCE
        )
        resource = self._ensure_endpoint(
            mission_id,
            entity_type,
            obs.resource,
            self._container_namespace(obs),
            evidence_id,
            confidence,
            session_id,
            "cloud.public_exposure_analysis",
        )
        if resource is None:
            return
        self._add_metadata_assertion(
            mission_id,
            session_id,
            resource,
            "public_exposure",
            str(obs.exposed),
            "derived",
            EvidenceStatus.INFERRED,
            confidence,
            evidence_id,
            report,
        )
        region = self._ensure_region(
            mission_id, obs, evidence_id, confidence, session_id
        )
        if region is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.LOCATED_IN,
                    source_entity_id=str(resource.id),
                    target_entity_id=str(region.id),
                    note="resource located in region",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )

    def _materialize_security_config(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        entity_type = _SECURITY_ENTITY_MAP.get(
            obs.entity_type or "", EntityType.CLOUD_RESOURCE
        )
        namespace = (
            obs.provider.value
            if entity_type == EntityType.CLOUD_ACCOUNT
            else self._container_namespace(obs)
        )
        entity = self._ensure_endpoint(
            mission_id,
            entity_type,
            obs.entity,
            namespace,
            evidence_id,
            confidence,
            session_id,
            "cloud.security_configuration_observation",
        )
        if entity is None:
            return
        authoritative = obs.source == "provider"
        status = EvidenceStatus.OBSERVED if authoritative else EvidenceStatus.INFERRED
        self._add_metadata_assertion(
            mission_id,
            session_id,
            entity,
            obs.item,
            obs.value,
            obs.source,
            status,
            confidence,
            evidence_id,
            report,
        )

    def _materialize_relationship(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        relationship_type = _RELATIONSHIP_CONTRACT.get(obs.relationship_type)
        if relationship_type is None:
            return
        source_type = _CLOUD_TYPE_ENTITY.get(
            obs.source_type, EntityType.CLOUD_RESOURCE
        )
        target_type = _CLOUD_TYPE_ENTITY.get(
            obs.target_type, EntityType.CLOUD_RESOURCE
        )
        source = self._ensure_endpoint(
            mission_id,
            source_type,
            obs.source,
            self._container_namespace(obs),
            evidence_id,
            confidence,
            session_id,
            "cloud.resource_relationship_analysis",
        )
        target = self._ensure_endpoint(
            mission_id,
            target_type,
            obs.target,
            self._container_namespace(obs),
            evidence_id,
            confidence,
            session_id,
            "cloud.resource_relationship_analysis",
        )
        if source is None or target is None:
            return
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=relationship_type,
                source_entity_id=str(source.id),
                target_entity_id=str(target.id),
                note="resource relationship edge",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )

    # ------------------------------------------------------------------
    # Edge / origin / transport records
    # ------------------------------------------------------------------
    def _materialize_edge_architecture(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        """edge entity + origin-endpoint entities + structural relationships.

        * EDGE_ENDPOINT --PROTECTS--> application entity (backend service).
        * EDGE_ENDPOINT --PROXIES--> ORIGIN_ENDPOINT (each origin address).
        * ORIGIN_ENDPOINT --FRONTED_BY--> EDGE_ENDPOINT (the edge fronts the
          origin), making 'directly reachable' distinguishable from the
          presence of an edge.
        * ``directly_reachable_origin`` is asserted as INFERRED: an edge
          present is never proof of unreachability.
        """
        namespace = self._container_namespace(obs)
        edge_entity, edge_action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.EDGE_ENDPOINT,
                name=obs.edge,
                namespace=namespace,
                properties={
                    "edge": obs.edge,
                    "edge_kind": obs.edge_kind,
                    "domain": obs.domain,
                    "source": "cloud.edge_architecture_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="edge_endpoint",
                name=edge_entity.name,
                namespace=edge_entity.namespace,
                entity_id=str(edge_entity.id),
                action=edge_action,
            )
        )
        self._add_metadata_assertion(
            mission_id,
            session_id,
            edge_entity,
            "directly_reachable_origin",
            str(bool(obs.directly_reachable_origin)).lower(),
            "edge_architecture",
            EvidenceStatus.INFERRED,
            confidence,
            evidence_id,
            report,
        )
        origin_entities: list[WorldEntity] = []
        for origin_address in obs.origin_endpoints or []:
            origin_entity, origin_action = self._upsert_entity(
                mission_id,
                EntityFact(
                    entity_type=EntityType.ORIGIN_ENDPOINT,
                    name=origin_address,
                    namespace=namespace,
                    properties={
                        "address": origin_address,
                        "domain": obs.domain,
                        "source": "cloud.edge_architecture_observation",
                    },
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                session_id,
            )
            report.entries.append(
                CloudMaterializeEntry(
                    entity_type="origin_endpoint",
                    name=origin_entity.name,
                    namespace=origin_entity.namespace,
                    entity_id=str(origin_entity.id),
                    action=origin_action,
                )
            )
            origin_entities.append(origin_entity)
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.PROXIES,
                    source_entity_id=str(edge_entity.id),
                    target_entity_id=str(origin_entity.id),
                    note="edge proxies to origin endpoint",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.FRONTED_BY,
                    source_entity_id=str(origin_entity.id),
                    target_entity_id=str(edge_entity.id),
                    note="origin endpoint fronted by edge",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        for protected in obs.protected_applications or []:
            application = self._ensure_endpoint(
                mission_id,
                EntityType.CLOUD_COMPUTE,
                protected,
                namespace,
                evidence_id,
                confidence,
                session_id,
                "cloud.edge_architecture_observation",
            )
            if application is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.PROTECTS,
                        source_entity_id=str(edge_entity.id),
                        target_entity_id=str(application.id),
                        note="edge protects application",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )

    def _materialize_origin_candidate(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        """Origin-candidate hypotheses never upgrade to confirmed origins.

        The candidate entity is namespaced and named by the *candidate
        address* so every candidate stays distinct even when multiple
        candidates share one domain. The classified address (public vs
        private) is materialized as a separate ADDRESS entity joined by a
        ROUTES_TO edge; an ORIGINATES_FROM edge is only written when a real
        ORIGIN_ENDPOINT with the same address already exists in the store —
        correlation evidence, never confirmation.

        The observation's own evidence stage (observed/inferred/hypothesized)
        and validation status are preserved verbatim as assertions and never
        elevated by the analysis confidence.
        """
        namespace = self._container_namespace(obs)
        prefix = f"{obs.domain}:" if obs.domain else ""
        candidate, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ORIGIN_CANDIDATE,
                name=f"{prefix}{obs.candidate_address}",
                namespace=namespace,
                properties={
                    "domain": obs.domain,
                    "candidate_address": obs.candidate_address,
                    "candidate_endpoint": obs.candidate_endpoint,
                    "source_category": obs.source_category,
                    "correlation_reasons": obs.correlation_reasons,
                    "evidence_ids": obs.evidence_ids,
                    "authorization_requirements": obs.authorization_requirements,
                    "source": "cloud.origin_candidate_analysis",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        report.entries.append(
            CloudMaterializeEntry(
                entity_type="origin_candidate",
                name=candidate.name,
                namespace=candidate.namespace,
                entity_id=str(candidate.id),
                action=action,
            )
        )
        stage = EvidenceStatus.OBSERVED
        try:
            stage = EvidenceStatus(obs.evidence_status or "hypothesized")
        except ValueError:
            stage = EvidenceStatus.HYPOTHESIZED
        for key, value, value_status in (
            ("source_category", obs.source_category, stage),
            ("confidence_label", obs.confidence_label, stage),
            ("evidence_status", obs.evidence_status, stage),
            ("validation_status", obs.validation_status, stage),
        ):
            self._add_metadata_assertion(
                mission_id,
                session_id,
                candidate,
                key,
                value,
                "origin_candidate",
                value_status,
                confidence,
                evidence_id,
                report,
            )
        address_type = classify_address(obs.candidate_address)
        address_entity_type = (
            EntityType.PUBLIC_ADDRESS
            if address_type is AddressType.PUBLIC_ADDRESS
            else EntityType.PRIVATE_ADDRESS
        )
        address_entity = self._ensure_endpoint(
            mission_id,
            address_entity_type,
            obs.candidate_address,
            namespace,
            evidence_id,
            confidence,
            session_id,
            "cloud.origin_candidate_analysis",
        )
        if address_entity is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.ROUTES_TO,
                    source_entity_id=str(candidate.id),
                    target_entity_id=str(address_entity.id),
                    note="candidate address routes to classified address",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        origin = self._store.find_entity(
            mission_id,
            EntityType.ORIGIN_ENDPOINT,
            obs.candidate_address,
            namespace=namespace,
        )
        if origin is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.ORIGINATES_FROM,
                    source_entity_id=str(candidate.id),
                    target_entity_id=str(origin.id),
                    note="candidate correlated to existing origin endpoint",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )

    def _materialize_transport_security(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        """Attach TLS posture assertions to a known endpoint, else ENDPOINT.

        Boundary/address entities observed by the edge or candidate tools
        are preferred; a brand-new external hostname is materialized as a
        generic ENDPOINT. Conflicting rows (e.g. tls_enforced True vs False
        from different sources) are each asserted — surfaced as a
        contradiction, never overwritten.
        """
        namespace = self._container_namespace(obs)
        endpoint_name = _endpoint_entity_name(obs.endpoint)
        endpoint = self._store.find_entity(
            mission_id,
            EntityType.EDGE_ENDPOINT,
            obs.endpoint,
            namespace=namespace,
        )
        if endpoint is None:
            endpoint = self._store.find_entity(
                mission_id,
                EntityType.ORIGIN_ENDPOINT,
                obs.endpoint,
                namespace=namespace,
            )
        if endpoint is None:
            endpoint = self._store.find_entity(
                mission_id,
                EntityType.ENDPOINT,
                endpoint_name,
                namespace=namespace,
            )
        if endpoint is None:
            created = self._materializer.materialize_entity(
                mission_id,
                EntityFact(
                    entity_type=EntityType.ENDPOINT,
                    name=endpoint_name,
                    namespace=namespace,
                    properties={
                        "endpoint": obs.endpoint,
                        "source": "cloud.transport_security_observation",
                    },
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                _OBSERVED,
                session_id,
            )
            endpoint = created.entity
            report.entries.append(
                CloudMaterializeEntry(
                    entity_type="endpoint",
                    name=endpoint.name,
                    namespace=endpoint.namespace,
                    entity_id=str(endpoint.id),
                    action=created.action.value,
                )
            )
        source_status = (
            EvidenceStatus.OBSERVED
            if obs.source == "provider"
            else EvidenceStatus.INFERRED
        )
        for key, value in (
            ("tls_enforced", obs.tls_enforced),
            ("tls_version", obs.tls_version),
            ("certificate_valid", obs.certificate_valid),
            ("transport_source", obs.source),
        ):
            self._add_metadata_assertion(
                mission_id,
                session_id,
                endpoint,
                key,
                None if value is None else str(value),
                obs.source,
                source_status,
                confidence,
                evidence_id,
                report,
            )

    # ------------------------------------------------------------------
    # Assertion helper
    # ------------------------------------------------------------------
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
        report: CloudMaterializeReport,
    ) -> None:
        existing = self._store.list_assertions(
            str(entity.id), lifecycle=WorldLifecycle.ACTIVE
        )
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
        result = self._materializer.materialize_relationship(
            mission_id, fact, session_id
        )
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
        namespace: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
        source: str,
    ) -> WorldEntity | None:
        found = self._store.find_entity(
            mission_id, entity_type, name, namespace=namespace
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=entity_type,
                name=name,
                namespace=namespace,
                properties={"source": source},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _ensure_provider(
        self,
        mission_id: MissionID,
        provider: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        found = self._store.find_entity(
            mission_id, EntityType.CLOUD_PROVIDER, provider
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLOUD_PROVIDER,
                name=provider,
                namespace=None,
                properties={"provider": provider, "source": "cloud"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _ensure_account(
        self,
        mission_id: MissionID,
        obs: CloudObservation,
        container: str | None,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        if not container:
            return None
        namespace = obs.provider.value
        found = self._store.find_entity(
            mission_id, EntityType.CLOUD_ACCOUNT, container, namespace=namespace
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLOUD_ACCOUNT,
                name=container,
                namespace=namespace,
                properties={"account": container, "source": "cloud"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _ensure_container(
        self,
        mission_id: MissionID,
        obs: CloudObservation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        container = getattr(obs, "project", None) or obs.account
        if not container:
            return None
        entity_type = self._container_entity_type(obs)
        namespace = (
            obs.provider.value
            if entity_type == EntityType.CLOUD_ACCOUNT
            else cloud_namespace(
                obs.provider.value, getattr(obs, "project", None) or obs.account
            )
        )
        found = self._store.find_entity(
            mission_id, entity_type, container, namespace=namespace
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=entity_type,
                name=container,
                namespace=namespace,
                properties={"container": container, "source": "cloud"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _ensure_region(
        self,
        mission_id: MissionID,
        obs: CloudObservation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        region = getattr(obs, "region", None)
        if not region:
            return None
        namespace = obs.provider.value
        found = self._store.find_entity(
            mission_id, EntityType.CLOUD_REGION, region, namespace=namespace
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLOUD_REGION,
                name=region,
                namespace=namespace,
                properties={
                    "region": region,
                    "provider": obs.provider.value,
                    "source": "cloud",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity


__all__ = [
    "CloudMaterializeEntry",
    "CloudMaterializeReport",
    "CloudWorldMaterializer",
]
