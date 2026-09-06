from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from blackforge.container.canonical import container_namespace
from blackforge.container.models import (
    ClusterObservation,
    ConfigurationDiscrepancyObservation,
    ContainerInstanceObservation,
    ContainerObservation,
    DeploymentObservation,
    ImageObservation,
    IngressObservation,
    NamespaceObservation,
    NetworkPolicyObservation,
    NodeObservation,
    PodObservation,
    RbacObservation,
    RegistryObservation,
    ResourceConfigurationObservation,
    SecurityContextObservation,
    ServiceAccountObservation,
    ServiceObservation,
    WorkloadObservation,
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


def _ref(evidence_id: EvidenceID, **properties: str | None) -> EvidenceLinkRef:
    return EvidenceLinkRef(
        evidence_id=evidence_id,
        property_key=properties.get("property_key"),
        property_value=properties.get("property_value"),
    )


class ContainerMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class ContainerMaterializeReport(BaseModel):
    entries: list[ContainerMaterializeEntry] = Field(default_factory=list)
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


class ContainerWorldMaterializer:
    """Maps typed container observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text.
    Container entities are namespaced by ``k8s/<cluster>`` (cluster-scoped) or
    ``k8s/<cluster>/<namespace>`` (namespace-scoped) so same-named workloads,
    services, and pods across clusters or namespaces stay distinct:

    * CLUSTER --CONTAINS--> NODE / NAMESPACE
    * NAMESPACE --CONTAINS--> WORKLOAD / DEPLOYMENT / POD / SERVICE /
      INGRESS / SERVICE_ACCOUNT / NETWORK_POLICY
    * DEPLOYMENT --DEPLOYS--> WORKLOAD
    * POD --RUNS-on--> NODE (RUNS), POD --USES_SERVICE_ACCOUNT-->
      SERVICE_ACCOUNT, POD --CONTAINS--> CONTAINER
    * CONTAINER --USES_IMAGE--> CONTAINER_IMAGE
    * CONTAINER_IMAGE --BELONGS_TO--> REGISTRY
    * SERVICE --SELECTS--> WORKLOAD
    * INGRESS --ROUTES_TO--> SERVICE
    * SERVICE_ACCOUNT --HAS_ROLE--> ROLE --HAS_PERMISSION--> PERMISSION
    * NETWORK_POLICY --APPLIES_TO--> NAMESPACE (and asserted pod targets)

    Security-context, resource-configuration, and configuration-discrepancy
    attributes materialize as assertions on the referenced pod/container/
    workload entity — they are beliefs, never separate world entities.

    All edges are descriptive/structural. No offensive semantics (EXPLOITS,
    CAN_COMPROMISE, LEADS_TO, ENABLES, PRIVILEGE_ESCALATION_PATH) are ever
    produced here.
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
        observations: list[tuple[ContainerObservation, EvidenceID, Confidence]],
        *,
        session_id: SessionID | None = None,
    ) -> ContainerMaterializeReport:
        report = ContainerMaterializeReport()
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
        observation: ContainerObservation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: ContainerMaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        mapper = {
            ClusterObservation: self._materialize_cluster,
            NodeObservation: self._materialize_node,
            NamespaceObservation: self._materialize_namespace,
            WorkloadObservation: self._materialize_workload,
            DeploymentObservation: self._materialize_deployment,
            PodObservation: self._materialize_pod,
            ContainerInstanceObservation: self._materialize_container,
            ImageObservation: self._materialize_image,
            RegistryObservation: self._materialize_registry,
            ServiceObservation: self._materialize_service,
            IngressObservation: self._materialize_ingress,
            RbacObservation: self._materialize_rbac,
            ServiceAccountObservation: self._materialize_service_account,
            NetworkPolicyObservation: self._materialize_network_policy,
            SecurityContextObservation: self._materialize_security_context,
            ResourceConfigurationObservation: self._materialize_resource_config,
            ConfigurationDiscrepancyObservation: self._materialize_discrepancy,
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
    # Containment backbone
    # ------------------------------------------------------------------
    def _materialize_cluster(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLUSTER,
                name=obs.cluster,
                namespace=namespace,
                properties={
                    "cluster": obs.cluster,
                    "platform": obs.platform,
                    "version": obs.version,
                    "source": "container.cluster_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.CLUSTER.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_node(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.NODE,
                name=obs.node,
                namespace=namespace,
                properties={
                    "node": obs.node,
                    "role": obs.role,
                    "os_image": obs.os_image,
                    "container_runtime": obs.container_runtime,
                    "source": "container.node_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_cluster_contains(
            mission_id,
            obs.cluster,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            EntityType.NODE,
            "cluster contains node",
        )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.NODE.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_namespace(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        cluster_ns = container_namespace(obs.cluster)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.NAMESPACE,
                name=obs.namespace,
                namespace=cluster_ns,
                properties={
                    "namespace": obs.namespace,
                    "source": "container.namespace_enumeration",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_cluster_contains(
            mission_id,
            obs.cluster,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            EntityType.NAMESPACE,
            "cluster contains namespace",
        )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.NAMESPACE.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    # ------------------------------------------------------------------
    # Namespace-scoped workload / pod records
    # ------------------------------------------------------------------
    def _materialize_workload(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.WORKLOAD,
                name=obs.workload,
                namespace=namespace,
                properties={
                    "workload": obs.workload,
                    "workload_kind": obs.workload_kind,
                    "strategy": obs.strategy,
                    "source": "container.workload_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_namespace_contains(
            mission_id,
            obs.cluster,
            obs.namespace,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            "namespace contains workload",
        )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.WORKLOAD.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_deployment(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.DEPLOYMENT,
                name=obs.deployment,
                namespace=namespace,
                properties={
                    "deployment": obs.deployment,
                    "replicas": obs.replicas,
                    "ready_replicas": obs.ready_replicas,
                    "source": "container.workload_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_namespace_contains(
            mission_id,
            obs.cluster,
            obs.namespace,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            "namespace contains deployment",
        )
        if obs.workload:
            workload = self._find_entity(
                mission_id,
                EntityType.WORKLOAD,
                obs.workload,
                namespace,
            )
            if workload is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.DEPLOYS,
                        source_entity_id=str(entity.id),
                        target_entity_id=str(workload.id),
                        note="deployment deploys workload",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.DEPLOYMENT.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_pod(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.POD,
                name=obs.pod,
                namespace=namespace,
                properties={
                    "pod": obs.pod,
                    "phase": obs.phase,
                    "pod_ip": obs.pod_ip,
                    "source": "container.pod_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_namespace_contains(
            mission_id,
            obs.cluster,
            obs.namespace,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            "namespace contains pod",
        )
        if obs.node:
            node = self._find_entity(
                mission_id,
                EntityType.NODE,
                obs.node,
                container_namespace(obs.cluster),
            )
            if node is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.RUNS,
                        source_entity_id=str(entity.id),
                        target_entity_id=str(node.id),
                        note="pod runs on node",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        if obs.service_account:
            sa = self._find_entity(
                mission_id,
                EntityType.SERVICE_ACCOUNT,
                obs.service_account,
                namespace,
            )
            if sa is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.USES_SERVICE_ACCOUNT,
                        source_entity_id=str(entity.id),
                        target_entity_id=str(sa.id),
                        note="pod uses service account",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.POD.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_container(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CONTAINER,
                name=obs.container,
                namespace=namespace,
                properties={
                    "container": obs.container,
                    "image": obs.image,
                    "image_pull_policy": obs.image_pull_policy,
                    "source": "container.container_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        if obs.pod:
            pod = self._find_entity(
                mission_id, EntityType.POD, obs.pod, namespace
            )
            if pod is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.CONTAINS,
                        source_entity_id=str(pod.id),
                        target_entity_id=str(entity.id),
                        note="pod contains container",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        if obs.image:
            image = self._find_entity(
                mission_id,
                EntityType.CONTAINER_IMAGE,
                obs.image,
                _image_namespace(obs),
            )
            if image is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.USES_IMAGE,
                        source_entity_id=str(entity.id),
                        target_entity_id=str(image.id),
                        note="container uses image",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.CONTAINER.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_image(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = _image_namespace(obs)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CONTAINER_IMAGE,
                name=obs.image,
                namespace=namespace,
                properties={
                    "image": obs.image,
                    "registry": obs.registry,
                    "tag": obs.tag,
                    "digest": obs.digest,
                    "source": "container.image_metadata_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        if obs.registry:
            registry = self._find_entity(
                mission_id,
                EntityType.REGISTRY,
                obs.registry,
                container_namespace(obs.cluster),
            )
            if registry is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.BELONGS_TO,
                        source_entity_id=str(entity.id),
                        target_entity_id=str(registry.id),
                        note="image belongs to registry",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.CONTAINER_IMAGE.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_registry(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.REGISTRY,
                name=obs.registry,
                namespace=namespace,
                properties={
                    "registry": obs.registry,
                    "host": obs.host,
                    "secure": obs.secure,
                    "source": "container.image_metadata_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.REGISTRY.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_service(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SERVICE,
                name=obs.service,
                namespace=namespace,
                properties={
                    "service": obs.service,
                    "service_type": obs.service_type,
                    "cluster_ip": obs.cluster_ip,
                    "source": "container.service_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_namespace_contains(
            mission_id,
            obs.cluster,
            obs.namespace,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            "namespace contains service",
        )
        selector = obs.selector or {}
        app = selector.get("app")
        if app:
            workload = self._find_entity(
                mission_id, EntityType.WORKLOAD, str(app), namespace
            )
            if workload is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.SELECTS,
                        source_entity_id=str(entity.id),
                        target_entity_id=str(workload.id),
                        note="service selects workload",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.SERVICE.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_ingress(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.INGRESS,
                name=obs.ingress,
                namespace=namespace,
                properties={
                    "ingress": obs.ingress,
                    "host": obs.host,
                    "tls_enabled": obs.tls_enabled,
                    "source": "container.ingress_exposure_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_namespace_contains(
            mission_id,
            obs.cluster,
            obs.namespace,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            "namespace contains ingress",
        )
        backend = obs.backend or obs.paths[0] if obs.paths else None
        if isinstance(backend, str) and ":" in backend:
            service_name = backend.split(":", 1)[0]
            service = self._find_entity(
                mission_id, EntityType.SERVICE, service_name, namespace
            )
            if service is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.ROUTES_TO,
                        source_entity_id=str(entity.id),
                        target_entity_id=str(service.id),
                        note="ingress routes to service",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.INGRESS.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_rbac(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        permission = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.PERMISSION,
                name=obs.permission or obs.role,
                namespace=namespace,
                properties={
                    "permission": obs.permission or obs.role,
                    "verbs": obs.verbs,
                    "resources": obs.resources,
                    "api_group": obs.api_group,
                    "source": "container.rbac_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        permission_entity, permission_action = permission
        role = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ROLE,
                name=obs.role,
                namespace=namespace,
                properties={
                    "role": obs.role,
                    "role_kind": obs.role_kind,
                    "source": "container.rbac_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        role_entity, role_action = role
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.HAS_PERMISSION,
                source_entity_id=str(role_entity.id),
                target_entity_id=str(permission_entity.id),
                note="role has permission",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        if obs.subject_kind == "ServiceAccount" or obs.subject:
            subject = self._find_entity(
                mission_id,
                EntityType.SERVICE_ACCOUNT,
                obs.subject,
                namespace,
            )
            if subject is not None:
                self._link_report(
                    mission_id,
                    RelationshipFact(
                        relationship_type=RelationshipType.HAS_ROLE,
                        source_entity_id=str(subject.id),
                        target_entity_id=str(role_entity.id),
                        note="service account has role",
                        confidence=confidence,
                        evidence=[_ref(evidence_id)],
                    ),
                    report,
                    session_id,
                )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.PERMISSION.value,
                name=permission_entity.name,
                namespace=permission_entity.namespace,
                entity_id=str(permission_entity.id),
                action=permission_action,
            )
        )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.ROLE.value,
                name=role_entity.name,
                namespace=role_entity.namespace,
                entity_id=str(role_entity.id),
                action=role_action,
            )
        )

    def _materialize_service_account(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.SERVICE_ACCOUNT,
                name=obs.service_account,
                namespace=namespace,
                properties={
                    "service_account": obs.service_account,
                    "automount_token": obs.automount_token,
                    "source": "container.service_account_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_namespace_contains(
            mission_id,
            obs.cluster,
            obs.namespace,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            "namespace contains service account",
        )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.SERVICE_ACCOUNT.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    def _materialize_network_policy(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.NETWORK_POLICY,
                name=obs.network_policy,
                namespace=namespace,
                properties={
                    "network_policy": obs.network_policy,
                    "policy_types": obs.policy_types,
                    "pod_selector": obs.pod_selector,
                    "source": "container.network_policy_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        self._link_namespace_contains(
            mission_id,
            obs.cluster,
            obs.namespace,
            str(entity.id),
            evidence_id,
            confidence,
            report,
            session_id,
            "namespace contains network policy",
        )
        namespace_entity = self._find_entity(
            mission_id,
            EntityType.NAMESPACE,
            obs.namespace,
            container_namespace(obs.cluster),
        )
        if namespace_entity is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.APPLIES_TO,
                    source_entity_id=str(entity.id),
                    target_entity_id=str(namespace_entity.id),
                    note="network policy applies to namespace",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            ContainerMaterializeEntry(
                entity_type=EntityType.NETWORK_POLICY.value,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )

    # ------------------------------------------------------------------
    # Derived records (assertions, never new entities)
    # ------------------------------------------------------------------
    def _materialize_security_context(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity = None
        if obs.container:
            entity = self._find_entity(
                mission_id, EntityType.CONTAINER, obs.container, namespace
            )
        if entity is None and obs.pod:
            entity = self._find_entity(
                mission_id, EntityType.POD, obs.pod, namespace
            )
        if entity is None:
            report_entity = self._upsert_entity(
                mission_id,
                EntityFact(
                    entity_type=EntityType.CONTAINER,
                    name=obs.container or obs.pod or "unknown",
                    namespace=namespace,
                    properties={
                        "container": obs.container or obs.pod or "unknown",
                        "source": "container.security_context_observation",
                    },
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                session_id,
            )
            entity = report_entity[0]
        authoritative = obs.source == "cluster"
        status = EvidenceStatus.OBSERVED if authoritative else EvidenceStatus.INFERRED
        for key, value in (
            ("privileged", obs.privileged),
            ("allow_privilege_escalation", obs.allow_privilege_escalation),
            ("run_as_non_root", obs.run_as_non_root),
            ("run_as_user", obs.run_as_user),
            ("read_only_root_filesystem", obs.read_only_root_filesystem),
            ("seccomp_profile", obs.seccomp_profile),
            ("capabilities", ",".join(obs.capabilities) if obs.capabilities else None),
        ):
            self._add_metadata_assertion(
                mission_id,
                session_id,
                entity,
                key,
                None if value is None else str(value),
                obs.source,
                status,
                confidence,
                evidence_id,
                report,
            )

    def _materialize_resource_config(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity = self._find_entity(
            mission_id, EntityType.WORKLOAD, obs.workload, namespace
        )
        if entity is None:
            entity = self._upsert_entity(
                mission_id,
                EntityFact(
                    entity_type=EntityType.WORKLOAD,
                    name=obs.workload,
                    namespace=namespace,
                    properties={
                        "workload": obs.workload,
                        "source": "container.resource_configuration_observation",
                    },
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                session_id,
            )[0]
        authoritative = obs.source == "cluster"
        status = EvidenceStatus.OBSERVED if authoritative else EvidenceStatus.INFERRED
        for key, value in (
            ("cpu_request", obs.cpu_request),
            ("memory_request", obs.memory_request),
            ("cpu_limit", obs.cpu_limit),
            ("memory_limit", obs.memory_limit),
        ):
            self._add_metadata_assertion(
                mission_id,
                session_id,
                entity,
                key,
                None if value is None else str(value),
                obs.source,
                status,
                confidence,
                evidence_id,
                report,
            )

    def _materialize_discrepancy(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        namespace = container_namespace(obs.cluster, obs.namespace)
        entity = self._find_entity(
            mission_id, EntityType.WORKLOAD, obs.workload, namespace
        )
        if entity is None:
            entity = self._upsert_entity(
                mission_id,
                EntityFact(
                    entity_type=EntityType.WORKLOAD,
                    name=obs.workload,
                    namespace=namespace,
                    properties={
                        "workload": obs.workload,
                        "source": "container.configuration_discrepancy_analysis",
                    },
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                session_id,
            )[0]
        self._add_metadata_assertion(
            mission_id,
            session_id,
            entity,
            f"discrepancy.{obs.item}",
            obs.cluster_reported_value,
            "discrepancy",
            EvidenceStatus.INFERRED,
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
        report: ContainerMaterializeReport,
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
    def _find_entity(
        self, mission_id: MissionID, entity_type: EntityType, name: str, namespace: str
    ) -> WorldEntity | None:
        return self._store.find_entity(
            mission_id, entity_type, name, namespace=namespace
        )

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

    def _ensure_cluster(
        self,
        mission_id: MissionID,
        cluster: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        found = self._store.find_entity(
            mission_id, EntityType.CLUSTER, cluster, namespace=container_namespace(cluster)
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.CLUSTER,
                name=cluster,
                namespace=container_namespace(cluster),
                properties={"cluster": cluster, "source": "container"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity

    def _link_cluster_contains(
        self,
        mission_id,
        cluster,
        target_entity_id,
        evidence_id,
        confidence,
        report,
        session_id,
        target_type: EntityType,
        note: str,
    ) -> None:
        cluster_entity = self._ensure_cluster(
            mission_id, cluster, evidence_id, confidence, session_id
        )
        if cluster_entity is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(cluster_entity.id),
                    target_entity_id=target_entity_id,
                    note=note,
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )

    def _link_namespace_contains(
        self,
        mission_id,
        cluster,
        namespace,
        target_entity_id,
        evidence_id,
        confidence,
        report,
        session_id,
        note: str,
    ) -> None:
        namespace_entity = self._ensure_namespace(
            mission_id, cluster, namespace, evidence_id, confidence, session_id
        )
        if namespace_entity is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.CONTAINS,
                    source_entity_id=str(namespace_entity.id),
                    target_entity_id=target_entity_id,
                    note=note,
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )

    def _ensure_namespace(
        self,
        mission_id,
        cluster,
        namespace,
        evidence_id,
        confidence,
        session_id,
    ) -> WorldEntity | None:
        found = self._store.find_entity(
            mission_id,
            EntityType.NAMESPACE,
            namespace,
            namespace=container_namespace(cluster),
        )
        if found is not None:
            return found
        return self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.NAMESPACE,
                name=namespace,
                namespace=container_namespace(cluster),
                properties={"namespace": namespace, "source": "container"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        ).entity


def _image_namespace(obs) -> str:
    if getattr(obs, "namespace", None):
        return container_namespace(obs.cluster, obs.namespace)
    return container_namespace(obs.cluster)


__all__ = [
    "ContainerMaterializeEntry",
    "ContainerMaterializeReport",
    "ContainerWorldMaterializer",
]
