from __future__ import annotations

import json

import pytest

from blackforge.auth.capabilities import build_auth_capabilities
from blackforge.authorization import AuthorizationBoundary
from blackforge.business_logic.capabilities import (
    build_business_logic_capabilities,
)
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.cloud import build_cloud_capabilities
from blackforge.container import (
    CONTAINER_CAPABILITY_IDS,
    CONTAINER_CREDENTIAL_KEYS,
    ContainerEngine,
    ContainerMaterializeReport,
    ContainerMode,
    ContainerObservationKind,
    ContainerRequest,
    ContainerResult,
    ContainerStatus,
    MockContainerTransport,
    build_container_capabilities,
    build_container_meta,
    credential_value_redacted,
    observation_confidence,
    redact_container_raw,
)
from blackforge.container.evidence import (
    artifact_evidence,
    evidence_dedup_key_for,
    existing_evidence_id,
    observation_evidence,
)
from blackforge.container.models import (
    ClusterObservation,
    ConfigurationDiscrepancyObservation,
    ContainerInstanceObservation,
    DeploymentObservation,
    IngressObservation,
)
from blackforge.container.normalization import (
    ContainerNormalizationError,
    adapter_for_tool,
)
from blackforge.core.errors import (
    AuthorizationError,
    ContainerExecutionError,
)
from blackforge.core.types import (
    Confidence,
    EvidenceStatus,
    RiskLevel,
    TargetType,
)
from blackforge.evidence.repository import InMemoryEvidenceRepository
from blackforge.evidence.store import EvidenceStore
from blackforge.identity.capabilities import build_identity_capabilities
from blackforge.network.capabilities import build_network_capabilities
from blackforge.recon.capabilities import build_recon_capabilities
from blackforge.scope.models import Target, TargetScope, detect_target_type
from blackforge.webapi.capabilities import build_webapi_capabilities
from blackforge.world_model.models import (
    EntityType,
    WorldLifecycle,
)
from blackforge.world_model.query import RelationshipQuery, WorldQuery
from blackforge.world_model.repository import InMemoryWorldRepository
from blackforge.world_model.store import WorldModelStore

MID = "mission_id12"
SID = "sess_id12"

PLATFORM = "aelionix-platform"
STAGING = "aelionix-staging"
FRONTEND = f"{PLATFORM}/frontend"

TOOLS = [
    "observe_clusters",
    "observe_nodes",
    "enumerate_namespaces",
    "observe_workloads",
    "observe_pods",
    "observe_containers",
    "observe_image_metadata",
    "observe_services",
    "observe_ingress",
    "observe_rbac",
    "observe_service_accounts",
    "observe_network_policies",
    "observe_security_contexts",
    "observe_resource_configuration",
]

PLATFORM_COUNTS: dict[str, int] = {
    "observe_clusters": 1,
    "observe_nodes": 2,
    "enumerate_namespaces": 3,
    "observe_workloads": 6,
    "observe_pods": 4,
    "observe_containers": 4,
    "observe_image_metadata": 4,
    "observe_services": 2,
    "observe_ingress": 1,
    "observe_rbac": 2,
    "observe_service_accounts": 3,
    "observe_network_policies": 2,
    "observe_security_contexts": 3,
    "observe_resource_configuration": 3,
}

STAGING_COUNTS: dict[str, int] = {
    "observe_clusters": 1,
    "observe_nodes": 1,
    "enumerate_namespaces": 1,
    "observe_workloads": 2,
    "observe_pods": 1,
    "observe_containers": 1,
    "observe_image_metadata": 2,
    "observe_services": 1,
    "observe_ingress": 0,
    "observe_rbac": 1,
    "observe_service_accounts": 1,
    "observe_network_policies": 0,
    "observe_security_contexts": 1,
    "observe_resource_configuration": 1,
}

_ERROR_TARGETS: dict[str, ContainerStatus] = {
    "snail-cluster": ContainerStatus.TIMEOUT,
    "bursty-cluster": ContainerStatus.RATE_LIMITED,
    "locked-cluster": ContainerStatus.UNAUTHORIZED,
    "garbled-cluster": ContainerStatus.MALFORMED_RESPONSE,
    "fabricated-cluster": ContainerStatus.UNSUPPORTED_CLUSTER,
}

_ERROR_KIND_BY_TARGET: dict[str, str] = {
    "snail-cluster": "timeout",
    "bursty-cluster": "rate_limited",
    "locked-cluster": "unauthorized",
    "garbled-cluster": "malformed",
    "fabricated-cluster": "unsupported_cluster",
}


def _scope(
    mission_id: str = MID, *, max_risk_level: RiskLevel = RiskLevel.HIGH,
    allowed_targets: list[Target] | None = None,
) -> TargetScope:
    return TargetScope(
        mission_id=mission_id,
        allowed_targets=allowed_targets or [
            Target(value=PLATFORM, target_type=TargetType.CLOUD),
            Target(value=STAGING, target_type=TargetType.CLOUD),
        ],
        allowed_capabilities=[],
        max_risk_level=max_risk_level,
    )


def _error_scope(mission_id: str = MID) -> TargetScope:
    targets = [
        Target(value=name, target_type=TargetType.ASSET)
        for name in tuple(_ERROR_TARGETS) + ("ghost-cluster",)
    ]
    return _scope(mission_id=mission_id, allowed_targets=targets)


def _request(
    mission_id: str = MID,
    *,
    scope: TargetScope | None = None,
    mode: ContainerMode = ContainerMode.CONTROLLED,
) -> ContainerRequest:
    return ContainerRequest(
        mission_id=mission_id,
        session_id=SID,
        scope=scope or _scope(),
        mode=mode,
        max_observations=500,
        timeout_seconds=30.0,
    )


def _engine(
    *,
    registry: CapabilityRegistry | None = None,
    use_stores: bool = True,
) -> tuple[ContainerEngine, EvidenceStore | None, WorldModelStore | None]:
    evidence_store = (
        EvidenceStore(repository=InMemoryEvidenceRepository())
        if use_stores
        else None
    )
    world = (
        WorldModelStore(repository=InMemoryWorldRepository())
        if use_stores
        else None
    )
    engine = ContainerEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


class TestContainerModels:
    def test_mode_enum(self) -> None:
        assert ContainerMode.CONTROLLED.value == "controlled"
        assert ContainerMode.PASSIVE.value == "passive"

    def test_status_enum(self) -> None:
        assert ContainerStatus.SUCCESS.value == "success"
        assert ContainerStatus.TIMEOUT.value == "timeout"
        assert ContainerStatus.RATE_LIMITED.value == "rate_limited"
        assert ContainerStatus.UNAUTHORIZED.value == "unauthorized"
        assert ContainerStatus.UNKNOWN_CLUSTER.value == "unknown_cluster"
        assert ContainerStatus.UNSUPPORTED_CLUSTER.value == "unsupported_cluster"
        assert ContainerStatus.MALFORMED_RESPONSE.value == "malformed_response"

    def test_observation_kind_enum(self) -> None:
        assert len(ContainerObservationKind) == 17
        values = {kind.value for kind in ContainerObservationKind}
        assert {
            "cluster", "node", "namespace", "workload", "deployment", "pod",
            "container", "image", "registry", "service", "ingress", "rbac",
            "service_account", "network_policy", "security_context",
            "resource_configuration", "configuration_discrepancy",
        } == values

    def test_observation_discriminated_union(self) -> None:
        cluster = ClusterObservation(cluster=PLATFORM, name=PLATFORM)
        container = ContainerInstanceObservation(
            cluster=PLATFORM, namespace="frontend", pod="web-api-0",
            container="web-api", image="registry.aelionix.test/web-api:latest",
        )
        deployment = DeploymentObservation(
            cluster=PLATFORM, namespace="frontend", deployment="web-api",
            workload="web-api",
        )
        assert cluster.kind == "cluster"
        assert container.kind == "container"
        assert deployment.kind == "deployment"

    def test_container_instance_union_discriminator(self) -> None:
        empirical = ContainerInstanceObservation(
            cluster=PLATFORM, namespace="frontend", pod="web-api-0",
            container="web-api", image="registry.aelionix.test/web-api:latest",
        )
        assert empirical.kind == "container"

    def test_request_validation(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            ContainerRequest(
                mode="turbo"  # type: ignore[arg-type]
            )

    def test_result_observation_count(self) -> None:
        result = ContainerResult(
            mission_id=MID,
            session_id=SID,
            target=PLATFORM,
            capability_id="container.cluster_observation",
            mode=ContainerMode.CONTROLLED,
            observations=[ClusterObservation(cluster=PLATFORM, name=PLATFORM)],
        )
        assert result.observation_count == 1
        assert result.observation_count == len(result.observations)


class TestContainerScopeMatching:
    def test_target_type_detection(self) -> None:
        assert detect_target_type(PLATFORM) == TargetType.ASSET
        assert detect_target_type(FRONTEND) == TargetType.CLOUD
        assert detect_target_type("apps.aelionix.test") == TargetType.DOMAIN

    def test_capabilities_support_cluster_targets(self) -> None:
        for meta in build_container_meta():
            assert TargetType.ASSET in meta.supported_target_types
            assert TargetType.CLOUD in meta.supported_target_types

    def test_all_container_capabilities_are_low_risk_passive(self) -> None:
        for meta in build_container_meta():
            assert meta.risk_level == RiskLevel.LOW
            assert meta.mode == ContainerMode.PASSIVE

    def test_produces_match_kinds(self) -> None:
        by_id = {str(m.id): [p.value for p in m.produces] for m in build_container_meta()}
        assert by_id["container.cluster_observation"] == ["cluster"]
        assert sorted(by_id["container.workload_observation"]) == [
            "deployment", "workload",
        ]
        assert sorted(by_id["container.image_metadata_observation"]) == [
            "image", "registry",
        ]
        assert sorted(
            by_id["container.resource_configuration_observation"]
        ) == ["configuration_discrepancy", "resource_configuration"]

    def test_scope_prefix_umbrella(self) -> None:
        scope = _scope(
            allowed_targets=[Target(value=PLATFORM, target_type=TargetType.CLOUD)]
        )
        assert scope.is_target_allowed(PLATFORM)
        assert scope.is_target_allowed(FRONTEND)
        assert not scope.is_target_allowed(STAGING)
        assert not scope.is_target_allowed("ghost-cluster")

    def test_capabilities_reject_non_cluster_targets(self) -> None:
        engine, _, _ = _engine()
        request = _request()
        with pytest.raises(ContainerExecutionError):
            engine.observe_pods(request, "apps.aelionix.test:8080")


class TestContainerTransport:
    def test_transport_is_deterministic(self) -> None:
        transport = MockContainerTransport()
        for tool in TOOLS:
            first = getattr(transport, tool)(PLATFORM)
            second = getattr(transport, tool)(PLATFORM)
            assert first == second

    def test_typed_counts_for_all_estates(self) -> None:
        transport = MockContainerTransport()
        for estate, counts in (
            (PLATFORM, PLATFORM_COUNTS),
            (STAGING, STAGING_COUNTS),
        ):
            for tool, expected in counts.items():
                doc = json.loads(getattr(transport, tool)(estate))
                assert len(doc["observations"]) == expected, (estate, tool)

    def test_namespaced_target_filters_rows(self) -> None:
        transport = MockContainerTransport()
        doc = json.loads(transport.observe_pods(FRONTEND))
        assert len(doc["observations"]) == 2
        assert all(o["namespace"] == "frontend" for o in doc["observations"])

    def test_error_targets_structured(self) -> None:
        transport = MockContainerTransport()
        for target in _ERROR_TARGETS:
            doc = json.loads(transport.observe_clusters(target))
            assert doc["error"]["kind"] == _ERROR_KIND_BY_TARGET[target], target

    def test_unknown_cluster_errors(self) -> None:
        transport = MockContainerTransport()
        doc = json.loads(transport.observe_clusters("ghost-cluster"))
        assert doc["error"]["kind"] == "unknown_cluster"

    def test_workloads_emit_deployment_rows(self) -> None:
        transport = MockContainerTransport()
        doc = json.loads(transport.observe_workloads(PLATFORM))
        kinds = [o["kind"] for o in doc["observations"]]
        assert "deployment" in kinds
        assert "workload" in kinds

    def test_image_metadata_emits_registry_rows(self) -> None:
        transport = MockContainerTransport()
        doc = json.loads(transport.observe_image_metadata(PLATFORM))
        kinds = [o["kind"] for o in doc["observations"]]
        assert "registry" in kinds
        assert "image" in kinds

    def test_resource_configuration_emits_discrepancy_rows(self) -> None:
        transport = MockContainerTransport()
        doc = json.loads(transport.observe_resource_configuration(PLATFORM))
        assert any(
            o.get("declared_value") and o.get("cluster_reported_value")
            for o in doc["observations"]
        )


class TestContainerRedaction:
    def test_credential_keys_cover_container_fields(self) -> None:
        assert "registry_token" in CONTAINER_CREDENTIAL_KEYS
        assert "service_account_token" in CONTAINER_CREDENTIAL_KEYS
        assert "password" in CONTAINER_CREDENTIAL_KEYS
        assert "tls_private_key" in CONTAINER_CREDENTIAL_KEYS
        assert "kubeconfig" in CONTAINER_CREDENTIAL_KEYS
        assert "dockerconfigjson" in CONTAINER_CREDENTIAL_KEYS

    def test_redaction_removes_demo_secrets(self) -> None:
        transport = MockContainerTransport()
        raw = (
            transport.observe_image_metadata(PLATFORM)
            + transport.observe_service_accounts(PLATFORM)
        )
        assert "demo-registry-token-" in raw
        assert "demo-sa-token-" in raw
        redacted = redact_container_raw(transport.observe_image_metadata(PLATFORM))
        redacted += redact_container_raw(transport.observe_service_accounts(PLATFORM))
        assert "demo-registry-token-" not in redacted
        assert "demo-sa-token-" not in redacted

    def test_redaction_preserves_security_values(self) -> None:
        transport = MockContainerTransport()
        raw = transport.observe_security_contexts(PLATFORM)
        redacted = redact_container_raw(raw)
        assert '"privileged"' in redacted
        assert "run_as_non_root" in redacted
        assert "seccomp_profile" in redacted

    def test_credential_value_redacted_signature(self) -> None:
        assert credential_value_redacted() == "REDACTED"


class TestContainerConfidence:
    def test_confidence_policy(self) -> None:
        cluster = ClusterObservation(cluster=PLATFORM, name=PLATFORM)
        ingress = IngressObservation(
            cluster=PLATFORM, namespace="frontend", ingress="public-api",
            host="api.aelionix.test",
        )
        assert observation_confidence(cluster, ContainerMode.CONTROLLED) == Confidence.HIGH
        assert observation_confidence(ingress, ContainerMode.CONTROLLED) == Confidence.MEDIUM
        assert observation_confidence(cluster, ContainerMode.PASSIVE) == Confidence.LOW
        assert observation_confidence(ingress, ContainerMode.PASSIVE) == Confidence.LOW

    def test_derived_kinds_never_high(self) -> None:
        ingress = IngressObservation(
            cluster=PLATFORM, namespace="frontend", ingress="public-api",
            host="api.aelionix.test",
        )
        discrepancy = ConfigurationDiscrepancyObservation(
            cluster=PLATFORM, namespace="frontend", workload="web-api",
            item="cpu_limit", declared_value="500m",
            cluster_reported_value="750m",
        )
        assert observation_confidence(ingress, ContainerMode.CONTROLLED) in {
            Confidence.MEDIUM, Confidence.LOW,
        }
        assert observation_confidence(discrepancy, ContainerMode.CONTROLLED) in {
            Confidence.MEDIUM, Confidence.LOW,
        }

    def test_no_cross_mode_confidence_inheritance(self) -> None:
        cluster = ClusterObservation(cluster=PLATFORM, name=PLATFORM)
        assert observation_confidence(cluster, ContainerMode.PASSIVE) == Confidence.LOW
        assert observation_confidence(cluster, ContainerMode.CONTROLLED) == Confidence.HIGH


class TestContainerNormalization:
    def test_adapter_registered_for_every_tool(self) -> None:
        for tool in TOOLS:
            assert adapter_for_tool(tool) is not None

    def test_error_document_propagates(self) -> None:
        transport = MockContainerTransport()
        raw = transport.observe_clusters("snail-cluster")
        out = adapter_for_tool("observe_clusters").adapt(
            raw, context={"target": "snail-cluster"}
        )
        assert out.error is not None
        assert out.error["kind"] == "timeout"
        assert out.observations == []

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(ContainerNormalizationError):
            adapter_for_tool("observe_clusters").adapt("{not json")

    def test_workload_adapter_emits_deployments(self) -> None:
        transport = MockContainerTransport()
        raw = transport.observe_workloads(PLATFORM)
        out = adapter_for_tool("observe_workloads").adapt(raw)
        kinds = {obs.kind for obs in out.observations}
        assert "deployment" in kinds
        assert "workload" in kinds


class TestContainerEvidence:
    def test_artifact_evidence_redacts_and_embeds_mode(self) -> None:
        transport = MockContainerTransport()
        raw = transport.observe_workloads(PLATFORM)
        evidence = artifact_evidence(
            MID, PLATFORM, "container.workload_observation", raw,
            mode=ContainerMode.CONTROLLED,
        )
        assert "demo-registry-token-" not in evidence.raw_data
        assert '"mode": "controlled"' in evidence.raw_data
        assert evidence.evidence_type.value == "artifact"

    def test_observation_evidence_embeds_mode(self) -> None:
        obs = ClusterObservation(cluster=PLATFORM, name=PLATFORM)
        evidence = observation_evidence(
            MID, PLATFORM, "container.cluster_observation", obs,
            mode=ContainerMode.PASSIVE,
        )
        assert evidence.confidence == Confidence.LOW

    def test_evidence_dedup_key_stable(self) -> None:
        evidence = artifact_evidence(
            MID, PLATFORM, "container.cluster_observation", "{}",
            mode=ContainerMode.CONTROLLED,
        )
        assert evidence_dedup_key_for(evidence) == evidence_dedup_key_for(evidence)

    def test_existing_evidence_id_dedup(self) -> None:
        engine, evidence_store, _ = _engine()
        request = _request()
        result = engine.observe_pods(request, PLATFORM)
        first_len = len(result.evidence_ids)
        result2 = engine.observe_pods(request, PLATFORM)
        assert len(result2.evidence_ids) == first_len

        evidence = observation_evidence(
            MID, PLATFORM, "container.pod_observation",
            result.observations[0],
        )
        assert existing_evidence_id(evidence_store, evidence) is not None


class TestContainerWorldMaterialization:
    def _observe_all(self, engine, request, target: str) -> None:
        order = [
            "observe_clusters",
            "observe_nodes",
            "enumerate_namespaces",
            "observe_workloads",
            "observe_service_accounts",
            "observe_pods",
            "observe_image_metadata",
            "observe_containers",
            "observe_services",
            "observe_ingress",
            "observe_network_policies",
            "observe_rbac",
            "observe_security_contexts",
            "observe_resource_configuration",
        ]
        for method in order:
            getattr(engine, method)(request, target)

    def test_world_topology(self) -> None:
        engine, _, world = _engine()
        self._observe_all(engine, _request(), PLATFORM)
        active = WorldLifecycle.ACTIVE
        assert world.count_entities(MID, entity_type=EntityType.CLUSTER, lifecycle=active) == 1
        assert world.count_entities(MID, entity_type=EntityType.NODE, lifecycle=active) == 2
        assert world.count_entities(MID, entity_type=EntityType.NAMESPACE, lifecycle=active) == 3
        assert world.count_entities(MID, entity_type=EntityType.WORKLOAD, lifecycle=active) == 3
        assert world.count_entities(MID, entity_type=EntityType.DEPLOYMENT, lifecycle=active) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.POD, lifecycle=active
        ) == 4
        assert world.count_entities(MID, entity_type=EntityType.CONTAINER, lifecycle=active) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.CONTAINER_IMAGE, lifecycle=active
        ) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.REGISTRY, lifecycle=active
        ) == 1
        assert world.count_entities(MID, entity_type=EntityType.SERVICE, lifecycle=active) == 2
        assert world.count_entities(MID, entity_type=EntityType.INGRESS, lifecycle=active) == 1
        assert world.count_entities(
            MID, entity_type=EntityType.ROLE, lifecycle=active
        ) == 2
        assert world.count_entities(
            MID, entity_type=EntityType.PERMISSION, lifecycle=active
        ) == 2
        assert world.count_entities(
            MID, entity_type=EntityType.SERVICE_ACCOUNT, lifecycle=active
        ) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.NETWORK_POLICY, lifecycle=active
        ) == 2

    def test_entity_chain_cluster_to_container(self) -> None:
        engine, _, world = _engine()
        self._observe_all(engine, _request(), PLATFORM)
        relationships = world.list_relationships(
            RelationshipQuery(mission_id=MID, limit=1000)
        )
        edges = {
            (r.relationship_type.value, str(r.source_entity_id), str(r.target_entity_id))
            for r in relationships
        }
        cluster = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.CLUSTER, limit=10)
        )[0]
        namespace_rows = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.NAMESPACE, limit=10)
        )
        frontend = next(n for n in namespace_rows if n.name == "frontend")
        workload_rows = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.WORKLOAD, limit=10)
        )
        web = next(w for w in workload_rows if w.name == "web-api")
        deployment_rows = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.DEPLOYMENT, limit=10)
        )
        web_deploy = next(d for d in deployment_rows if d.name == "web-api")
        pod_rows = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.POD, limit=10)
        )
        web_pod = next(p for p in pod_rows if p.name.startswith("web-api"))
        container_rows = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.CONTAINER, limit=10)
        )
        root = next(c for c in container_rows if c.name.startswith("web-api"))

        assert ("contains", str(cluster.id), str(frontend.id)) in edges
        assert ("contains", str(frontend.id), str(web.id)) in edges
        assert ("deploys", str(web_deploy.id), str(web.id)) in edges
        assert ("contains", str(frontend.id), str(web_pod.id)) in edges
        assert ("contains", str(web_pod.id), str(root.id)) in edges

    def test_no_offensive_relationships(self) -> None:
        engine, _, world = _engine()
        self._observe_all(engine, _request(), PLATFORM)
        relationships = world.list_relationships(
            RelationshipQuery(mission_id=MID, limit=1000)
        )
        assert relationships
        offensive = {
            "exploits", "can_compromise", "leads_to", "enables",
            "privilege_escalation_path",
        }
        used = {r.relationship_type.value for r in relationships}
        assert used & offensive == set()

    def test_relationship_semantics(self) -> None:
        engine, _, world = _engine()
        self._observe_all(engine, _request(), PLATFORM)
        relationships = world.list_relationships(
            RelationshipQuery(mission_id=MID, limit=1000)
        )
        used = {r.relationship_type.value for r in relationships}
        assert "selects" in used
        assert "routes_to" in used
        assert "has_role" in used
        assert "has_permission" in used
        assert "uses_service_account" in used
        assert "uses_image" in used
        assert "belongs_to" in used
        assert "applies_to" in used
        assert "deploys" in used
        assert "runs" in used

    def test_security_context_assertions_materialize(self) -> None:
        engine, _, world = _engine()
        request = _request()
        engine.observe_workloads(request, PLATFORM)
        engine.observe_containers(request, PLATFORM)
        engine.observe_security_contexts(request, PLATFORM)
        containers = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.CONTAINER, limit=10)
        )
        assert containers
        assertions = world.list_assertions(
            str(containers[0].id), lifecycle=WorldLifecycle.ACTIVE
        )
        keys = {a.property_key for a in assertions}
        assert {"privileged", "allow_privilege_escalation", "run_as_non_root"}.issubset(keys)

    def test_resource_configuration_and_discrepancy_assertions(self) -> None:
        engine, _, world = _engine()
        request = _request()
        engine.observe_workloads(request, PLATFORM)
        engine.observe_resource_configuration(request, PLATFORM)
        workloads = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.WORKLOAD, limit=10)
        )
        web = next(w for w in workloads if w.name == "web-api")
        assertions = world.list_assertions(
            str(web.id), lifecycle=WorldLifecycle.ACTIVE
        )
        keys = {a.property_key for a in assertions}
        assert {"cpu_request", "cpu_limit", "memory_request", "memory_limit"}.issubset(keys)
        assert any(key.startswith("discrepancy.") for key in keys)

    def test_inferred_discrepancy_epistemic_status(self) -> None:
        engine, _, world = _engine()
        request = _request()
        engine.observe_workloads(request, PLATFORM)
        engine.observe_resource_configuration(request, PLATFORM)
        workloads = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.WORKLOAD, limit=10)
        )
        web = next(w for w in workloads if w.name == "web-api")
        assertions = world.list_assertions(
            str(web.id), lifecycle=WorldLifecycle.ACTIVE
        )
        discrepancies = [
            a for a in assertions
            if a.property_key.startswith("discrepancy.")
        ]
        assert discrepancies
        assert all(a.epistemic_status == EvidenceStatus.INFERRED for a in discrepancies)

    def test_materialize_report_shape(self) -> None:
        report = ContainerMaterializeReport()
        assert report.entities_created == 0
        assert report.assertions_contradicted == 0


class TestContainerEngine:
    def test_engine_capabilities_match_meta(self) -> None:
        engine, _, _ = _engine()
        ids = {str(cap.meta().id) for cap in engine.capabilities}
        assert ids == set(CONTAINER_CAPABILITY_IDS)

    def test_engine_registers_without_clobbering_defaults(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        before = len(registry.list_capabilities())
        engine, _, _ = _engine(registry=registry)
        assert len(registry.list_capabilities()) == before + 14
        assert registry.has("container.cluster_observation")

    def test_run_dispatcher(self) -> None:
        engine, _, _ = _engine()
        result = engine.run(_request(), "container.cluster_observation", PLATFORM)
        assert result.capability_id == "container.cluster_observation"
        assert result.observation_count == 1

    def test_unknown_capability_raises(self) -> None:
        engine, _, _ = _engine()
        with pytest.raises(ContainerExecutionError):
            engine.run(_request(), "container.does_not_exist", PLATFORM)

    def test_invalid_mode_raises(self) -> None:
        engine, _, _ = _engine()
        with pytest.raises(ContainerExecutionError):
            engine.observe_pods(_request(), PLATFORM, mode="turbo")

    def test_out_of_scope_raises(self) -> None:
        engine, _, _ = _engine()
        request = _request(
            scope=_scope(
                allowed_targets=[
                    Target(value=STAGING, target_type=TargetType.CLOUD)
                ]
            )
        )
        with pytest.raises(AuthorizationError):
            engine.observe_clusters(request, PLATFORM)

    def test_denied_before_transport(self) -> None:
        engine, _, _ = _engine()
        request = _request(
            scope=_scope(
                allowed_targets=[
                    Target(value=STAGING, target_type=TargetType.CLOUD)
                ]
            )
        )

        class Boom(MockContainerTransport):
            def observe_clusters(self, *args, **kwargs):  # pragma: no cover
                raise AssertionError("transport must not be invoked")

        engine._transport = Boom()
        with pytest.raises(AuthorizationError):
            engine.observe_clusters(request, PLATFORM)

    def test_unknown_cluster_in_scope_fails_closed(self) -> None:
        engine, _, _ = _engine()
        request = _request(scope=_error_scope())
        result = engine.observe_clusters(request, "ghost-cluster")
        assert result.status == ContainerStatus.UNKNOWN_CLUSTER
        assert len(result.observations) == 0

    def test_error_target_statuses(self) -> None:
        engine, _, _ = _engine()
        request = _request(scope=_error_scope())
        for target, expected in _ERROR_TARGETS.items():
            result = engine.observe_clusters(request, target)
            assert result.status == expected, target

    def test_passive_mode_success(self) -> None:
        engine, _, _ = _engine()
        result = engine.observe_clusters(
            _request(mode=ContainerMode.PASSIVE), PLATFORM, mode="passive"
        )
        assert result.status == ContainerStatus.SUCCESS
        assert result.mode == ContainerMode.PASSIVE
        obs = result.observations[0]
        evidence = observation_evidence(
            MID, PLATFORM, "container.cluster_observation", obs,
            mode=ContainerMode.PASSIVE,
        )
        assert evidence.confidence == Confidence.LOW

    def test_mode_param_override(self) -> None:
        engine, _, _ = _engine()
        request = _request(mode=ContainerMode.CONTROLLED)
        result = engine.observe_clusters(request, PLATFORM, mode="passive")
        assert result.mode == ContainerMode.PASSIVE

    def test_observation_limit_truncates(self) -> None:
        engine, _, _ = _engine()
        request = ContainerRequest(
            mission_id=MID,
            session_id=SID,
            scope=_scope(),
            mode=ContainerMode.CONTROLLED,
            max_observations=2,
            timeout_seconds=30.0,
        )
        result = engine.observe_workloads(request, PLATFORM)
        assert result.status == ContainerStatus.LIMITED
        assert result.observation_count == 2
        assert len(result.warnings) == 1

    def test_evidence_persisted_redacted(self) -> None:
        engine, evidence_store, _ = _engine()
        result = engine.observe_workloads(_request(), PLATFORM)
        assert len(result.evidence_ids) == 7
        artifact = evidence_store.get(result.evidence_ids[0])
        assert artifact.evidence_type.value == "artifact"
        assert "demo-registry-token-" not in artifact.raw_data
        assert "demo-service-account-token-" not in artifact.raw_data

    def test_repeat_run_does_not_duplicate_evidence(self) -> None:
        engine, _, _ = _engine()
        request = _request()
        first = engine.observe_pods(request, PLATFORM)
        second = engine.observe_pods(request, PLATFORM)
        assert first.evidence_ids == second.evidence_ids

    def test_timeout_error_target_status(self) -> None:
        engine, _, _ = _engine()
        request = _request(scope=_error_scope())
        result = engine.observe_clusters(request, "snail-cluster")
        assert result.status == ContainerStatus.TIMEOUT
        assert len(result.observations) == 0


class TestContainerCoexistence:
    def test_all_engines_total_ninety_five(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        builders = [
            build_recon_capabilities,
            build_webapi_capabilities,
            build_auth_capabilities,
            build_business_logic_capabilities,
            build_network_capabilities,
            build_identity_capabilities,
            build_cloud_capabilities,
            build_container_capabilities,
        ]
        for builder in builders:
            for capability in builder():
                if not registry.has(capability.capability_id):
                    registry.register(capability)
        all_caps = registry.list_capabilities()
        assert len(all_caps) == 95
        assert "mock_discovery" in all_caps
        for cap_id in CONTAINER_CAPABILITY_IDS:
            assert cap_id in all_caps
        assert len(CONTAINER_CAPABILITY_IDS) == 14

    def test_container_engine_coexists(self) -> None:
        engine, _, _ = _engine()
        assert engine.has_capability("container.node_observation")
        assert not engine.has_capability("container.does_not_exist")
