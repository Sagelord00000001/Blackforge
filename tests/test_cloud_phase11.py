from __future__ import annotations

import json

import pytest

from blackforge.auth.capabilities import build_auth_capabilities
from blackforge.authorization import AuthorizationBoundary
from blackforge.business_logic.capabilities import (
    build_business_logic_capabilities,
)
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.cloud import (
    CLOUD_CAPABILITY_IDS,
    CLOUD_CREDENTIAL_KEYS,
    AddressType,
    CloudEngine,
    CloudMaterializeReport,
    CloudMode,
    CloudObservationKind,
    CloudRequest,
    CloudResult,
    CloudStatus,
    MockCloudTransport,
    build_cloud_capabilities,
    build_cloud_meta,
    classify_address,
    credential_value_redacted,
    observation_confidence,
    redact_cloud_raw,
)
from blackforge.cloud.evidence import (
    artifact_evidence,
    evidence_dedup_key_for,
    existing_evidence_id,
    observation_evidence,
)
from blackforge.cloud.models import (
    CloudResourceType,
    ComputeObservation,
    PublicExposureObservation,
    ResourceRelationshipObservation,
    SecurityConfigurationObservation,
)
from blackforge.cloud.normalization import (
    CloudNormalizationError,
    adapter_for_tool,
)
from blackforge.cloud.providers import (
    parse_cloud_target,
    provider_for_target,
)
from blackforge.core.errors import (
    AuthorizationError,
    CloudExecutionError,
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
    RelationshipType,
    WorldLifecycle,
)
from blackforge.world_model.query import RelationshipQuery, WorldQuery
from blackforge.world_model.repository import InMemoryWorldRepository
from blackforge.world_model.store import WorldModelStore

MID = "mission_id11"
SID = "sess_id11"

AWS = "aws/aelionix-aws-test"
AZURE = "azure/aelionix-azure-test"
GCP = "gcp/aelionix-gcp-test"

TOOLS = [
    "discover_providers",
    "inventory_accounts",
    "inventory_projects",
    "inventory_resources",
    "observe_compute",
    "observe_storage",
    "observe_databases",
    "observe_networks",
    "analyze_public_exposure",
    "observe_security_configuration",
    "observe_secret_references",
    "observe_iam_identities",
    "observe_iam_roles",
    "observe_iam_permissions",
    "analyze_resource_relationships",
    "observe_containers",
    "observe_clusters",
    "observe_edge_architecture",
    "analyze_origin_candidates",
    "observe_transport_security",
]

EXPECTED_COUNTS: dict[str, dict[str, int]] = {
    AWS: {
        "discover_providers": 1,
        "inventory_accounts": 1,
        "inventory_projects": 2,
        "inventory_resources": 17,
        "observe_compute": 2,
        "observe_storage": 3,
        "observe_databases": 1,
        "observe_networks": 5,
        "analyze_public_exposure": 5,
        "observe_security_configuration": 7,
        "observe_secret_references": 3,
        "observe_iam_identities": 3,
        "observe_iam_roles": 3,
        "observe_iam_permissions": 5,
        "analyze_resource_relationships": 7,
        "observe_containers": 2,
        "observe_clusters": 1,
        "observe_edge_architecture": 2,
        "analyze_origin_candidates": 4,
        "observe_transport_security": 4,
    },
    AZURE: {
        "discover_providers": 1,
        "inventory_accounts": 1,
        "inventory_projects": 2,
        "inventory_resources": 9,
        "observe_compute": 2,
        "observe_storage": 1,
        "observe_databases": 1,
        "observe_networks": 2,
        "analyze_public_exposure": 2,
        "observe_security_configuration": 2,
        "observe_secret_references": 1,
        "observe_iam_identities": 2,
        "observe_iam_roles": 2,
        "observe_iam_permissions": 2,
        "analyze_resource_relationships": 2,
        "observe_containers": 1,
        "observe_clusters": 1,
        "observe_edge_architecture": 1,
        "analyze_origin_candidates": 2,
        "observe_transport_security": 2,
    },
    GCP: {
        "discover_providers": 1,
        "inventory_accounts": 1,
        "inventory_projects": 1,
        "inventory_resources": 8,
        "observe_compute": 2,
        "observe_storage": 1,
        "observe_databases": 1,
        "observe_networks": 1,
        "analyze_public_exposure": 2,
        "observe_security_configuration": 2,
        "observe_secret_references": 1,
        "observe_iam_identities": 2,
        "observe_iam_roles": 2,
        "observe_iam_permissions": 2,
        "analyze_resource_relationships": 2,
        "observe_containers": 1,
        "observe_clusters": 1,
        "observe_edge_architecture": 1,
        "analyze_origin_candidates": 2,
        "observe_transport_security": 2,
    },
}

_ERROR_TARGETS: dict[str, CloudStatus] = {
    "aws/snail-account": CloudStatus.TIMEOUT,
    "aws/bursty-account": CloudStatus.RATE_LIMITED,
    "aws/locked-account": CloudStatus.UNAUTHORIZED,
    "aws/garbled-account": CloudStatus.MALFORMED_RESPONSE,
    "aws/fabricated-estate": CloudStatus.UNSUPPORTED_PROVIDER,
}

_ERROR_KIND_BY_TARGET: dict[str, str] = {
    "aws/snail-account": "timeout",
    "aws/bursty-account": "rate_limited",
    "aws/locked-account": "unauthorized",
    "aws/garbled-account": "malformed",
    "aws/fabricated-estate": "unsupported_provider",
}

_ALLOWED_TARGETS = [
    Target(value=AWS, target_type=TargetType.CLOUD),
    Target(value=AZURE, target_type=TargetType.CLOUD),
    Target(value=GCP, target_type=TargetType.CLOUD),
]


def _scope(
    mission_id: str = MID,
    *,
    max_risk_level: RiskLevel = RiskLevel.HIGH,
    allowed_targets: list[Target] | None = None,
) -> TargetScope:
    return TargetScope(
        mission_id=mission_id,
        allowed_targets=allowed_targets or _ALLOWED_TARGETS,
        allowed_capabilities=[],
        max_risk_level=max_risk_level,
    )


def _demo_scope(mission_id: str = MID) -> TargetScope:
    return _scope(allowed_targets=[*_ALLOWED_TARGETS], mission_id=mission_id)


def _request(
    mission_id: str = MID,
    *,
    scope: TargetScope | None = None,
    mode: CloudMode = CloudMode.CONTROLLED,
) -> CloudRequest:
    return CloudRequest(
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
) -> tuple[CloudEngine, EvidenceStore | None, WorldModelStore | None]:
    evidence_store = (
        EvidenceStore(repository=InMemoryEvidenceRepository()) if use_stores else None
    )
    world = (
        WorldModelStore(repository=InMemoryWorldRepository()) if use_stores else None
    )
    engine = CloudEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


class TestCloudModels:
    def test_mode_enum(self) -> None:
        assert CloudMode.PASSIVE.value == "passive"
        assert CloudMode.CONTROLLED.value == "controlled"

    def test_status_enum(self) -> None:
        expected = {
            "success", "partial", "limited", "no_evidence", "request_failed",
            "rate_limited", "unauthorized", "out_of_scope",
            "malformed_response", "timeout", "unknown_provider",
            "unsupported_provider", "failed",
        }
        assert {s.value for s in CloudStatus} == expected

    def test_observation_kind_enum(self) -> None:
        expected = {
            "provider", "account", "project", "cloud_resource", "compute",
            "storage", "database", "network", "public_exposure",
            "security_configuration", "secret_reference", "iam_identity",
            "iam_role", "iam_permission", "resource_relationship",
            "container", "cluster", "edge_architecture",
            "origin_candidate", "transport_security",
        }
        assert {k.value for k in CloudObservationKind} == expected

    def test_observation_discriminated_union(self) -> None:
        compute = ComputeObservation(
            provider="aws", account="aelionix-aws-test", region="us-test-1",
            name="web-01",
        )
        assert compute.kind == "compute"
        sec = SecurityConfigurationObservation(
            provider="aws", account="aelionix-aws-test",
            entity_type="account", entity="aelionix-aws-test",
            item="cloudtrail_logging", value="enabled", source="provider",
        )
        assert sec.kind == "security_configuration"

    def test_request_validation(self) -> None:
        with pytest.raises(ValueError):
            CloudRequest(mission_id=MID, scope=_scope(), max_observations=0)
        with pytest.raises(ValueError):
            CloudRequest(mission_id=MID, scope=_scope(), timeout_seconds=0)

    def test_result_observation_count(self) -> None:
        result = CloudResult(
            mission_id=MID,
            session_id=SID,
            target=AWS,
            capability_id="cloud.compute_observation",
            mode=CloudMode.CONTROLLED,
            observations=[compute()],
        )
        assert result.observation_count == 1
        assert result.observation_count == len(result.observations)


class TestCloudScopeMatching:
    def test_target_type_detection(self) -> None:
        assert detect_target_type(AWS) == TargetType.CLOUD
        assert detect_target_type(AZURE) == TargetType.CLOUD
        assert detect_target_type(GCP) == TargetType.CLOUD
        assert detect_target_type("aws/aelionix-aws-test/web-01") == TargetType.ASSET
        assert detect_target_type("supersky.aelionix.com") == TargetType.DOMAIN

    def test_provider_capabilities_support_cloud_targets(self) -> None:
        for meta in build_cloud_meta():
            assert TargetType.CLOUD in meta.supported_target_types

    def test_all_cloud_capabilities_are_low_risk_passive(self) -> None:
        for meta in build_cloud_meta():
            assert meta.risk_level == RiskLevel.LOW
            assert meta.mode == CloudMode.PASSIVE
            assert len(meta.produces) == 1

    def test_scope_prefix_umbrella(self) -> None:
        provider_scope = _scope(
            allowed_targets=[Target(value="aws", target_type=TargetType.CLOUD)]
        )
        assert provider_scope.is_target_allowed(AWS)
        assert provider_scope.is_target_allowed("aws/other/account")
        assert not provider_scope.is_target_allowed(AZURE)
        account_scope = _scope(allowed_targets=_ALLOWED_TARGETS)
        assert account_scope.is_target_allowed(AWS)
        assert account_scope.is_target_allowed(f"{AWS}/web-01")
        assert not account_scope.is_target_allowed("aws")
        assert not account_scope.is_target_allowed("oci/oracle-account")

    def test_cloud_capabilities_reject_non_cloud_targets(self) -> None:
        engine, _, _ = _engine()
        request = _request()
        with pytest.raises(CloudExecutionError):
            engine.observe_compute(request, "api-service.example.com")


class TestCloudProviders:
    def test_parse_and_resolve(self) -> None:
        parts = parse_cloud_target(AWS)
        assert parts.provider.value == "aws"
        parts = parse_cloud_target("oci/oracle-account")
        assert parts.provider.value == "unknown"
        assert provider_for_target("aws").value == "aws"
        assert provider_for_target("oci").value == "unknown"

    def test_bare_provider_umbrella_dispatch(self) -> None:
        engine, _, _ = _engine()
        scope = _scope(
            allowed_targets=[Target(value="aws", target_type=TargetType.CLOUD)]
        )
        result = engine.discover_providers(_request(scope=scope), "aws")
        assert result.observation_count == 1


class TestCloudTransport:
    def test_transport_is_deterministic(self) -> None:
        transport = MockCloudTransport()
        for tool in TOOLS:
            first = getattr(transport, tool)(AWS)
            second = getattr(transport, tool)(AWS)
            assert first == second

    def test_typed_counts_for_all_estates(self) -> None:
        transport = MockCloudTransport()
        for estate, counts in EXPECTED_COUNTS.items():
            for tool, expected in counts.items():
                doc = json.loads(getattr(transport, tool)(estate))
                assert len(doc["observations"]) == expected, (estate, tool)

    def test_error_targets_structured(self) -> None:
        transport = MockCloudTransport()
        for target in _ERROR_TARGETS:
            doc = json.loads(transport.inventory_accounts(target))
            assert doc["error"]["kind"] == _ERROR_KIND_BY_TARGET[target], target

    def test_unknown_provider_errors(self) -> None:
        transport = MockCloudTransport()
        for tool in ("discover_providers", "inventory_accounts"):
            doc = json.loads(getattr(transport, tool)("oci/foo"))
            assert doc["error"]["kind"] == "unknown_provider"

    def test_unmodeled_provider_estate_fails_closed(self) -> None:
        transport = MockCloudTransport()
        doc = json.loads(transport.inventory_accounts("aws/not-in-model"))
        assert doc["error"]["kind"] == "unsupported_provider"


class TestCloudRedaction:
    def test_credential_keys_cover_cloud_fields(self) -> None:
        assert "access_key" in CLOUD_CREDENTIAL_KEYS
        assert "access_key_id" in CLOUD_CREDENTIAL_KEYS
        assert "secret_value" in CLOUD_CREDENTIAL_KEYS
        assert "connection_string" in CLOUD_CREDENTIAL_KEYS
        assert "private_key" in CLOUD_CREDENTIAL_KEYS
        assert "managed_identity_secret" in CLOUD_CREDENTIAL_KEYS

    def test_redaction_removes_demo_secrets(self) -> None:
        transport = MockCloudTransport()
        raw = transport.observe_compute(AWS)
        assert "demo-" in raw
        redacted = redact_cloud_raw(raw)
        assert "demo-access-key-0000" not in redacted
        assert "demo-private-key-0000" not in redacted
        assert "demo-aws-secret-0000" not in redacted

    def test_redaction_preserves_security_values(self) -> None:
        transport = MockCloudTransport()
        raw = transport.observe_security_configuration(AWS)
        redacted = redact_cloud_raw(raw)
        assert '"enabled"' in redacted
        assert '"disabled"' in redacted
        assert "cloudtrail_logging" in redacted

    def test_credential_value_redacted_signature(self) -> None:
        assert credential_value_redacted() == "REDACTED"


class TestCloudConfidence:
    def test_confidence_policy(self) -> None:
        compute = ComputeObservation(
            provider="aws", account="aelionix-aws-test", name="web-01"
        )
        exposure = PublicExposureObservation(
            provider="aws", account="aelionix-aws-test",
            resource_type=CloudResourceType.COMPUTE_INSTANCE,
            resource="web-01", exposed=True,
        )
        assert observation_confidence(compute, CloudMode.CONTROLLED) == Confidence.HIGH
        assert observation_confidence(exposure, CloudMode.CONTROLLED) == Confidence.MEDIUM
        assert observation_confidence(compute, CloudMode.PASSIVE) == Confidence.LOW
        assert observation_confidence(exposure, CloudMode.PASSIVE) == Confidence.LOW

    def test_derived_kinds_never_high(self) -> None:
        exposure = PublicExposureObservation(
            provider="aws", account="aelionix-aws-test",
            resource_type=CloudResourceType.COMPUTE_INSTANCE,
            resource="web-01", exposed=True,
        )
        relationship = ResourceRelationshipObservation(
            provider="aws", account="aelionix-aws-test",
            relationship_type="uses",
            source_type=CloudResourceType.COMPUTE_INSTANCE, source="web-01",
            target_type=CloudResourceType.STORAGE_BUCKET, target="public-bucket",
        )
        assert observation_confidence(exposure, CloudMode.CONTROLLED) in {
            Confidence.MEDIUM, Confidence.LOW,
        }
        assert observation_confidence(relationship, CloudMode.CONTROLLED) in {
            Confidence.MEDIUM, Confidence.LOW,
        }


class TestCloudNormalization:
    def test_adapter_registered_for_every_tool(self) -> None:
        for tool in TOOLS:
            assert adapter_for_tool(tool) is not None

    def test_error_document_propagates(self) -> None:
        transport = MockCloudTransport()
        raw = transport.inventory_accounts("aws/snail-account")
        out = adapter_for_tool("inventory_accounts").adapt(
            raw, context={"target": "aws/snail-account"}
        )
        assert out.error is not None
        assert out.error["kind"] == "timeout"
        assert out.observations == []

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(CloudNormalizationError):
            adapter_for_tool("observe_compute").adapt("{not json")

    def test_compute_adapter_redacts_tags(self) -> None:
        transport = MockCloudTransport()
        raw = transport.observe_compute(AWS)
        out = adapter_for_tool("observe_compute").adapt(raw, context={"target": AWS})
        observations = list(out.observations)
        assert observations
        json.dumps([o.model_dump() for o in observations])
        assert not any(
            "demo-" in json.dumps(o.model_dump()) for o in observations
        )


class TestCloudEvidence:
    def test_artifact_evidence_redacts_and_embeds_mode(self) -> None:
        transport = MockCloudTransport()
        raw = transport.observe_iam_identities(AWS)
        evidence = artifact_evidence(MID, AWS, "cloud.iam_identity_observation", raw)
        assert evidence.evidence_type.value == "artifact"
        assert evidence.confidence == Confidence.HIGH
        payload = evidence.raw_data
        assert "demo-" not in payload
        assert '"mode": "controlled"' in payload

    def test_observation_evidence_embeds_mode(self) -> None:
        compute = ComputeObservation(
            provider="aws", account="aelionix-aws-test", name="web-01"
        )
        evidence = observation_evidence(MID, AWS, "cloud.compute_observation", compute)
        assert '"mode": "controlled"' in evidence.raw_data
        assert evidence.confidence == Confidence.HIGH

    def test_evidence_dedup_key_stable(self) -> None:
        compute = ComputeObservation(
            provider="aws", account="aelionix-aws-test", name="web-01"
        )
        one = observation_evidence(MID, AWS, "cloud.compute_observation", compute)
        two = observation_evidence(MID, AWS, "cloud.compute_observation", compute)
        assert evidence_dedup_key_for(one) == evidence_dedup_key_for(two)

    def test_existing_evidence_id_dedup(self) -> None:
        engine, evidence_store, _ = _engine()
        request = _request()
        result = engine.observe_compute(request, AWS)
        first_len = len(result.evidence_ids)
        result2 = engine.observe_compute(request, AWS)
        assert len(result2.evidence_ids) == first_len

        evidence = observation_evidence(
            MID, AWS, "cloud.compute_observation",
            result.observations[0],
        )
        assert existing_evidence_id(evidence_store, evidence) is not None


class TestCloudMaterializer:
    def test_world_materialization(self) -> None:
        engine, evidence_store, world = _engine()
        request = _request()
        for tool in TOOLS:
            getattr(engine, tool)(request, AWS)

        assert world.count_entities(MID, lifecycle=WorldLifecycle.ACTIVE) > 0
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_PROVIDER, lifecycle=WorldLifecycle.ACTIVE
        ) == 1
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_ACCOUNT, lifecycle=WorldLifecycle.ACTIVE
        ) == 1
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_PROJECT, lifecycle=WorldLifecycle.ACTIVE
        ) == 2
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_COMPUTE, lifecycle=WorldLifecycle.ACTIVE
        ) == 2
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_STORAGE, lifecycle=WorldLifecycle.ACTIVE
        ) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_NETWORK, lifecycle=WorldLifecycle.ACTIVE
        ) == 5
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_CLUSTER, lifecycle=WorldLifecycle.ACTIVE
        ) == 1
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_CONTAINER, lifecycle=WorldLifecycle.ACTIVE
        ) == 2
        assert world.count_entities(
            MID, entity_type=EntityType.CLOUD_SECRET, lifecycle=WorldLifecycle.ACTIVE
        ) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.IDENTITY, lifecycle=WorldLifecycle.ACTIVE
        ) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.ROLE, lifecycle=WorldLifecycle.ACTIVE
        ) == 3
        assert world.count_entities(
            MID, entity_type=EntityType.PERMISSION, lifecycle=WorldLifecycle.ACTIVE
        ) == 5

    def test_iam_entities_namespaced_per_provider_account(self) -> None:
        engine, _, world = _engine()
        for tool in ("observe_iam_identities", "observe_iam_roles", "observe_iam_permissions"):
            getattr(engine, tool)(_request(), AWS)
        identities = world.list_entities(
            WorldQuery(mission_id=MID, entity_type=EntityType.IDENTITY, limit=100)
        )
        assert identities
        assert all(e.namespace == "aws/aelionix-aws-test" for e in identities)

    def test_no_offensive_relationships(self) -> None:
        engine, _, world = _engine()
        request = _request()
        for tool in ("observe_compute", "observe_networks", "analyze_resource_relationships"):
            getattr(engine, tool)(request, AWS)
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

    def test_security_configuration_contradiction_surfaces(self) -> None:
        engine, _, world = _engine()
        result = engine.observe_security_configuration(_request(), AWS)
        assert result.observation_count == 6
        assert result.status == CloudStatus.PARTIAL
        accounts = world.list_entities(
            WorldQuery(
                mission_id=MID,
                entity_type=EntityType.CLOUD_ACCOUNT,
                limit=100,
            )
        )
        account = next(e for e in accounts if e.name == "aelionix-aws-test")
        assertions = world.list_assertions(
            str(account.id), lifecycle=WorldLifecycle.ACTIVE
        )
        cloudtrail = [
            a for a in assertions if a.property_key == "cloudtrail_logging"
        ]
        assert {a.property_value for a in cloudtrail} == {
            "enabled", "disabled",
        }

    def test_materialize_report_shape(self) -> None:
        report = CloudMaterializeReport()
        assert report.entities_created == 0
        assert report.assertions_contradicted == 0


class TestCloudEdgeExposure:
    """Phase 11 amendment: edge / origin-candidate / transport-security.

    Scenario fixtures:
      S1 AWS ``cdn-edge-main`` fronts web-01 via origin 10.0.0.10;
         ``directly_reachable_origin`` is asserted INFERRED ``false``.
      S2 Azure ``vm-02.aelionix.test`` candidate 198.51.100.21 is a
         provider-reported public endpoint with no edge in front.
      S3 AWS ``app.aelionix.test`` has two candidates: 10.0.0.10
         (HIGH confidence / INFERRED / unvalidated, ``edge_config``) and
         203.0.113.10 (LOW / HYPOTHESIZED / unvalidated, exposure feed).
      S4 AWS ``orders.internal.aelionix.test``/10.0.1.20 is an internal
         service candidate (HIGH / OBSERVED).
      S5 AWS ``app.aelionix.test`` carries contradictory TLS rows
         (``tls_enforced`` true vs false) that must both surface.
    """

    EDGE_TOOLS = (
        "observe_edge_architecture",
        "analyze_origin_candidates",
        "observe_transport_security",
    )

    def _run(
        self,
        engine: CloudEngine,
        target: str,
        tools: tuple[str, ...] | None = None,
    ) -> None:
        request = _request()
        for tool in tools or self.EDGE_TOOLS:
            result = getattr(engine, tool)(request, target)
            assert result.status == CloudStatus.SUCCESS, (target, tool, result.status)

    def _assertions(
        self, world: WorldModelStore, entity_id: str
    ) -> dict[str, set[str]]:
        by_key: dict[str, set[str]] = {}
        for assertion in world.list_assertions(
            entity_id, lifecycle=WorldLifecycle.ACTIVE
        ):
            by_key.setdefault(assertion.property_key, set()).add(
                assertion.property_value or ""
            )
        return by_key

    def test_edge_origin_transport_counts_per_estate(self) -> None:
        expected = {
            AWS: {
                EntityType.EDGE_ENDPOINT: 2,
                EntityType.ORIGIN_ENDPOINT: 1,
                EntityType.ORIGIN_CANDIDATE: 4,
                EntityType.PUBLIC_ADDRESS: 1,
                EntityType.PRIVATE_ADDRESS: 2,
                EntityType.ENDPOINT: 3,
            },
            AZURE: {
                EntityType.EDGE_ENDPOINT: 1,
                EntityType.ORIGIN_ENDPOINT: 1,
                EntityType.ORIGIN_CANDIDATE: 2,
                EntityType.PUBLIC_ADDRESS: 1,
                EntityType.PRIVATE_ADDRESS: 1,
                EntityType.ENDPOINT: 2,
            },
            GCP: {
                EntityType.EDGE_ENDPOINT: 1,
                EntityType.ORIGIN_ENDPOINT: 1,
                EntityType.ORIGIN_CANDIDATE: 2,
                EntityType.PUBLIC_ADDRESS: 1,
                EntityType.PRIVATE_ADDRESS: 1,
                EntityType.ENDPOINT: 2,
            },
        }
        for target, counts in expected.items():
            engine, _, world = _engine()
            self._run(engine, target)
            for entity_type, expected_count in counts.items():
                actual = world.count_entities(
                    MID,
                    entity_type=entity_type,
                    lifecycle=WorldLifecycle.ACTIVE,
                )
                assert actual == expected_count, (target, entity_type, actual)

    def test_protected_applications_not_directly_exposed(self) -> None:
        engine, _, world = _engine()
        request = _request()
        engine.observe_compute(request, AWS)
        engine.observe_edge_architecture(request, AWS)
        web01 = world.find_entity(
            MID, EntityType.CLOUD_COMPUTE, "web-01", namespace=AWS
        )
        assert web01 is not None
        edges = world.list_entities(
            WorldQuery(
                mission_id=MID,
                entity_type=EntityType.EDGE_ENDPOINT,
                lifecycle=WorldLifecycle.ACTIVE,
                limit=100,
            )
        )
        assert len(edges) == 2
        origin = world.find_entity(
            MID, EntityType.ORIGIN_ENDPOINT, "10.0.0.10", namespace=AWS
        )
        assert origin is not None
        proxy_targets: list[str] = []
        for edge in edges:
            reachable = self._assertions(world, str(edge.id))[
                "directly_reachable_origin"
            ]
            assert reachable == {"false"}
            reachable_assertions = [
                a
                for a in world.list_assertions(
                    str(edge.id), lifecycle=WorldLifecycle.ACTIVE
                )
                if a.property_key == "directly_reachable_origin"
            ]
            assert all(
                a.epistemic_status == EvidenceStatus.INFERRED
                for a in reachable_assertions
            )
            protects = world.list_relationships(
                RelationshipQuery(
                    mission_id=MID,
                    source_entity_id=str(edge.id),
                    relationship_type=RelationshipType.PROTECTS,
                    limit=100,
                )
            )
            assert len(protects) == 1
            assert str(protects[0].target_entity_id) == str(web01.id)
            proxies = world.list_relationships(
                RelationshipQuery(
                    mission_id=MID,
                    source_entity_id=str(edge.id),
                    relationship_type=RelationshipType.PROXIES,
                    limit=100,
                )
            )
            assert len(proxies) == 1
            proxy_targets.append(str(proxies[0].target_entity_id))
        assert str(origin.id) in proxy_targets
        fronted = world.list_relationships(
            RelationshipQuery(
                mission_id=MID,
                source_entity_id=str(origin.id),
                relationship_type=RelationshipType.FRONTED_BY,
                limit=100,
            )
        )
        assert len(fronted) >= 1
        for r in fronted:
            fronted_entity = world.get_entity(str(r.target_entity_id))
            assert fronted_entity is not None
            assert fronted_entity.entity_type == EntityType.EDGE_ENDPOINT

    def test_candidate_correlation_does_not_confirm(self) -> None:
        engine, _, world = _engine()
        self._run(engine, AWS, tools=("observe_edge_architecture", "analyze_origin_candidates"))
        candidate = world.find_entity(
            MID,
            EntityType.ORIGIN_CANDIDATE,
            "app.aelionix.test:10.0.0.10",
            namespace=AWS,
        )
        assert candidate is not None
        assert candidate.entity_type == EntityType.ORIGIN_CANDIDATE
        assertions = self._assertions(world, str(candidate.id))
        assert assertions["confidence_label"] == {"high"}
        assert assertions["evidence_status"] == {"inferred"}
        assert assertions["validation_status"] == {"unvalidated"}
        origin = world.find_entity(
            MID, EntityType.ORIGIN_ENDPOINT, "10.0.0.10", namespace=AWS
        )
        assert origin is not None
        out = world.list_relationships(
            RelationshipQuery(
                mission_id=MID,
                source_entity_id=str(candidate.id),
                limit=100,
            )
        )
        routes = [
            r for r in out if r.relationship_type == RelationshipType.ROUTES_TO
        ]
        assert len(routes) == 1
        assert str(routes[0].target_entity_id) == str(
            world.find_entity(
                MID, EntityType.PRIVATE_ADDRESS, "10.0.0.10", namespace=AWS
            ).id
        )
        correlated = [
            r
            for r in out
            if r.relationship_type == RelationshipType.ORIGINATES_FROM
        ]
        assert len(correlated) == 1
        assert str(correlated[0].target_entity_id) == str(origin.id)
        candidates = world.list_entities(
            WorldQuery(
                mission_id=MID,
                entity_type=EntityType.ORIGIN_CANDIDATE,
                namespace=AWS,
                lifecycle=WorldLifecycle.ACTIVE,
                limit=100,
            )
        )
        assert all(
            e.entity_type == EntityType.ORIGIN_CANDIDATE for e in candidates
        )

    def test_exposure_feed_candidate_stays_hypothesized(self) -> None:
        engine, _, world = _engine()
        self._run(engine, AWS, tools=("analyze_origin_candidates",))
        candidate = world.find_entity(
            MID,
            EntityType.ORIGIN_CANDIDATE,
            "app.aelionix.test:203.0.113.10",
            namespace=AWS,
        )
        assert candidate is not None
        assertions = self._assertions(world, str(candidate.id))
        assert assertions["confidence_label"] == {"low"}
        assert assertions["evidence_status"] == {"hypothesized"}
        assert assertions["validation_status"] == {"unvalidated"}
        assert (
            classify_address("203.0.113.10") == AddressType.PUBLIC_ADDRESS
        )
        assert (
            classify_address("10.0.0.10") == AddressType.PRIVATE_ADDRESS
        )
        public = world.find_entity(
            MID, EntityType.PUBLIC_ADDRESS, "203.0.113.10", namespace=AWS
        )
        assert public is not None
        out = world.list_relationships(
            RelationshipQuery(
                mission_id=MID,
                source_entity_id=str(candidate.id),
                limit=100,
            )
        )
        route_to_public = [
            r
            for r in out
            if r.relationship_type == RelationshipType.ROUTES_TO
            and str(r.target_entity_id) == str(public.id)
        ]
        assert len(route_to_public) == 1
        assert all(
            r.relationship_type != RelationshipType.ORIGINATES_FROM for r in out
        )

    def test_internal_service_candidate_is_private(self) -> None:
        engine, _, world = _engine()
        self._run(engine, AWS, tools=("analyze_origin_candidates",))
        candidate = world.find_entity(
            MID,
            EntityType.ORIGIN_CANDIDATE,
            "orders.internal.aelionix.test:10.0.1.20",
            namespace=AWS,
        )
        assert candidate is not None
        assertions = self._assertions(world, str(candidate.id))
        assert assertions["confidence_label"] == {"high"}
        assert assertions["evidence_status"] == {"observed"}
        assert assertions["validation_status"] == {"unvalidated"}
        assert classify_address("10.0.1.20") == AddressType.PRIVATE_ADDRESS
        private = world.find_entity(
            MID, EntityType.PRIVATE_ADDRESS, "10.0.1.20", namespace=AWS
        )
        assert private is not None
        out = world.list_relationships(
            RelationshipQuery(
                mission_id=MID,
                source_entity_id=str(candidate.id),
                limit=100,
            )
        )
        route_to_private = [
            r
            for r in out
            if r.relationship_type == RelationshipType.ROUTES_TO
            and str(r.target_entity_id) == str(private.id)
        ]
        assert len(route_to_private) == 1
        assert all(
            r.relationship_type != RelationshipType.ORIGINATES_FROM for r in out
        )

    def test_contradictory_tls_assertions_surface(self) -> None:
        engine, _, world = _engine()
        self._run(engine, AWS, tools=("observe_transport_security",))
        endpoint = world.find_entity(
            MID, EntityType.ENDPOINT, "https://app.aelionix.test", namespace=AWS
        )
        assert endpoint is not None
        assertions = self._assertions(world, str(endpoint.id))
        assert assertions["tls_enforced"] == {"False", "True"}
        assert assertions["tls_version"] == {"TLS1.0", "TLS1.3"}

    def test_no_offensive_relationship_semantics(self) -> None:
        engine, _, world = _engine()
        for target in (AWS, AZURE, GCP):
            self._run(engine, target)
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

    def test_scope_enforcement_applies_to_edge_tools(self) -> None:
        engine, _, _ = _engine()
        request = _request(
            scope=_scope(
                allowed_targets=[
                    Target(value=AWS, target_type=TargetType.CLOUD),
                ]
            )
        )
        for tool in self.EDGE_TOOLS:
            with pytest.raises(AuthorizationError):
                getattr(engine, tool)(request, AZURE)

    def test_rerun_is_idempotent_no_duplicates(self) -> None:
        engine, _, world = _engine()
        entity_types = [
            EntityType.EDGE_ENDPOINT,
            EntityType.ORIGIN_ENDPOINT,
            EntityType.ORIGIN_CANDIDATE,
            EntityType.PUBLIC_ADDRESS,
            EntityType.PRIVATE_ADDRESS,
            EntityType.ENDPOINT,
        ]
        runs = []
        for _ in range(2):
            self._run(engine, AWS)
            counts = {
                et: world.count_entities(
                    MID, entity_type=et, lifecycle=WorldLifecycle.ACTIVE
                )
                for et in entity_types
            }
            relationship_count = len(
                world.list_relationships(
                    RelationshipQuery(mission_id=MID, limit=1000)
                )
            )
            runs.append((counts, relationship_count))
        assert runs[0] == runs[1]

    def test_confidence_policy_applies_to_edge_evidence(self) -> None:
        engine, _, _ = _engine()
        edge = engine.observe_edge_architecture(_request(), AWS)
        obs = edge.observations[0]
        controlled = observation_evidence(
            MID,
            AWS,
            "cloud.edge_architecture_observation",
            obs,
            mode=CloudMode.CONTROLLED,
        )
        assert controlled.confidence == Confidence.MEDIUM
        transport = engine.observe_transport_security(
            _request(mode=CloudMode.PASSIVE), AWS, mode="passive"
        )
        obs = transport.observations[0]
        passive = observation_evidence(
            MID,
            AWS,
            "cloud.transport_security_observation",
            obs,
            mode=CloudMode.PASSIVE,
        )
        assert passive.confidence == Confidence.LOW


class TestCloudCapabilitiesMeta:
    def test_twenty_capability_metadata(self) -> None:
        metas = build_cloud_meta()
        assert len(metas) == 20
        assert [str(m.id) for m in metas] == CLOUD_CAPABILITY_IDS

    def test_produces_match_kinds(self) -> None:
        expected = {
            "cloud.provider_discovery": CloudObservationKind.PROVIDER,
            "cloud.account_inventory": CloudObservationKind.ACCOUNT,
            "cloud.project_inventory": CloudObservationKind.PROJECT,
            "cloud.resource_inventory": CloudObservationKind.CLOUD_RESOURCE,
            "cloud.compute_observation": CloudObservationKind.COMPUTE,
            "cloud.storage_observation": CloudObservationKind.STORAGE,
            "cloud.database_observation": CloudObservationKind.DATABASE,
            "cloud.network_observation": CloudObservationKind.NETWORK,
            "cloud.public_exposure_analysis": CloudObservationKind.PUBLIC_EXPOSURE,
            "cloud.security_configuration_observation": (
                CloudObservationKind.SECURITY_CONFIGURATION
            ),
            "cloud.secret_reference_observation": (
                CloudObservationKind.SECRET_REFERENCE
            ),
            "cloud.iam_identity_observation": CloudObservationKind.IAM_IDENTITY,
            "cloud.iam_role_observation": CloudObservationKind.IAM_ROLE,
            "cloud.iam_permission_observation": (
                CloudObservationKind.IAM_PERMISSION
            ),
            "cloud.resource_relationship_analysis": (
                CloudObservationKind.RESOURCE_RELATIONSHIP
            ),
            "cloud.container_observation": CloudObservationKind.CONTAINER,
            "cloud.cluster_observation": CloudObservationKind.CLUSTER,
            "cloud.edge_architecture_observation": (
                CloudObservationKind.EDGE_ARCHITECTURE
            ),
            "cloud.origin_candidate_analysis": (
                CloudObservationKind.ORIGIN_CANDIDATE
            ),
            "cloud.transport_security_observation": (
                CloudObservationKind.TRANSPORT_SECURITY
            ),
        }
        for meta in build_cloud_meta():
            assert meta.produces == [expected[str(meta.id)]]

    def test_build_cloud_capabilities_instances(self) -> None:
        capabilities = build_cloud_capabilities()
        assert len(capabilities) == 20
        assert [c.capability_id for c in capabilities] == CLOUD_CAPABILITY_IDS


class TestCloudEngine:
    def test_engine_capabilities_match_meta(self) -> None:
        engine, _, _ = _engine()
        assert len(engine.capabilities) == 20
        for meta in build_cloud_meta():
            assert engine.has_capability(str(meta.id))

    def test_engine_registers_without_clobbering_defaults(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        before = len(registry.list_capabilities())
        _engine(registry=registry)
        assert len(registry.list_capabilities()) == before + 20
        assert registry.has("cloud.compute_observation")

    def test_run_dispatcher(self) -> None:
        engine, _, _ = _engine()
        result = engine.run(_request(), "cloud.compute_observation", AWS)
        assert result.capability_id == "cloud.compute_observation"
        assert result.observation_count == 2

    def test_unknown_capability_raises(self) -> None:
        engine, _, _ = _engine()
        with pytest.raises(CloudExecutionError):
            engine.run(_request(), "cloud.does_not_exist", AWS)

    def test_invalid_mode_raises(self) -> None:
        engine, _, _ = _engine()
        with pytest.raises(CloudExecutionError):
            engine.observe_compute(_request(), AWS, mode="turbo")

    def test_out_of_scope_raises(self) -> None:
        engine, _, _ = _engine()
        request = _request(scope=_scope(allowed_targets=_ALLOWED_TARGETS))
        with pytest.raises(AuthorizationError):
            engine.observe_compute(request, "oci/oracle-account")

    def test_unknown_provider_in_scope_fails_closed(self) -> None:
        engine, _, _ = _engine()
        scope = _scope(
            allowed_targets=[
                Target(value="oci/foo", target_type=TargetType.CLOUD),
            ]
        )
        result = engine.inventory_accounts(_request(scope=scope), "oci/foo")
        assert result.status == CloudStatus.UNKNOWN_PROVIDER
        assert len(result.observations) == 0

    def test_error_target_statuses(self) -> None:
        engine, _, _ = _engine()
        scope = _scope(
            allowed_targets=[
                Target(value="aws", target_type=TargetType.CLOUD),
            ]
        )
        for target, expected in _ERROR_TARGETS.items():
            result = engine.inventory_accounts(_request(scope=scope), target)
            assert result.status == expected, target

    def test_passive_mode_success(self) -> None:
        engine, evidence_store, _ = _engine()
        result = engine.observe_compute(
            _request(mode=CloudMode.PASSIVE), AWS, mode="passive"
        )
        assert result.status == CloudStatus.SUCCESS
        assert result.mode == CloudMode.PASSIVE
        obs = result.observations[0]
        evidence = observation_evidence(
            MID, AWS, "cloud.compute_observation", obs, mode=CloudMode.PASSIVE
        )
        assert evidence.confidence == Confidence.LOW

    def test_mode_param_override(self) -> None:
        engine, _, _ = _engine()
        request = _request(mode=CloudMode.CONTROLLED)
        result = engine.observe_compute(request, AWS, mode="passive")
        assert result.mode == CloudMode.PASSIVE

    def test_observation_limit_truncates(self) -> None:
        engine, _, _ = _engine()
        request = CloudRequest(
            mission_id=MID,
            session_id=SID,
            scope=_scope(),
            mode=CloudMode.CONTROLLED,
            max_observations=2,
            timeout_seconds=30.0,
        )
        result = engine.inventory_resources(request, AWS)
        assert result.status == CloudStatus.LIMITED
        assert result.observation_count == 2
        assert len(result.warnings) == 1

    def test_evidence_persisted(self) -> None:
        engine, evidence_store, _ = _engine()
        result = engine.observe_compute(_request(), AWS)
        assert len(result.evidence_ids) == 3
        artifact = evidence_store.get(result.evidence_ids[0])
        assert artifact.evidence_type.value == "artifact"
        assert "demo-" not in artifact.raw_data

    def test_repeat_run_does_not_duplicate_evidence(self) -> None:
        engine, evidence_store, _ = _engine()
        request = _request()
        first = engine.observe_iam_identities(request, AWS)
        second = engine.observe_iam_identities(request, AWS)
        assert first.evidence_ids == second.evidence_ids


class TestCloudCoexistence:
    def test_cloud_and_all_engines_total_eighty_one(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        for builder in (
            build_recon_capabilities,
            build_webapi_capabilities,
            build_auth_capabilities,
            build_business_logic_capabilities,
            build_network_capabilities,
            build_identity_capabilities,
            build_cloud_capabilities,
        ):
            for capability in builder():
                if not registry.has(capability.capability_id):
                    registry.register(capability)
        all_caps = registry.list_capabilities()
        assert len(all_caps) == 81
        assert "mock_discovery" in all_caps
        for cap_id in CLOUD_CAPABILITY_IDS:
            assert cap_id in all_caps
        assert len(CLOUD_CAPABILITY_IDS) == 20

    def test_cloud_engine_coexists_in_provider_registry(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        cloud_engine, _, _ = _engine(registry=registry)
        assert len(cloud_engine.capabilities) == 20
        for cap_id in CLOUD_CAPABILITY_IDS:
            assert registry.has(cap_id)


def compute() -> ComputeObservation:
    return ComputeObservation(
        provider="aws", account="aelionix-aws-test", region="us-test-1", name="web-01"
    )
