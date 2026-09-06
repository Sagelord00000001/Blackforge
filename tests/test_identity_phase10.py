from __future__ import annotations

import json

import pytest

from blackforge.authorization import AuthorizationBoundary
from blackforge.business_logic.capabilities import (
    build_business_logic_capabilities,
)
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import AuthorizationError, IdentityExecutionError
from blackforge.core.types import (
    Confidence,
    RiskLevel,
    TargetType,
)
from blackforge.evidence.repository import InMemoryEvidenceRepository
from blackforge.evidence.store import EvidenceStore
from blackforge.identity import (
    IDENTITY_CAPABILITY_IDS,
    IDENTITY_DIRECTORY,
    IDENTITY_DIRECTORY_DNS,
    IdentityEngine,
    IdentityInventoryAdapter,
    IdentityMaterializeReport,
    IdentityMode,
    IdentityObservationKind,
    IdentityRequest,
    IdentityStatus,
    IdentityWorldMaterializer,
    MockIdentityTransport,
    build_identity_capabilities,
    build_identity_meta,
    credential_value_redacted,
    observation_confidence,
    observation_evidence,
    redact_identity_raw,
)
from blackforge.identity.evidence import (
    existing_evidence_id,
)
from blackforge.identity.models import (
    IdentityObservation,
    MetadataObservation,
    RelationshipObservation,
)
from blackforge.identity.normalization import (
    adapter_for_tool,
)
from blackforge.identity.redaction import IDENTITY_CREDENTIAL_KEYS
from blackforge.network.capabilities import build_network_capabilities
from blackforge.network.engine import NetworkEngine
from blackforge.recon.capabilities import build_recon_capabilities
from blackforge.scope.models import Target, TargetScope, detect_target_type
from blackforge.webapi.capabilities import build_webapi_capabilities
from blackforge.world_model.query import WorldQuery
from blackforge.world_model.repository import InMemoryWorldRepository
from blackforge.world_model.store import WorldModelStore

MID = "mission_id10"
SID = "sess_id10"

DIR = IDENTITY_DIRECTORY  # AELIONIX-CORP
DNS = IDENTITY_DIRECTORY_DNS  # AELIONIX-CORP.LOCAL

ERROR_DIRS: dict[str, IdentityStatus] = {
    "SNAIL-DIR": IdentityStatus.TIMEOUT,
    "BURSTY-DIR": IdentityStatus.RATE_LIMITED,
    "LOCKED-DIR": IdentityStatus.UNAUTHORIZED,
    "GARBLED-DIR": IdentityStatus.MALFORMED_RESPONSE,
    "FABRICATED-DIR": IdentityStatus.UNSUPPORTED_DIRECTORY,
    "OTHER-CORP": IdentityStatus.UNSUPPORTED_DIRECTORY,
}

_SCOPE_TARGETS = [
    DIR,
    DNS,
    "AELIONIX-CORP\\alice",
    "alice@aelionix-corp.local",
    "alice",
    "bob",
    "api-service",
    "ghost-identity",
    *list(ERROR_DIRS),
]


def _scope(
    mission_id: str = MID,
    *,
    max_risk_level: RiskLevel = RiskLevel.HIGH,
    allowed_targets: list[str] | None = None,
) -> TargetScope:
    targets = (
        [Target(value=t, target_type=detect_target_type(t)) for t in allowed_targets]
        if allowed_targets is not None
        else [
            Target(value=DIR, target_type=TargetType.DIRECTORY),
            Target(value=DNS, target_type=TargetType.DOMAIN),
        ]
    )
    return TargetScope(
        mission_id=mission_id,
        allowed_targets=targets,
        allowed_capabilities=[],
        max_risk_level=max_risk_level,
    )


def _request(
    mission_id: str = MID,
    *,
    scope: TargetScope | None = None,
    mode: IdentityMode = IdentityMode.CONTROLLED,
    identity: str | None = None,
) -> IdentityRequest:
    return IdentityRequest(
        mission_id=mission_id,
        session_id=SID,
        scope=scope or _scope(),
        mode=mode,
        identity=identity,
        max_observations=500,
        timeout_seconds=30.0,
    )


def _demo_scope(mission_id: str = MID) -> TargetScope:
    return _scope(allowed_targets=_SCOPE_TARGETS, mission_id=mission_id)


def _engine(
    *,
    registry: CapabilityRegistry | None = None,
    use_stores: bool = True,
) -> tuple[IdentityEngine, EvidenceStore | None, WorldModelStore | None]:
    evidence_store = (
        EvidenceStore(repository=InMemoryEvidenceRepository()) if use_stores else None
    )
    world = (
        WorldModelStore(repository=InMemoryWorldRepository()) if use_stores else None
    )
    engine = IdentityEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


class TestIdentityModels:
    def test_mode_enum(self) -> None:
        assert IdentityMode.PASSIVE.value == "passive"
        assert IdentityMode.CONTROLLED.value == "controlled"

    def test_status_enum(self) -> None:
        expected = {
            "success", "partial", "limited", "no_evidence", "request_failed",
            "rate_limited", "unauthorized", "out_of_scope",
            "malformed_response", "timeout", "unsupported_directory", "failed",
        }
        assert {s.value for s in IdentityStatus} == expected

    def test_observation_kind_enum(self) -> None:
        expected = {
            "directory", "identity", "group", "role", "permission",
            "resource", "membership", "role_assignment",
            "permission_assignment", "relationship", "metadata",
        }
        assert {k.value for k in IdentityObservationKind} == expected

    def test_result_observation_count(self) -> None:
        from blackforge.identity.models import IdentityResult

        result = IdentityResult(
            mission_id=MID,
            session_id=SID,
            target=DIR,
            capability_id="identity.identity_inventory",
            mode=IdentityMode.CONTROLLED,
            observations=[
                IdentityObservation(identity="alice", directory="aelionix-corp")
            ],
        )
        assert result.observation_count == 1


class TestIdentityScopeMatching:
    def test_target_type_detection(self) -> None:
        assert detect_target_type(DIR) == TargetType.ASSET
        assert detect_target_type(DNS) == TargetType.DOMAIN
        assert detect_target_type("alice@aelionix-corp.local") == TargetType.DOMAIN
        assert detect_target_type("AELIONIX-CORP\\alice") == TargetType.ASSET

    def test_directory_nd_identity_level_target_support(self) -> None:
        engine, _, _ = _engine()
        for meta in build_identity_meta():
            assert TargetType.ASSET in meta.supported_target_types
        directory_level = {
            m.id for m in build_identity_meta()
            if TargetType.IDENTITY not in m.supported_target_types
        }
        assert directory_level == {
            "identity.directory_discovery",
            "identity.identity_inventory",
            "identity.group_inventory",
            "identity.role_inventory",
            "identity.permission_inventory",
            "identity.resource_inventory",
        }

    def test_all_identity_capabilities_are_low_risk(self) -> None:
        for meta in build_identity_meta():
            assert meta.risk_level == RiskLevel.LOW


class TestIdentityTransport:
    def test_discover_directories(self) -> None:
        transport = MockIdentityTransport()
        doc = json.loads(transport.discover_directories(DIR))
        assert doc["directory"] == DIR
        assert doc["observations"][0]["dns_name"] == DNS
        assert doc["observations"][0]["directory_type"] == "active_directory_domain"

    def test_inventory_identities_carries_demo_secrets(self) -> None:
        transport = MockIdentityTransport()
        raw = transport.inventory_identities(DIR)
        assert "demo-build-secret-hash-0000" in raw
        assert "demo-api-key-0000" in raw

    def test_identity_target_spellings(self) -> None:
        transport = MockIdentityTransport()
        cases = {
            "alice@aelionix-corp.local": None,
            "AELIONIX-CORP\\alice": None,
            "AELIONIX-CORP": "alice",
        }
        for spelling, identity in cases.items():
            doc = json.loads(
                transport.observe_membership(spelling, identity=identity)
            )
            assert doc["directory"] == DIR
            assert doc["identity"] == "alice"
            assert "engineering" in [o["group"] for o in doc["observations"]]

    def test_unknown_identity_error(self) -> None:
        doc = json.loads(
            MockIdentityTransport().observe_membership(
                "AELIONIX-CORP\\ghost-identity"
            )
        )
        assert doc["error"]["kind"] == "unknown_identity"

    def test_directory_level_with_identity_name(self) -> None:
        transport = MockIdentityTransport()
        doc = json.loads(transport.inventory_identities("AELIONIX-CORP\\alice"))
        assert doc["observations"][0]["directory"] == DIR

    def test_error_directories(self) -> None:
        transport = MockIdentityTransport()
        expected = {
            "SNAIL-DIR": "timeout",
            "BURSTY-DIR": "rate_limited",
            "LOCKED-DIR": "unauthorized",
            "GARBLED-DIR": "malformed",
            "FABRICATED-DIR": "unsupported_directory",
            "OTHER-CORP": "unsupported_directory",
        }
        for directory, kind in expected.items():
            doc = json.loads(transport.inventory_identities(directory))
            assert doc["error"]["kind"] == kind, directory


class TestIdentityNormalization:
    def test_inventory_adapter_kind(self) -> None:
        transport = MockIdentityTransport()
        adapter = IdentityInventoryAdapter()
        output = adapter.adapt(
            transport.inventory_identities(DIR), context={"target": DIR}
        )
        kinds = {o.kind for o in output.observations}
        assert kinds == {IdentityObservationKind.IDENTITY}
        assert all(isinstance(o, IdentityObservation) for o in output.observations)

    def test_membership_duplicate_collapse(self) -> None:
        transport = MockIdentityTransport()
        adapter = adapter_for_tool("observe_membership")
        output = adapter.adapt(
            transport.observe_membership(DIR, identity="alice"),
            context={"target": DIR},
        )
        assert len(output.observations) == 1
        assert output.observations[0].group == "engineering"
        assert any(
            "collapsed duplicate membership" in w for w in output.warnings
        )

    def test_metadata_unresolved_reference_skipped(self) -> None:
        transport = MockIdentityTransport()
        adapter = adapter_for_tool("observe_metadata")
        output = adapter.adapt(
            transport.observe_metadata(DIR, identity="api-service"),
            context={"target": DIR},
        )
        assert all(o.resolved for o in output.observations)
        assert any(
            "skipped unresolved metadata" in w and "manager" in w
            for w in output.warnings
        )

    def test_metadata_secondary_feed_source_kept(self) -> None:
        transport = MockIdentityTransport()
        adapter = adapter_for_tool("observe_metadata")
        output = adapter.adapt(
            transport.observe_metadata(DIR, identity="alice"),
            context={"target": DIR},
        )
        assert len(output.observations) == 2
        sources = {o.source for o in output.observations}
        assert sources == {"directory", "secondary_hr_feed"}

    def test_all_adapters_registered(self) -> None:
        for method in (
            "discover_directories", "inventory_identities", "inventory_groups",
            "inventory_roles", "inventory_permissions", "inventory_resources",
            "observe_membership", "observe_role_assignment",
            "observe_permission_assignment", "analyze_relationships",
            "observe_metadata",
        ):
            assert adapter_for_tool(method).tool == method

    def test_unknown_adapter_raises(self) -> None:
        with pytest.raises(IdentityExecutionError):
            engine, _, _ = _engine()
            engine.run(_request(), "identity.not_a_capability", DIR)


class TestIdentityRedaction:
    def test_credential_keys(self) -> None:
        assert "password_hash" in IDENTITY_CREDENTIAL_KEYS
        assert "session_token" in IDENTITY_CREDENTIAL_KEYS
        assert "credentials" in IDENTITY_CREDENTIAL_KEYS

    def test_redact_identity_raw_strips_secrets(self) -> None:
        transport = MockIdentityTransport()
        raw = transport.inventory_identities(DIR)
        redacted = redact_identity_raw(raw)
        assert "demo-build-secret-hash-0000" not in redacted
        assert "demo-api-key-0000" not in redacted
        assert "REDACTED" in redacted

    def test_redacted_marker_is_stable_literal(self) -> None:
        assert credential_value_redacted() == "REDACTED"


class TestIdentityPipeline:
    def test_directory_discovery_pipeline(self) -> None:
        engine, evidence, world = _engine()
        result = engine.discover_directories(_request(scope=_demo_scope()), DIR)
        assert result.status == IdentityStatus.SUCCESS
        assert result.observation_count == 1
        assert len(result.evidence_ids) == 2
        entities = world.list_entities(WorldQuery(mission_id=MID, limit=1000))
        assert any(
            e.entity_type.value == "directory" and e.name == "aelionix-corp"
            for e in entities
        )

    def test_inventory_pipeline(self) -> None:
        engine, evidence, world = _engine()
        result = engine.inventory_identities(_request(scope=_demo_scope()), DIR)
        assert result.status == IdentityStatus.SUCCESS
        assert result.observation_count == 5
        assert len(result.evidence_ids) == 6
        stored = evidence.list(limit=1000)
        assert len(stored) == 6
        identities = {
            e.name for e in world.list_entities(WorldQuery(mission_id=MID, limit=1000))
            if e.entity_type.value == "identity"
        }
        assert {"alice", "bob", "build-service", "api-service", "web-server-01$"} <= identities

    def test_membership_pipeline_world_edge(self) -> None:
        from blackforge.world_model.query import RelationshipQuery

        engine, _, world = _engine()
        engine.inventory_identities(_request(scope=_demo_scope()), DIR)
        result = engine.observe_membership(
            _request(scope=_demo_scope(), identity="alice"), DIR
        )
        assert result.status == IdentityStatus.PARTIAL
        assert len(result.observations) == 1
        relationships = world.list_relationships(
            RelationshipQuery(mission_id=MID, limit=1000)
        )
        assert any(
            r.relationship_type.value == "member_of"
            for r in relationships
        )

    def test_role_assignment_pipeline(self) -> None:
        from blackforge.world_model.query import RelationshipQuery

        engine, evidence, world = _engine()
        result = engine.observe_role_assignment(
            _request(scope=_demo_scope(), identity="bob"), DIR
        )
        assert result.status == IdentityStatus.SUCCESS
        assert [o.role for o in result.observations] == ["deployment-operator"]
        relationships = world.list_relationships(
            RelationshipQuery(mission_id=MID, limit=1000)
        )
        assert any(
            r.relationship_type.value == "has_role"
            for r in relationships
        )

    def test_metadata_contradiction_surfaces(self) -> None:
        world = WorldModelStore(repository=InMemoryWorldRepository())
        materializer = IdentityWorldMaterializer(world)
        transport = MockIdentityTransport()
        adapter = adapter_for_tool("observe_metadata")
        output = adapter.adapt(
            transport.observe_metadata(DIR, identity="alice"),
            context={"target": DIR},
        )
        report: IdentityMaterializeReport = materializer.materialize(
            MID,
            [(o, f"ev_{i}", Confidence.HIGH) for i, o in enumerate(output.observations)],
            session_id=SID,
        )
        assert report.assertions_contradicted == 1
        alice = next(
            e for e in world.list_entities(WorldQuery(mission_id=MID, limit=1000))
            if e.name == "alice"
        )
        assertions = world.list_assertions(entity_id=alice.id)
        values = {(a.property_key, a.property_value) for a in assertions}
        assert ("department", "engineering") in values
        assert ("department", "sales") in values

    def test_relationship_pipeline_vocabulary(self) -> None:
        engine, _, world = _engine()
        result = engine.analyze_relationships(
            _request(scope=_demo_scope(), identity="alice"), DIR
        )
        assert result.status == IdentityStatus.SUCCESS
        assert result.observation_count == 4
        kinds = {o.relationship_type for o in result.observations}
        assert kinds == {"member_of", "has_role", "has_permission", "applies_to"}


class TestIdentityStatusMapping:
    def test_error_directories_map_to_statuses(self) -> None:
        engine, _, world = _engine()
        request = _request(scope=_demo_scope())
        for directory, status in ERROR_DIRS.items():
            result = engine.inventory_identities(request, directory)
            assert result.status == status, directory
            assert result.error is not None

    def test_unknown_identity_maps_to_no_evidence(self) -> None:
        engine, _, _ = _engine()
        result = engine.observe_membership(
            _request(scope=_demo_scope(), identity="ghost-identity"), DIR
        )
        assert result.status == IdentityStatus.NO_EVIDENCE
        assert "identity not present" in (result.error or "")

    def test_identity_level_without_identity_requires_target(self) -> None:
        engine, _, _ = _engine()
        result = engine.observe_membership(_request(scope=_demo_scope()), DIR)
        assert result.status == IdentityStatus.UNSUPPORTED_DIRECTORY

    def test_unresolved_metadata_yields_partial(self) -> None:
        engine, _, _ = _engine()
        result = engine.observe_metadata(
            _request(scope=_demo_scope(), identity="api-service"), DIR
        )
        assert result.status == IdentityStatus.PARTIAL
        assert any("manager" in w for w in result.warnings)


class TestIdentityEvidence:
    def test_artifact_evidence_redacted(self) -> None:
        engine, evidence, _ = _engine()
        engine.inventory_identities(_request(scope=_demo_scope()), DIR)
        artifacts = [
            e for e in evidence.list(limit=1000)
            if e.evidence_type.value == "artifact"
        ]
        assert artifacts
        payload = json.dumps(json.loads(artifacts[0].raw_data))
        assert "demo-build-secret-hash-0000" not in payload
        assert "demo-api-key-0000" not in payload
        assert "REDACTED" in payload

    def test_observation_evidence_never_carries_secrets(self) -> None:
        engine, evidence, _ = _engine()
        engine.inventory_identities(_request(scope=_demo_scope()), DIR)
        observations = [
            e for e in evidence.list(limit=1000)
            if e.evidence_type.value == "observation"
        ]
        for entry in observations:
            assert "demo-build-secret-hash-0000" not in entry.raw_data
            assert "demo-api-key-0000" not in entry.raw_data

    def test_mode_embedded_in_artifact_payload(self) -> None:
        engine, evidence, _ = _engine()
        engine.inventory_identities(_request(scope=_demo_scope()), DIR)
        artifacts = [
            e for e in evidence.list(limit=1000)
            if e.evidence_type.value == "artifact"
        ]
        payload = json.loads(artifacts[0].raw_data)
        assert payload.get("mode") == IdentityMode.CONTROLLED.value

    def test_observation_confidence_policy(self) -> None:
        assert observation_confidence(
            IdentityObservation(identity="alice", directory="aelionix-corp"),
            IdentityMode.CONTROLLED,
        ) == Confidence.HIGH
        assert observation_confidence(
            IdentityObservation(identity="alice", directory="aelionix-corp"),
            IdentityMode.PASSIVE,
        ) == Confidence.LOW
        assert observation_confidence(
            RelationshipObservation(
                relationship_type="member_of",
                source="alice",
                target="engineering",
                directory="aelionix-corp",
            ),
            IdentityMode.CONTROLLED,
        ) == Confidence.MEDIUM
        assert observation_confidence(
            MetadataObservation(
                identity="alice",
                attribute_key="department",
                attribute_value="sales",
                source="secondary_hr_feed",
                directory="aelionix-corp",
            ),
            IdentityMode.CONTROLLED,
        ) == Confidence.MEDIUM


class TestIdentityDedup:
    def test_repeat_run_does_not_duplicate_evidence(self) -> None:
        engine, evidence, _ = _engine()
        request = _request(scope=_demo_scope())
        engine.inventory_identities(request, DIR)
        engine.inventory_identities(request, DIR)
        assert len(evidence.list(limit=1000)) == 6

    def test_passive_and_controlled_records_do_not_collide(self) -> None:
        engine, evidence, _ = _engine()
        request = _request(scope=_demo_scope())
        engine.inventory_identities(request, DIR)
        passive = _request(scope=_demo_scope(), mode=IdentityMode.PASSIVE)
        engine.inventory_identities(passive, DIR)
        assert len(evidence.list(limit=1000)) == 12

    def test_dedup_maps_reference(self) -> None:
        engine, evidence, _ = _engine()
        request = _request(scope=_demo_scope())
        first = engine.observe_membership(request, DIR, identity="alice")
        existing = existing_evidence_id(
            evidence,
            observation_evidence(
                MID, DIR, "identity.membership_observation",
                first.observations[0],
            ),
        )
        assert existing is not None
        assert existing == first.evidence_ids[1]


class TestIdentityAuthorization:
    def test_denied_target_raises(self) -> None:
        engine, _, _ = _engine()
        request = _request(scope=_scope(allowed_targets=[DIR]))
        with pytest.raises(AuthorizationError):
            engine.inventory_identities(request, "OTHER-CORP")

    def test_unsupported_target_type_raises(self) -> None:
        engine, _, _ = _engine()
        request = _request(scope=_demo_scope())
        with pytest.raises(IdentityExecutionError):
            engine.inventory_identities(request, "192.0.2.10")

    def test_denied_capability_requires_authorized_target(self) -> None:
        engine, _, _ = _engine()
        request = _request(scope=_demo_scope())
        result = engine.discover_directories(request, DNS)
        assert result.authorized is True


class TestIdentityMemoryIntegration:
    def test_memory_records_created_through_bridge(self) -> None:
        from blackforge.memory.repository import InMemoryRepository
        from blackforge.runtime.bootstrap import bootstrap

        app = bootstrap(
            memory_backend=InMemoryRepository(),
            evidence_backend=InMemoryEvidenceRepository(),
            world_model_backend=InMemoryWorldRepository(),
        )
        result = app.identity_engine.inventory_identities(
            _request(scope=_scope(allowed_targets=[DIR])),
            DIR,
        )
        assert result.status == IdentityStatus.SUCCESS
        assert app.memory.count() >= 5
        assert app.verify()["identity_ready"] is True


class TestIdentitySqlitePersistence:
    def test_sqlite_persists_evidence_and_world(self, tmp_path) -> None:
        from blackforge.evidence.repository import SQLiteEvidenceRepository
        from blackforge.world_model.repository import SQLiteWorldRepository

        evidence = EvidenceStore(
            repository=SQLiteEvidenceRepository(str(tmp_path / "identity_ev.db"))
        )
        world = WorldModelStore(
            repository=SQLiteWorldRepository(str(tmp_path / "identity_wm.db"))
        )
        engine = IdentityEngine(
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        result = engine.inventory_identities(
            _request(scope=_demo_scope()), DIR
        )
        assert result.observation_count == 5
        assert len(evidence.list(limit=1000)) == 6
        entities = world.list_entities(WorldQuery(mission_id=MID, limit=1000))
        assert len(entities) >= 6


class TestIdentityPackageAssembly:
    def test_module_exports(self) -> None:
        import blackforge.identity as identity

        assert identity.IdentityEngine is not None
        assert identity.MockIdentityTransport is not None
        assert identity.IdentityWorldMaterializer is not None
        assert identity.IdentityNormalizedOutput is not None
        for name in (
            "IdentityMode", "IdentityRequest", "IdentityResult",
            "IdentityStatus", "Observation", "IdentityToolAdapter",
        ):
            assert hasattr(identity, name), name

    def test_all_capabilities_present_in_engine(self) -> None:
        engine, _, _ = _engine()
        capabilities = {c.capability_id for c in engine.capabilities}
        assert capabilities == set(IDENTITY_CAPABILITY_IDS)
        assert len(capabilities) == 11

    def test_run_dispatcher(self) -> None:
        engine, _, _ = _engine()
        result = engine.run(
            _request(scope=_demo_scope(), identity="bob"),
            "identity.relationship_analysis",
            DIR,
        )
        assert result.capability_id == "identity.relationship_analysis"
        assert result.observation_count >= 1

    def test_coexists_with_all_engines(self, tmp_path) -> None:
        from blackforge.auth.capabilities import build_auth_capabilities

        evidence = EvidenceStore(repository=InMemoryEvidenceRepository())
        world = WorldModelStore(repository=InMemoryWorldRepository())
        registry = CapabilityRegistry()
        registry.register_defaults()
        builds = [
            build_recon_capabilities(),
            build_webapi_capabilities(),
            build_auth_capabilities(),
            build_business_logic_capabilities(),
            build_network_capabilities(),
            build_identity_capabilities(),
        ]
        for capability_set in builds:
            for cap in capability_set:
                registry.register(cap)
        IdentityEngine(
            capability_registry=registry,
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        NetworkEngine(
            capability_registry=registry,
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        domain_cap = (
            registry.list_capabilities()
            if isinstance(registry.list_capabilities()[0], str)
            else [c.name for c in registry.list_capabilities()]
        )
        assert len(domain_cap) == 61
        for cap in IDENTITY_CAPABILITY_IDS:
            assert registry.has(cap)
        for cap in ("network.host_discovery", "business_logic.workflow_discovery"):
            assert registry.has(cap)


class TestIdentitySafetyBoundaries:
    def test_relationship_vocabulary_is_structurally_bound(self) -> None:
        engine, _, _ = _engine()
        result = engine.analyze_relationships(
            _request(scope=_demo_scope(), identity="bob"), DIR
        )
        for observation in result.observations:
            assert observation.relationship_type in {
                "member_of", "has_role", "has_permission", "applies_to"
            }

    def test_no_generic_command_executor_methods(self) -> None:
        import inspect


        transport_methods = {
            name for name, _ in inspect.getmembers(
                MockIdentityTransport, predicate=inspect.isfunction
            )
            if not name.startswith("_") and not name.startswith("test_")
        }
        prohibited_prefixes = (
            "execute_", "run_command", "dump", "extract_hash",
            "dump_creds", "get_creds", "sync_", "enable_", "disable_",
            "reset_", "grant_", "revoke_", "impersonate",
        )
        for method in transport_methods:
            lowered = method.lower()
            assert not lowered.startswith(prohibited_prefixes), (
                f"unauthorized operation found on identity transport: {method}"
            )

    def test_no_credential_material_in_normalized_output(self) -> None:
        engine, evidence, _ = _engine()
        engine.inventory_identities(_request(scope=_demo_scope()), DIR)
        stored = evidence.list(limit=1000)
        observations = [
            e for e in stored if e.evidence_type.value == "observation"
        ]
        artifacts = [
            e for e in stored if e.evidence_type.value == "artifact"
        ]
        for entry in stored:
            for marker in (
                "demo-build-secret-hash-0000",
                "demo-session-token-0000",
                "demo-api-key-0000",
            ):
                assert marker not in entry.raw_data
        for entry in observations:
            assert "password_hash" not in entry.raw_data
            assert "session_token" not in entry.raw_data
            assert "credentials" not in entry.raw_data
        assert any(credential_value_redacted() in e.raw_data for e in artifacts)

