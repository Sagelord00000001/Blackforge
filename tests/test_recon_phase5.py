from __future__ import annotations

import json
import time

import pytest
from pydantic import TypeAdapter, ValidationError

from blackforge.authorization import AuthorizationBoundary
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import (
    AuthorizationError,
    ReconExecutionError,
    ReconNormalizationError,
    ReconTimeoutError,
)
from blackforge.core.types import (
    Confidence,
    EvidenceType,
    MissionID,
    RiskLevel,
    SessionID,
    TargetType,
)
from blackforge.evidence.models import EvidenceRelation
from blackforge.evidence.repository import (
    InMemoryEvidenceRepository,
    SQLiteEvidenceRepository,
)
from blackforge.evidence.store import EvidenceStore
from blackforge.recon.capabilities import (
    RECON_CAPABILITY_IDS,
    ReconCapability,
    build_recon_capabilities,
    build_recon_meta,
)
from blackforge.recon.engine import ReconEngine
from blackforge.recon.evidence import (
    observation_confidence,
    observation_evidence,
    observation_summary,
)
from blackforge.recon.mock import MockReconTool
from blackforge.recon.models import (
    DNSObservation,
    HostObservation,
    HTTPObservation,
    NetworkObservation,
    Observation,
    ReconMode,
    ReconRequest,
    ReconResult,
    ReconStatus,
    ServiceObservation,
    TechnologyObservation,
    TLSObservation,
)
from blackforge.recon.normalization import (
    DNSInspectionAdapter,
    HostDiscoveryAdapter,
    HTTPMetadataAdapter,
    ServiceDiscoveryAdapter,
    TechnologyIdentificationAdapter,
    TLSInspectionAdapter,
)
from blackforge.scope.models import Target, TargetScope
from blackforge.world_model.models import EntityType
from blackforge.world_model.query import RelationshipQuery
from blackforge.world_model.repository import (
    InMemoryWorldRepository,
    SQLiteWorldRepository,
)
from blackforge.world_model.store import WorldModelStore

MID = MissionID("mission_recon")
MID_OTHER = MissionID("mission_recon_other")
SID = SessionID("sess_recon")


def _scope(
    mission_id: MissionID = MID,
    *,
    max_risk_level: RiskLevel = RiskLevel.HIGH,
    allowed_capabilities: list[str] | None = None,
    allowed_targets: list[str] | None = None,
) -> TargetScope:
    from blackforge.scope.models import detect_target_type

    targets = (
        [
            Target(value=t, target_type=detect_target_type(t))
            for t in allowed_targets
        ]
        if allowed_targets is not None
        else [Target(value="example.com", target_type=TargetType.DOMAIN)]
    )
    return TargetScope(
        mission_id=str(mission_id),
        allowed_targets=targets,
        allowed_capabilities=allowed_capabilities or [],
        max_risk_level=max_risk_level,
    )


def _request(
    mission_id: MissionID = MID,
    *,
    mode: ReconMode = ReconMode.ACTIVE,
    scope: TargetScope | None = None,
    max_observations: int = 500,
    timeout_seconds: float = 30.0,
    session_id: SessionID | None = SID,
) -> ReconRequest:
    return ReconRequest(
        mission_id=mission_id,
        scope=scope or _scope(mission_id),
        session_id=session_id,
        mode=mode,
        max_observations=max_observations,
        timeout_seconds=timeout_seconds,
    )


REPO_FACTORIES = [
    pytest.param(("in_memory", "in_memory"), id="in_memory"),
    pytest.param(("sqlite", "sqlite"), id="sqlite"),
]


def _engine(
    tmp_path,
    *,
    pairs: tuple[str, str] = ("in_memory", "in_memory"),
    registry: CapabilityRegistry | None = None,
) -> tuple[ReconEngine, EvidenceStore, WorldModelStore]:
    evidence_kind, world_kind = pairs
    if evidence_kind == "sqlite":
        evidence_store = EvidenceStore(
            repository=SQLiteEvidenceRepository(str(tmp_path / "ev.db"))
        )
    else:
        evidence_store = EvidenceStore(repository=InMemoryEvidenceRepository())
    if world_kind == "sqlite":
        world = WorldModelStore(
            repository=SQLiteWorldRepository(str(tmp_path / "wm.db"))
        )
    else:
        world = WorldModelStore(repository=InMemoryWorldRepository())
    engine = ReconEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class TestReconModels:
    def test_mode_enum(self) -> None:
        assert ReconMode.PASSIVE.value == "passive"
        assert ReconMode.ACTIVE.value == "active"

    def test_observation_union_discrimination(self) -> None:
        adapter = TypeAdapter(Observation)
        service = ServiceObservation(
            host="web.example.com", port=443, protocol="tcp", service="https"
        )
        assert adapter.validate_python(service.model_dump()).kind == "service"
        tls = TLSObservation(
            host="web.example.com",
            port=443,
            certificate_subject="CN=web.example.com",
            certificate_issuer="CN=CA",
            not_before="2024-01-01",
            not_after="2026-01-01",
            tls_version="TLSv1.3",
            cipher="TLS_AES_128_GCM_SHA256",
        )
        assert adapter.validate_python(tls.model_dump()).kind == "tls"
        network = NetworkObservation(cidr="192.0.2.0/24", hosts=["a", "b"])
        assert adapter.validate_python(network.model_dump()).kind == "network"

    def test_request_validation(self) -> None:
        req = _request()
        assert req.mode == ReconMode.ACTIVE
        assert req.max_observations == 500
        assert req.timeout_seconds == 30.0
        with pytest.raises(ValidationError):
            ReconRequest(
                mission_id=MID,
                scope=_scope(),
                max_observations=0,
            )
        with pytest.raises(ValidationError):
            ReconRequest(
                mission_id=MID,
                scope=_scope(),
                timeout_seconds=0,
            )

    def test_result_observation_count(self) -> None:
        result = ReconResult(
            mission_id=MID,
            session_id=SID,
            target="web.example.com",
            capability_id="recon.dns",
            mode=ReconMode.PASSIVE,
            observations=[
                DNSObservation(host="web.example.com", record_type="A", answers=["192.0.2.10"])
            ],
        )
        assert result.observation_count == 1
        assert result.status == ReconStatus.SUCCESS


# --------------------------------------------------------------------------- #
# Capability metadata & registration
# --------------------------------------------------------------------------- #
class TestReconCapabilities:
    def test_exactly_six_recon_capabilities(self) -> None:
        metas = build_recon_meta()
        assert len(metas) == 6
        assert [m.name for m in metas] == RECON_CAPABILITY_IDS
        assert len(set(RECON_CAPABILITY_IDS)) == 6

    def test_metadata_fields(self) -> None:
        by_name = {m.name: m for m in build_recon_meta()}
        dns = by_name["recon.dns"]
        assert dns.risk_level == RiskLevel.LOW
        assert dns.mode == ReconMode.PASSIVE
        assert dns.category == "reconnaissance"
        assert dns.world_model is True
        assert dns.authorization_required is True
        assert TargetType.DOMAIN in dns.supported_target_types
        assert [p.value for p in dns.produces] == ["dns"]

        service = by_name["recon.service_discovery"]
        assert service.risk_level == RiskLevel.MEDIUM
        assert service.mode == ReconMode.ACTIVE
        assert set(p.value for p in service.produces) == {"port", "service"}

    def test_modes_by_capability(self) -> None:
        metas = {m.name: m for m in build_recon_meta()}
        expected_defaults = {
            "recon.host_discovery": ReconMode.ACTIVE,
            "recon.service_discovery": ReconMode.ACTIVE,
            "recon.technology_identification": ReconMode.PASSIVE,
            "recon.dns": ReconMode.PASSIVE,
            "recon.http_metadata": ReconMode.ACTIVE,
            "recon.tls_metadata": ReconMode.PASSIVE,
        }
        for name, mode in expected_defaults.items():
            assert metas[name].mode == mode, name

    def test_license_and_package_metadata(self) -> None:
        project = {}
        section = None
        with open("pyproject.toml", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("[") and "]" in line:
                    section = line.strip().strip("[]")
                    continue
                if section == "project" and "=" in line and not line.lstrip().startswith("#"):
                    key, _, value = line.partition("=")
                    project[key.strip()] = value.strip().strip('"')
        assert project.get("license", "").lower() == "mit"
        assert "blackforge" in project.get("name", "")
        for meta in build_recon_meta():
            assert meta.name
            assert meta.description
            assert meta.version == "1.0.0"
            assert meta.input_schema and meta.output_schema
            assert meta.evidence_types_produced == ["artifact", "observation"]

    def test_recon_capability_executes_typed(self, tmp_path) -> None:
        cap = build_recon_capabilities()[1]
        assert isinstance(cap, ReconCapability)
        assert cap.capability_id == "recon.service_discovery"
        result = cap.execute("web.example.com")
        assert result.success is True
        raw = result.output
        assert isinstance(raw, list) and len(raw) == 3
        assert all(o["kind"] in ("port", "service") for o in raw)
        assert result.metadata["mock"] is True

    def test_engine_registers_without_clobbering_defaults(self, tmp_path) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        engine, _, _ = _engine(tmp_path, registry=registry)
        assert registry.has("mock_discovery")
        assert len(registry.list_capabilities()) == 7
        engine2, _, _ = _engine(tmp_path, registry=registry)
        assert registry.has("mock_discovery")
        assert len(registry.list_capabilities()) == 7

    def test_engine_exposes_all_recon_capabilities(self, tmp_path) -> None:
        engine, _, _ = _engine(tmp_path)
        assert len(engine.capabilities) == 6
        assert all(engine.has_capability(c) for c in RECON_CAPABILITY_IDS)

    @pytest.mark.parametrize("pairs", REPO_FACTORIES)
    def test_register_into_existing_registry(self, tmp_path, pairs) -> None:
        registry = CapabilityRegistry()
        engine, _, _ = _engine(tmp_path, pairs=pairs, registry=registry)
        assert registry.get("recon.host_discovery").meta().name == "recon.host_discovery"


# --------------------------------------------------------------------------- #
# Mock tool
# --------------------------------------------------------------------------- #
class TestMockReconTool:
    def test_demo_host_deterministic(self) -> None:
        tool = MockReconTool()
        first = tool.enumerate_services("web.example.com")
        second = MockReconTool().enumerate_services("web.example.com")
        assert first == second

    def test_fallback_is_stable(self) -> None:
        tool = MockReconTool()
        a = tool.enumerate_services("fictional-sub.example.com")
        b = tool.enumerate_services("fictional-sub.example.com")
        c = MockReconTool().enumerate_services("fictional-sub.example.com")
        assert a == b == c
        ip = json.loads(b)["host"]
        assert ip != "web.example.com"

    def test_public_test_ranges_used(self) -> None:
        tool = MockReconTool()
        for host in (
            "web.example.com",
            "mail.example.com",
            "db.example.com",
            "fictional-sub.example.com",
        ):
            doc = json.loads(tool.discover_hosts(host))
            for entry in doc["hosts"]:
                ip = entry["ip_addresses"][0]
                assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip

    def test_passive_mode_adds_networks(self) -> None:
        doc = json.loads(
            MockReconTool().discover_hosts("web.example.com", mode=ReconMode.PASSIVE)
        )
        assert doc["networks"] and doc["networks"][0]["cidr"] == "192.0.2.0/24"
        active = json.loads(
            MockReconTool().discover_hosts("web.example.com", mode=ReconMode.ACTIVE)
        )
        assert active["networks"] == []

    def test_passive_enumerate_marks_inferred(self) -> None:
        doc = json.loads(
            MockReconTool().enumerate_services("web.example.com", mode=ReconMode.PASSIVE)
        )
        assert all(s["state"] == "inferred" for s in doc["services"])


# --------------------------------------------------------------------------- #
# Normalization adapters
# --------------------------------------------------------------------------- #
class TestNormalizationAdapters:
    def test_host_discovery(self) -> None:
        raw = MockReconTool().discover_hosts("web.example.com")
        out = HostDiscoveryAdapter().adapt(raw)
        assert len(out.observations) == 3
        hosts = [o for o in out.observations if isinstance(o, HostObservation)]
        assert {h.host for h in hosts} >= {"web.example.com", "www.example.com", "api.example.com"}
        assert all(h.ip_addresses for h in hosts)

    def test_service_discovery(self) -> None:
        raw = MockReconTool().enumerate_services("web.example.com")
        out = ServiceDiscoveryAdapter().adapt(raw)
        services = [o for o in out.observations if isinstance(o, ServiceObservation)]
        assert [(s.port, s.protocol, s.service) for s in services] == [
            (22, "tcp", "ssh"),
            (80, "tcp", "http"),
            (443, "tcp", "https"),
        ]
        assert services[0].version == "OpenSSH_8.2p1"
        assert services[1].banner == "Apache/2.4.41 (Ubuntu)"

    def test_technology_identification_lowercases(self) -> None:
        raw = MockReconTool().identify_technologies("web.example.com")
        out = TechnologyIdentificationAdapter().adapt(raw)
        techs = [o for o in out.observations if isinstance(o, TechnologyObservation)]
        names = {t.technology for t in techs}
        assert names == {"nginx", "php", "jquery"}
        assert all(t.category == t.category.lower() for t in techs)

    def test_dns_inspection(self) -> None:
        raw = MockReconTool().inspect_dns("web.example.com")
        out = DNSInspectionAdapter().adapt(raw)
        records = {(o.record_type, tuple(o.answers)) for o in out.observations}
        assert ("A", ("192.0.2.10",)) in records
        assert ("AAAA", ("2001:db8::10",)) in records

    def test_http_metadata(self) -> None:
        raw = MockReconTool().inspect_http_metadata("web.example.com")
        out = HTTPMetadataAdapter().adapt(raw)
        assert len(out.observations) == 1
        http = out.observations[0]
        assert isinstance(http, HTTPObservation)
        assert http.url == "https://web.example.com/"
        assert http.status_code == 200
        assert http.server_header == "nginx/1.24.0"
        assert http.title == "Example Web Server"
        assert http.headers["Server"] == "nginx/1.24.0"

    def test_tls_inspection(self) -> None:
        raw = MockReconTool().inspect_tls("web.example.com")
        out = TLSInspectionAdapter().adapt(raw)
        assert len(out.observations) == 1
        tls = out.observations[0]
        assert isinstance(tls, TLSObservation)
        assert tls.host == "web.example.com"
        assert tls.port == 443
        assert "web.example.com" in tls.certificate_subject

    def test_no_http_returns_warning(self) -> None:
        raw = MockReconTool().inspect_http_metadata("mail.example.com")
        out = HTTPMetadataAdapter().adapt(raw)
        assert out.observations == []
        assert out.warnings and "no HTTP endpoint" in out.warnings[0]

    def test_discards_invalid_entries(self) -> None:
        raw = {
            "tool": "enumerate_services",
            "host": "web.example.com",
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https"},
                {"port": 99999, "protocol": "tcp", "service": "weird"},
                {"port": "80", "protocol": "tcp", "service": "http"},
                "not-an-object",
            ],
        }
        out = ServiceDiscoveryAdapter().adapt(raw)
        assert len(out.observations) == 1
        assert len(out.warnings) == 3
        assert all("discarded" in w for w in out.warnings)

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(ReconNormalizationError, match="malformed JSON"):
            HostDiscoveryAdapter().adapt("{not json")

    def test_non_document_raises(self) -> None:
        with pytest.raises(ReconNormalizationError, match="not a parseable"):
            ServiceDiscoveryAdapter().adapt(42)

    def test_missing_required_field_discards(self) -> None:
        raw = {
            "tool": "inspect_dns",
            "host": "web.example.com",
            "records": [
                {"type": "A", "answers": ["192.0.2.10"]},
                {"type": "", "answers": ["bad"]},
                {"type": "MX", "answers": []},
            ],
        }
        out = DNSInspectionAdapter().adapt(raw)
        assert len(out.observations) == 2
        assert len(out.warnings) == 1

    def test_duplicate_entries_preserved_by_adapter(self) -> None:
        raw = {
            "tool": "inspect_dns",
            "host": "web.example.com",
            "records": [
                {"type": "A", "answers": ["192.0.2.10"]},
                {"type": "A", "answers": ["192.0.2.10"]},
            ],
        }
        out = DNSInspectionAdapter().adapt(raw)
        assert len(out.observations) == 2


# --------------------------------------------------------------------------- #
# Confidence & evidence helpers
# --------------------------------------------------------------------------- #
class TestConfidencePolicy:
    def test_active_direct_kinds_high(self) -> None:
        service = ServiceObservation(host="h", port=443, protocol="tcp", service="https")
        assert observation_confidence(service, ReconMode.ACTIVE) == Confidence.HIGH
        assert observation_confidence(service, ReconMode.PASSIVE) == Confidence.LOW

    def test_technology_medium(self) -> None:
        tech = TechnologyObservation(host="h", technology="nginx")
        assert observation_confidence(tech, ReconMode.ACTIVE) == Confidence.MEDIUM
        assert observation_confidence(tech, ReconMode.PASSIVE) == Confidence.MEDIUM

    def test_dns_and_network_low(self) -> None:
        dns = DNSObservation(host="h", record_type="A", answers=["1.2.3.4"])
        assert observation_confidence(dns, ReconMode.ACTIVE) == Confidence.LOW
        net = NetworkObservation(cidr="192.0.2.0/24")
        assert observation_confidence(net, ReconMode.PASSIVE) == Confidence.LOW

    def test_summary_and_evidence_construction(self) -> None:
        obs = ServiceObservation(
            host="web.example.com", port=443, protocol="tcp", service="https"
        )
        assert "443" in observation_summary(obs)
        evidence = observation_evidence(
            MID, "web.example.com", "recon.service_discovery", obs, mode=ReconMode.ACTIVE
        )
        assert evidence.evidence_type == EvidenceType.OBSERVATION
        assert evidence.confidence == Confidence.HIGH
        assert json.loads(evidence.raw_data)["kind"] == "service"
        assert evidence.reference == "web.example.com"


# --------------------------------------------------------------------------- #
# End-to-end engine (in-memory + SQLite)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pairs", REPO_FACTORIES)
class TestEnginePipeline:
    def test_discover_hosts_e2e(self, tmp_path, pairs) -> None:
        engine, evidence, world = _engine(tmp_path, pairs=pairs)
        result = engine.discover_hosts(_request(), "web.example.com")
        assert result.status == ReconStatus.SUCCESS
        assert result.authorized is True
        assert result.capability_id == "recon.host_discovery"
        assert result.mode == ReconMode.ACTIVE
        hosts = [o for o in result.observations if isinstance(o, HostObservation)]
        assert len(hosts) == 3
        assert len(result.evidence_ids) == len(result.observations) + 1

        evidence_rows = len(evidence.repository.list(limit=10_000))
        assert evidence_rows == len(result.evidence_ids)

    def test_evidence_artifact_and_derived_from(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        result = engine.enumerate_services(_request(), "web.example.com")
        artifact_id = result.evidence_ids[0]
        artifact = evidence.get(artifact_id)
        assert artifact is not None
        assert artifact.evidence_type == EvidenceType.ARTIFACT
        assert json.loads(artifact.raw_data)["tool"] == "enumerate_services"
        assert artifact.provenance.capability_id == "recon.service_discovery"
        assert artifact.reference == "web.example.com"

        for obs_id in result.evidence_ids[1:]:
            record = evidence.get(obs_id)
            assert record.evidence_type == EvidenceType.OBSERVATION
            rels = evidence.get_relationships(obs_id)
            derived = [r for r in rels if r.relation_type == EvidenceRelation.DERIVED_FROM]
            assert len(derived) == 1
            assert derived[0].target_id == str(artifact_id)

    def test_rerun_dedups_evidence(self, tmp_path, pairs) -> None:
        engine, evidence, world = _engine(tmp_path, pairs=pairs)
        first = engine.inspect_dns(_request(), "web.example.com")
        count_a = len(evidence.repository.list(limit=10_000))
        second = engine.inspect_dns(_request(), "web.example.com")
        count_b = len(evidence.repository.list(limit=10_000))
        assert count_a == count_b
        assert first.evidence_ids == second.evidence_ids
        assert world.count_entities(MID) == 2

    def test_mission_isolation(self, tmp_path, pairs) -> None:
        engine, evidence, world = _engine(tmp_path, pairs=pairs)
        engine.inspect_dns(_request(MID), "web.example.com")
        other_scope = _scope(MID_OTHER)
        engine.inspect_dns(_request(MID_OTHER, scope=other_scope), "web.example.com")
        other_evidence = [
            e for e in evidence.repository.list(limit=10_000) if e.mission_id == MID_OTHER
        ]
        assert len(other_evidence) == 4
        assert world.count_entities(MID) == 2
        assert world.count_entities(MID_OTHER) == 2

    def test_world_model_mapping_service(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.enumerate_services(_request(), "web.example.com")
        asset = world.find_entity(MID, EntityType.ASSET, "web.example.com")
        assert asset is not None
        service = world.find_entity(MID, EntityType.SERVICE, "443/tcp", namespace="web.example.com")
        assert service is not None
        assert service.properties["service"] == "https"
        rels = world.list_relationships(
            RelationshipQuery(
                mission_id=MID, limit=100
            )
        )
        exposes = [
            r
            for r in rels
            if getattr(r.relationship_type, "value", r.relationship_type) == "exposes"
        ]
        assert len(exposes) == 3

    def test_world_model_mapping_http_and_tls(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.inspect_http_metadata(_request(), "web.example.com")
        engine.inspect_tls(_request(), "web.example.com")
        endpoint = world.find_entity(
            MID, EntityType.ENDPOINT, "https://web.example.com/"
        )
        assert endpoint is not None
        assert endpoint.properties["status_code"] == 200
        tls_endpoint = world.find_entity(
            MID, EntityType.ENDPOINT, "https://web.example.com:443/", namespace="tls"
        )
        assert tls_endpoint is not None
        assert tls_endpoint.properties["tls_version"] == "TLSv1.3"

    def test_world_model_dedup_corroboration(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.enumerate_services(_request(), "web.example.com")
        entity_count_a = world.count_entities(MID)
        rel_count_a = len(
            world.list_relationships(RelationshipQuery(mission_id=MID, limit=100))
        )
        engine.enumerate_services(_request(), "web.example.com")
        assert world.count_entities(MID) == entity_count_a
        assert (
            len(world.list_relationships(RelationshipQuery(mission_id=MID, limit=100)))
            == rel_count_a
        )

    def test_partial_status_when_warnings(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.inspect_http_metadata(_request(), "mail.example.com")
        assert result.status == ReconStatus.PARTIAL
        assert result.observations == []
        assert result.warnings
        assert result.raw_output is not None

    def test_limited_truncation(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        request = _request(max_observations=1)
        result = engine.discover_hosts(request, "web.example.com")
        assert result.status == ReconStatus.LIMITED
        assert len(result.observations) == 1
        assert any("limit" in w for w in result.warnings)

    def test_dispatcher_run(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.run(_request(), "recon.dns", "web.example.com")
        assert result.capability_id == "recon.dns"
        assert result.status == ReconStatus.SUCCESS
        assert {o.record_type for o in result.observations} >= {"A", "AAAA"}

    def test_unknown_capability_via_engine(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(ReconExecutionError, match="unknown reconnaissance capability"):
            engine.run(_request(), "recon.not_real", "web.example.com")

    def test_target_type_mismatch(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(ReconExecutionError, match="does not support target"):
            engine.enumerate_services(_request(), "https://web.example.com/")

    def test_cidr_target_host_discovery(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        scope = _scope(allowed_targets=["192.0.2.0/24"])
        database = engine.discover_hosts(_request(scope=scope), "192.0.2.10")
        assert database.status in (ReconStatus.SUCCESS, ReconStatus.PARTIAL)

    def test_passive_mode_state(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        result = engine.enumerate_services(_request(), "web.example.com", mode=ReconMode.PASSIVE)
        services = [o for o in result.observations if isinstance(o, ServiceObservation)]
        assert all(s.state == "inferred" for s in services)
        assert all(
            evidence.get(e).confidence == Confidence.LOW for e in result.evidence_ids[1:]
        )

    def test_authorization_denied_out_of_scope(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        scope = _scope(allowed_targets=["other.example.com"])
        with pytest.raises(AuthorizationError, match="not authorized"):
            engine.inspect_tls(_request(scope=scope), "web.example.com")

    def test_authorization_denied_capability(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        scope = _scope(allowed_capabilities=["recon.dns"])
        with pytest.raises(AuthorizationError, match="not authorized"):
            engine.inspect_tls(_request(scope=scope), "web.example.com")

    def test_malformed_tool_output_raises(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        engine._tool.enumerate_services = lambda target, mode: "{not json"
        with pytest.raises(ReconNormalizationError, match="malformed JSON"):
            engine.enumerate_services(_request(), "web.example.com")

    def test_timeout_raises(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        original = engine._tool.discover_hosts

        def slow(target, mode):
            time.sleep(0.05)
            return original(target, mode=mode)

        engine._tool.discover_hosts = slow
        with pytest.raises(ReconTimeoutError, match="timed out"):
            engine.discover_hosts(_request(timeout_seconds=0.001), "web.example.com")

    def test_sqlite_persistence(self, tmp_path, pairs) -> None:
        if pairs[0] != "sqlite":
            pytest.skip("sqlite pair only")
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        engine.inspect_dns(_request(), "web.example.com")
        engine.evidence_store.close()
        engine.world_model.close()
        fresh = ReconEngine(
            evidence_store=EvidenceStore(
                repository=SQLiteEvidenceRepository(str(tmp_path / "ev.db"))
            ),
            world_model=WorldModelStore(
                repository=SQLiteWorldRepository(str(tmp_path / "wm.db"))
            ),
            authorization=AuthorizationBoundary(mode="strict"),
        )
        assert fresh.evidence_store.count(MID) == 4
        assert fresh.world_model.count_entities(MID) == 2


# --------------------------------------------------------------------------- #
# Unauthorized/dispatcher safety & security surface
# --------------------------------------------------------------------------- #
class TestEngineSafety:
    def test_no_generic_shell_executor(self) -> None:
        assert not hasattr(ReconEngine, "execute_command")
        assert not hasattr(ReconEngine, "shell")
        assert not hasattr(ReconEngine, "run_command")

    def test_recon_package_has_no_network_dependencies(self) -> None:
        import os

        for root, _dirs, files in os.walk("blackforge/recon"):
            for name in files:
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    text = fh.read()
                for banned in (
                    "os.system",
                    "subprocess",
                    "socket",
                    "requests.",
                    "urllib.request",
                    "http.client",
                    "eval(",
                    "exec(",
                    "pickle",
                ):
                    assert banned not in text, (name, banned)

    def test_recon_engine_executes_only_typed_methods(self) -> None:
        for method in (
            "discover_hosts",
            "enumerate_services",
            "identify_technologies",
            "inspect_dns",
            "inspect_http_metadata",
            "inspect_tls",
        ):
            assert callable(getattr(ReconEngine, method))

    def test_original_capability_registry_unmodified(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        assert len(registry.list_capabilities()) == 1


# --------------------------------------------------------------------------- #
# License & module assembly
# --------------------------------------------------------------------------- #
class TestReconPackageAssembly:
    def test_import_surface(self) -> None:
        from blackforge import recon

        assert recon.ReconEngine is ReconEngine
        assert recon.MockReconTool is MockReconTool
        assert recon.HostObservation is HostObservation

    def test_materializer_import_and_report(self, tmp_path) -> None:
        from blackforge.recon.materializer import MaterializeReport

        report = MaterializeReport()
        assert report.relationships_created == 0
        assert report.entities_created == 0
        assert report.entities_updated == 0
