from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from blackforge.authorization import AuthorizationBoundary
from blackforge.business_logic.capabilities import (
    build_business_logic_capabilities,
)
from blackforge.business_logic.engine import BusinessLogicEngine
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import AuthorizationError, NetworkExecutionError
from blackforge.core.types import (
    Confidence,
    EvidenceStatus,
    EvidenceType,
    ProvenanceType,
    RiskLevel,
    TargetType,
)
from blackforge.evidence.repository import InMemoryEvidenceRepository
from blackforge.evidence.store import EvidenceStore
from blackforge.network.capabilities import (
    NETWORK_CAPABILITY_IDS,
    build_network_capabilities,
    build_network_meta,
)
from blackforge.network.engine import METHOD_TO_CAPABILITY, NetworkEngine
from blackforge.network.evidence import (
    artifact_evidence,
    evidence_dedup_key_for,
    existing_evidence_id,
    observation_confidence,
    observation_evidence,
    observation_reference,
    observation_summary,
)
from blackforge.network.models import (
    DnsObservation,
    ExposureObservation,
    HostObservation,
    NetworkMode,
    NetworkObservationKind,
    NetworkRequest,
    NetworkResult,
    NetworkStatus,
    PortObservation,
    PortState,
)
from blackforge.network.normalization import (
    NetworkNormalizedOutput,
    adapter_for_tool,
)
from blackforge.network.redaction import (
    credential_value_redacted,
    redact_banner_text,
    redact_credential_fields,
)
from blackforge.network.transport import MockNetworkTransport
from blackforge.recon.capabilities import build_recon_capabilities
from blackforge.scope.models import Target, TargetScope, detect_target_type
from blackforge.webapi.capabilities import build_webapi_capabilities
from blackforge.world_model.query import RelationshipQuery, WorldQuery
from blackforge.world_model.repository import InMemoryWorldRepository
from blackforge.world_model.store import WorldModelStore

MID = "mission_net"
SID = "sess_net"

WEB = "192.0.2.10"
WEB_NAME = "web.internal.example"
API_NAME = "api.internal.example"

DEMO_TARGETS = [
    "192.0.2.0/24",
    WEB_NAME,
    API_NAME,
    "dns.internal.example",
    "mail.internal.example",
    "quiet.internal.example",
    "gateway.internal.example",
    "core-switch.internal.example",
    "firewall.internal.example",
]
for suffix in (
    "refused", "slow", "throttled", "filtered", "malformed",
    "unauthorized", "outofscope", "missing",
):
    DEMO_TARGETS.append(f"{suffix}.internal.example")

ERROR_TARGETS: dict[str, NetworkStatus] = {
    "refused.internal.example": NetworkStatus.REQUEST_FAILED,
    "slow.internal.example": NetworkStatus.TIMEOUT,
    "throttled.internal.example": NetworkStatus.RATE_LIMITED,
    "filtered.internal.example": NetworkStatus.FILTERED,
    "malformed.internal.example": NetworkStatus.MALFORMED_RESPONSE,
    "unauthorized.internal.example": NetworkStatus.UNAUTHORIZED,
    "outofscope.internal.example": NetworkStatus.REQUEST_FAILED,
    "missing.internal.example": NetworkStatus.REQUEST_FAILED,
}


def _scope(
    mission_id: str = MID,
    *,
    max_risk_level: RiskLevel = RiskLevel.HIGH,
    allowed_targets: list[str] | None = None,
) -> TargetScope:
    targets = (
        [Target(value=t, target_type=detect_target_type(t)) for t in allowed_targets]
        if allowed_targets is not None
        else [Target(value="internal.example", target_type=TargetType.DOMAIN)]
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
    mode: NetworkMode = NetworkMode.ACTIVE,
) -> NetworkRequest:
    return NetworkRequest(
        mission_id=mission_id,
        session_id=SID,
        scope=scope or _scope(),
        mode=mode,
        max_observations=500,
        timeout_seconds=30.0,
    )


def _demo_scope(mission_id: str = MID) -> TargetScope:
    return _scope(allowed_targets=DEMO_TARGETS, mission_id=mission_id)


def _engine(
    *,
    registry: CapabilityRegistry | None = None,
    use_stores: bool = True,
) -> tuple[NetworkEngine, EvidenceStore | None, WorldModelStore | None]:
    evidence_store = (
        EvidenceStore(repository=InMemoryEvidenceRepository()) if use_stores else None
    )
    world = (
        WorldModelStore(repository=InMemoryWorldRepository()) if use_stores else None
    )
    engine = NetworkEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


class TestNetworkModels:
    def test_mode_enum(self) -> None:
        assert NetworkMode.PASSIVE.value == "passive"
        assert NetworkMode.ACTIVE.value == "active"

    def test_status_enum(self) -> None:
        expected = {
            "success", "partial", "limited", "no_evidence", "request_failed",
            "rate_limited", "unauthorized", "out_of_scope",
            "malformed_response", "timeout", "filtered", "failed",
        }
        assert {s.value for s in NetworkStatus} == expected

    def test_port_state_enum(self) -> None:
        expected = {"open", "closed", "filtered", "unknown"}
        assert {s.value for s in PortState} == expected

    def test_kind_enum(self) -> None:
        expected = {
            "host", "port", "service", "protocol", "banner", "dns", "tls",
            "exposure", "infrastructure", "service_application",
            "network_evidence",
        }
        assert {k.value for k in NetworkObservationKind} == expected

    def test_observation_discriminated_union(self) -> None:
        port = PortObservation(
            kind="port", host=WEB_NAME, ip=WEB, port=443, state=PortState.OPEN
        )
        assert port.state == PortState.OPEN

    def test_request_validation(self) -> None:
        with pytest.raises(ValidationError):
            NetworkRequest(mission_id=MID, scope=_scope(), max_observations=0)
        with pytest.raises(ValidationError):
            NetworkRequest(mission_id=MID, scope=_scope(), max_observations=10_001)
        with pytest.raises(ValidationError):
            NetworkRequest(mission_id=MID, scope=_scope(), timeout_seconds=0)

    def test_result_observation_count(self) -> None:
        result = NetworkResult(
            mission_id=MID,
            session_id=SID,
            target=WEB_NAME,
            capability_id="network.port_discovery",
            mode=NetworkMode.ACTIVE,
            observations=[
                PortObservation(
                    kind="port", host=WEB_NAME, ip=WEB, port=443,
                    state=PortState.OPEN,
                )
            ],
        )
        assert result.observation_count == 1


class TestMockNetworkTransport:
    def test_transport_is_deterministic(self) -> None:
        transport = MockNetworkTransport()
        first = transport.observe_banners(WEB_NAME, mode=NetworkMode.ACTIVE, ports=[80])
        second = transport.observe_banners(WEB_NAME, mode=NetworkMode.ACTIVE, ports=[80])
        assert first == second
        assert "HTTP/1.1 200 OK" in first

    def test_web_host_open_ports(self) -> None:
        transport = MockNetworkTransport()
        raw = transport.discover_ports(
            WEB_NAME, mode=NetworkMode.ACTIVE, ports=[22, 80, 443]
        )
        doc = json.loads(raw)
        assert [o["port"] for o in doc["observations"]] == [22, 80, 443]
        assert all(o["state"] == "open" for o in doc["observations"])

    def test_quiet_host_has_no_open_ports(self) -> None:
        transport = MockNetworkTransport()
        doc = json.loads(
            transport.discover_ports(
                "quiet.internal.example", mode=NetworkMode.ACTIVE
            )
        )
        assert doc["observations"] == []

    def test_cidr_host_discovery(self) -> None:
        transport = MockNetworkTransport()
        doc = json.loads(
            transport.discover_hosts("192.0.2.0/24", mode=NetworkMode.ACTIVE)
        )
        names = {o["host"] for o in doc["observations"]}
        assert names == {
            WEB_NAME,
            API_NAME,
            "dns.internal.example",
            "mail.internal.example",
            "quiet.internal.example",
        }

    def test_error_hosts_structured(self) -> None:
        transport = MockNetworkTransport()
        for host, status in ERROR_TARGETS.items():
            doc = json.loads(
                transport.discover_ports(
                    host, mode=NetworkMode.ACTIVE, ports=[22]
                )
            )
            error = doc["error"]
            assert error is not None, host
            assert "kind" in error
            if "filtered" in host:
                assert error["kind"] == "filtered"
            if status == NetworkStatus.MALFORMED_RESPONSE:
                assert error["kind"] == "malformed_response"

    def test_unknown_target_connection_refused(self) -> None:
        transport = MockNetworkTransport()
        doc = json.loads(
            transport.discover_ports("203.0.113.99", mode=NetworkMode.ACTIVE)
        )
        assert doc["error"]["kind"] == "connection_refused"


class TestNetworkRedaction:
    def test_credential_fields_recursive(self) -> None:
        redacted = redact_credential_fields(
            {
                "access_token": "abc",
                "credentials": {"api_password": "top-secret"},
                "user": "alice",
            }
        )
        assert redacted["access_token"] == credential_value_redacted()
        assert redacted["credentials"] == credential_value_redacted()
        assert redacted["user"] == "alice"

    def test_redact_json_banner(self) -> None:
        banner = (
            '{"service": "inventory_api", "access_token": "demo-token-123", '
            '"api_key": "demo-key-abc", "credentials": {"api_password": "top-secret"}}'
        )
        redacted = redact_banner_text(banner)
        assert "demo-token" not in redacted
        assert "demo-key" not in redacted
        assert "top-secret" not in redacted
        assert "inventory_api" in redacted

    def test_redact_banner_non_json_unchanged(self) -> None:
        banner = "SSH-2.0-OpenSSH_8.9"
        assert redact_banner_text(banner) == banner


class TestNetworkEvidenceAndConfidence:
    def test_confidence_policy(self) -> None:
        direct = PortObservation(
            kind="port", host=WEB_NAME, ip=WEB, port=443, state=PortState.OPEN
        )
        derived = ExposureObservation(
            kind="exposure", host=WEB_NAME, ip=WEB, interface="eth0", exposed=True
        )
        dns = DnsObservation(
            kind="dns", server="dns.internal.example", name=WEB_NAME,
            record_type="A", value=WEB,
        )
        assert observation_confidence(direct, NetworkMode.ACTIVE) == Confidence.HIGH
        assert observation_confidence(dns, NetworkMode.ACTIVE) == Confidence.HIGH
        assert observation_confidence(derived, NetworkMode.ACTIVE) == Confidence.MEDIUM
        assert observation_confidence(derived, NetworkMode.PASSIVE) == Confidence.LOW
        assert observation_confidence(direct, NetworkMode.PASSIVE) == Confidence.LOW

    def test_observation_summary_and_reference(self) -> None:
        host = HostObservation(
            kind="host", host=WEB_NAME, ip=WEB, role="web_server"
        )
        assert observation_summary(host).startswith("Host")
        assert observation_reference(host) == WEB_NAME
        dns = DnsObservation(
            kind="dns", server="dns.internal.example", name=WEB_NAME,
            record_type="A", value=WEB,
        )
        assert observation_reference(dns) == "dns.internal.example"

    def test_artifact_evidence_shape(self) -> None:
        artifact = artifact_evidence(
            MID, WEB_NAME, "network.port_discovery", '{"x":1}'
        )
        assert artifact.evidence_type == EvidenceType.ARTIFACT
        assert artifact.status == EvidenceStatus.OBSERVED
        assert artifact.provenance.provenance_type == ProvenanceType.DIRECT
        assert artifact.confidence == Confidence.HIGH

    def test_observation_evidence_status_is_observed(self) -> None:
        obs = PortObservation(
            kind="port", host=WEB_NAME, ip=WEB, port=443, state=PortState.OPEN
        )
        evidence = observation_evidence(
            MID, WEB_NAME, "network.port_discovery", obs
        )
        assert evidence.status == EvidenceStatus.OBSERVED
        assert evidence.evidence_type == EvidenceType.OBSERVATION

    def test_evidence_dedup_key_stable(self) -> None:
        engine, _, _ = _engine()
        result = engine.discover_ports(
            _request(scope=_demo_scope()), WEB_NAME, ports=[443]
        )
        evidence = observation_evidence(
            MID, WEB_NAME, "network.port_discovery", result.observations[0]
        )
        assert evidence_dedup_key_for(evidence) == evidence_dedup_key_for(evidence)


class TestNetworkNormalization:
    @pytest.mark.parametrize(
        "tool",
        [
            "discover_hosts",
            "discover_ports",
            "observe_services",
            "identify_protocols",
            "observe_banners",
            "observe_dns",
            "observe_tls",
            "analyze_exposure",
            "model_infrastructure",
            "correlate_service_applications",
            "collect_network_evidence",
        ],
    )
    def test_adapter_registered(self, tool: str) -> None:
        assert adapter_for_tool(tool).tool == tool

    def test_port_adapter_maps_state(self) -> None:
        transport = MockNetworkTransport()
        raw = transport.discover_ports(
            WEB_NAME, mode=NetworkMode.ACTIVE, ports=[22]
        )
        out = adapter_for_tool("discover_ports").adapt(
            raw, context={"target": WEB_NAME, "mode": NetworkMode.ACTIVE}
        )
        assert isinstance(out, NetworkNormalizedOutput)
        assert out.observations[0].kind == "port"
        assert out.observations[0].state == PortState.OPEN

    def test_dns_adapter_uses_server(self) -> None:
        transport = MockNetworkTransport()
        raw = transport.observe_dns("dns.internal.example", mode=NetworkMode.ACTIVE)
        out = adapter_for_tool("observe_dns").adapt(
            raw,
            context={
                "target": "dns.internal.example",
                "mode": NetworkMode.ACTIVE,
            },
        )
        assert len(out.observations) == 8
        assert all(o.server == "dns.internal.example" for o in out.observations)

    def test_error_document_propagates(self) -> None:
        transport = MockNetworkTransport()
        raw = transport.discover_ports(
            "filtered.internal.example", mode=NetworkMode.ACTIVE, ports=[22]
        )
        out = adapter_for_tool("discover_ports").adapt(
            raw, context={"mode": NetworkMode.ACTIVE}
        )
        assert out.error is not None
        assert out.observations == []

    def test_banner_redaction_at_normalization(self) -> None:
        transport = MockNetworkTransport()
        raw = transport.observe_banners(
            API_NAME, mode=NetworkMode.ACTIVE, ports=[8080]
        )
        out = adapter_for_tool("observe_banners").adapt(
            raw, context={"target": API_NAME, "mode": NetworkMode.ACTIVE}
        )
        banner = next(o for o in out.observations if o.port == 8080)
        assert "top-secret" not in banner.banner
        assert "demo-token" not in banner.banner
        assert "demo-key" not in banner.banner

    def test_malformed_json_raises(self) -> None:
        from blackforge.core.errors import NetworkNormalizationError

        with pytest.raises(NetworkNormalizationError):
            adapter_for_tool("discover_ports").adapt("{not-json", context={})


class TestNetworkCapabilities:
    def test_meta(self) -> None:
        metas = {m.name: m for m in build_network_meta()}
        assert len(metas) == 11
        meta = metas["network.port_discovery"]
        assert meta.risk_level == RiskLevel.MEDIUM
        assert meta.mode.value == "active"
        assert meta.produces == [NetworkObservationKind.PORT]

    def test_engine_capabilities_match_meta(self) -> None:
        metas = {m.name: m for m in build_network_meta()}
        assert metas["network.host_discovery"].risk_level == RiskLevel.LOW
        assert metas["network.dns_observation"].mode.value == "passive"

    def test_build_network_capabilities(self) -> None:
        caps = build_network_capabilities()
        assert len(caps) == 11
        assert {c.capability_id for c in caps} == set(NETWORK_CAPABILITY_IDS)

    def test_adapter_bound_to_capability(self) -> None:
        caps = {c.capability_id: c for c in build_network_capabilities()}
        cap = caps["network.banner_observation"]
        assert cap.adapter.tool == "observe_banners"

    def test_tool_method_mapping(self) -> None:
        assert len(METHOD_TO_CAPABILITY) == 11
        assert METHOD_TO_CAPABILITY["discover_hosts"] == "network.host_discovery"


class TestNetworkEnginePipeline:
    def _pipeline(self) -> NetworkEngine:
        engine, _, _ = _engine()
        return engine

    def test_discover_hosts_cidr(self) -> None:
        result = self._pipeline().discover_hosts(
            _request(scope=_demo_scope()), "192.0.2.0/24"
        )
        assert result.status == NetworkStatus.SUCCESS
        assert result.observation_count == 5
        assert all(o.kind == "host" for o in result.observations)

    def test_discover_ports(self) -> None:
        result = self._pipeline().discover_ports(
            _request(scope=_demo_scope()), WEB_NAME, ports=[22, 80, 443]
        )
        assert result.status == NetworkStatus.SUCCESS
        assert result.observation_count == 3

    def test_passive_mode_success(self) -> None:
        result = self._pipeline().discover_hosts(
            _request(scope=_demo_scope(), mode=NetworkMode.PASSIVE),
            "192.0.2.0/24",
        )
        assert result.mode == NetworkMode.PASSIVE
        assert result.status == NetworkStatus.SUCCESS

    def test_evidence_persisted(self) -> None:
        engine, evidence, _ = _engine()
        result = engine.discover_ports(
            _request(scope=_demo_scope()), WEB_NAME, ports=[22, 80, 443]
        )
        assert result.evidence_ids
        stored = evidence.list(limit=1000)
        assert len(stored) == 4

    def test_world_materialization(self) -> None:
        engine, _, world = _engine()
        req = _request(scope=_demo_scope())
        engine.discover_ports(req, WEB_NAME, ports=[22, 80, 443])
        engine.observe_services(req, WEB_NAME, ports=[22, 80, 443])
        engine.observe_banners(req, WEB_NAME, ports=[22, 80])
        engine.observe_tls(req, WEB_NAME, ports=[443])
        engine.identify_protocols(req, WEB_NAME, ports=[22, 443])
        engine.analyze_exposure(req, WEB_NAME)
        engine.observe_dns(req, "dns.internal.example")
        entities = world.list_entities(WorldQuery(mission_id=MID, limit=1000))
        types = {e.entity_type.value for e in entities}
        assert {"host", "port", "service", "protocol", "interface"} - types == set()
        rels = world.list_relationships(
            RelationshipQuery(mission_id=MID, limit=1000)
        )
        rel_types = {r.relationship_type.value for r in rels}
        assert {"has_port", "runs_service", "uses_protocol", "has_interface"} <= rel_types

    def test_banner_redaction_end_to_end(self) -> None:
        engine, evidence, _ = _engine()
        result = engine.observe_banners(
            _request(scope=_demo_scope()), API_NAME, ports=[8080]
        )
        banner = next(o for o in result.observations if o.port == 8080)
        assert "top-secret" not in banner.banner
        stored = evidence.list(limit=1000)
        artifact = next(e for e in stored if e.evidence_type == EvidenceType.ARTIFACT)
        assert "top-secret" not in artifact.raw_data
        assert "demo-token" not in artifact.raw_data

    def test_run_dispatcher(self) -> None:
        engine = self._pipeline()
        result = engine.run(
            _request(scope=_demo_scope()), "network.port_discovery", WEB_NAME,
            ports=[22, 80],
        )
        assert result.status == NetworkStatus.SUCCESS
        assert result.capability_id == "network.port_discovery"
        with pytest.raises(NetworkExecutionError):
            engine.run(_request(scope=_demo_scope()), "network.nonexistent", WEB_NAME)

    def test_observation_limit_truncates(self) -> None:
        engine = self._pipeline()
        req = _request(scope=_demo_scope())
        req = req.model_copy(update={"max_observations": 2})
        result = engine.discover_hosts(req, "192.0.2.0/24")
        assert result.status == NetworkStatus.LIMITED
        assert result.observation_count == 2

    def test_mode_param_override(self) -> None:
        engine = self._pipeline()
        result = engine.discover_hosts(
            _request(scope=_demo_scope(), mode=NetworkMode.ACTIVE),
            "192.0.2.0/24",
            mode="passive",
        )
        assert result.mode == NetworkMode.PASSIVE


class TestNetworkStatusMapping:
    def test_error_host_statuses(self) -> None:
        engine, _, _ = _engine()
        req = _request(scope=_demo_scope())
        for host, expected in ERROR_TARGETS.items():
            result = engine.discover_ports(req, host, ports=[22])
            assert result.status == expected, host

    def test_no_evidence_status(self) -> None:
        engine, _, _ = _engine()
        result = engine.discover_ports(
            _request(scope=_demo_scope()), "quiet.internal.example"
        )
        assert result.status == NetworkStatus.NO_EVIDENCE

    def test_out_of_scope_raises(self) -> None:
        engine, _, _ = _engine()
        req = _request(scope=_scope(allowed_targets=["internal.example"]))
        with pytest.raises(AuthorizationError):
            engine.discover_ports(req, "203.0.113.99", ports=[22])

    def test_medium_risk_passes_low_mission_limit(self) -> None:
        engine, _, _ = _engine()
        scope = _scope(allowed_targets=[WEB_NAME], max_risk_level=RiskLevel.LOW)
        req = _request(scope=scope)
        result = engine.observe_services(req, WEB_NAME, ports=[443])
        assert result.status == NetworkStatus.SUCCESS


class TestNetworkPortValidation:
    def test_oversize_port_list_raises(self) -> None:
        engine, _, _ = _engine()
        with pytest.raises(NetworkExecutionError, match="port range too large"):
            engine.discover_ports(
                _request(scope=_demo_scope()), WEB_NAME, ports=[22] * 70000
            )

    def test_non_int_port_raises(self) -> None:
        engine, _, _ = _engine()
        with pytest.raises(NetworkExecutionError, match="only integers"):
            engine.discover_ports(
                _request(scope=_demo_scope()), WEB_NAME, ports=[22, "80"]
            )

    def test_out_of_range_port_raises(self) -> None:
        engine, _, _ = _engine()
        with pytest.raises(NetworkExecutionError, match="out of range"):
            engine.discover_ports(
                _request(scope=_demo_scope()), WEB_NAME, ports=[70000]
            )

    def test_ports_ignored_for_non_probing_capability(self) -> None:
        engine, _, _ = _engine()
        result = engine.discover_hosts(
            _request(scope=_demo_scope()), "192.0.2.0/24", ports=[70000]
        )
        assert result.status == NetworkStatus.SUCCESS


class TestNetworkDedup:
    def test_repeat_run_does_not_duplicate_evidence(self) -> None:
        engine, evidence, _ = _engine()
        req = _request(scope=_demo_scope())
        first = engine.discover_ports(req, WEB_NAME, ports=[22, 80, 443])
        assert len(first.evidence_ids) == 4
        engine.discover_ports(req, WEB_NAME, ports=[22, 80, 443])
        stored = evidence.list(limit=1000)
        assert len(stored) == 4

    def test_dedup_via_existing_evidence_id(self) -> None:
        engine, evidence, _ = _engine()
        req = _request(scope=_demo_scope())
        first = engine.discover_ports(req, WEB_NAME, ports=[443])
        existing = existing_evidence_id(
            evidence,
            observation_evidence(
                MID, WEB_NAME, "network.port_discovery", first.observations[0]
            ),
        )
        assert existing is not None


class TestNetworkSqlitePersistence:
    def test_sqlite_persists_evidence_and_world(self, tmp_path) -> None:
        from blackforge.evidence.repository import SQLiteEvidenceRepository
        from blackforge.world_model.repository import SQLiteWorldRepository

        evidence = EvidenceStore(
            repository=SQLiteEvidenceRepository(str(tmp_path / "net_ev.db"))
        )
        world = WorldModelStore(
            repository=SQLiteWorldRepository(str(tmp_path / "net_wm.db"))
        )
        engine = NetworkEngine(
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        result = engine.discover_ports(
            _request(scope=_demo_scope()), WEB_NAME, ports=[22, 80, 443]
        )
        assert result.observation_count == 3
        stored = evidence.list(limit=1000)
        assert len(stored) == 4
        entities = world.list_entities(WorldQuery(mission_id=MID, limit=1000))
        assert len(entities) >= 1


class TestNetworkPackageAssembly:
    def test_module_exports(self) -> None:
        import blackforge.network as net

        assert net.NetworkEngine is not None
        assert net.MockNetworkTransport is not None
        assert len(net.NETWORK_CAPABILITY_IDS) == 11
        for name in (
            "NetworkCapability",
            "NetworkMode",
            "NetworkRequest",
            "NetworkResult",
            "Observation",
            "NetworkWorldMaterializer",
        ):
            assert hasattr(net, name), name

    def test_all_capabilities_present_in_engine(self) -> None:
        engine, _, _ = _engine()
        capabilities = {c.capability_id for c in engine.capabilities}
        assert capabilities == set(NETWORK_CAPABILITY_IDS)

    def test_network_and_business_logic_engines_coexist(self, tmp_path) -> None:
        evidence = EvidenceStore(repository=InMemoryEvidenceRepository())
        world = WorldModelStore(repository=InMemoryWorldRepository())
        registry = CapabilityRegistry()
        registry.register_defaults()
        for cap in build_recon_capabilities():
            registry.register(cap)
        for cap in build_webapi_capabilities():
            registry.register(cap)
        for cap in build_network_capabilities():
            registry.register(cap)
        net_engine = NetworkEngine(
            capability_registry=registry,
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        bl_engine = BusinessLogicEngine(
            capability_registry=registry,
            evidence_store=evidence,
            world_model=world,
            authorization=AuthorizationBoundary(mode="strict"),
        )
        expected = (
            1
            + len(build_recon_capabilities())
            + len(build_webapi_capabilities())
            + len(build_network_capabilities())
            + len(build_business_logic_capabilities())
        )
        assert len(registry.list_capabilities()) == expected == 39
        net_result = net_engine.discover_ports(
            _request(scope=_demo_scope()), WEB_NAME, ports=[22]
        )
        assert net_result.status == NetworkStatus.SUCCESS
        from blackforge.business_logic.models import BusinessLogicRequest

        bl_req = BusinessLogicRequest(
            mission_id=MID,
            session_id=SID,
            scope=_scope(allowed_targets=["shop.example.com"]),
            mode="active",
            test_identities=["alice", "bob", "customer", "admin", "warehouse"],
            max_observations=500,
            timeout_seconds=30.0,
        )
        bl_result = bl_engine.discover_workflows(bl_req, "shop.example.com")
        assert bl_result.observation_count >= 1
        assert evidence.list(limit=1000)
