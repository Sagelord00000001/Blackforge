from __future__ import annotations

import hashlib
import json
import time

import pytest
from pydantic import TypeAdapter, ValidationError

from blackforge.authorization import AuthorizationBoundary
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import (
    AuthorizationError,
    WebApiExecutionError,
    WebApiNormalizationError,
    WebApiTimeoutError,
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
from blackforge.recon.engine import ReconEngine
from blackforge.scope.models import Target, TargetScope
from blackforge.webapi.capabilities import (
    WEBAPI_CAPABILITY_IDS,
    WebApiCapability,
    build_webapi_capabilities,
    build_webapi_meta,
)
from blackforge.webapi.engine import WebApiEngine
from blackforge.webapi.evidence import (
    observation_confidence,
    observation_evidence,
    observation_summary,
)
from blackforge.webapi.mock import MockWebTransport
from blackforge.webapi.models import (
    ApiObservation,
    AuthSurfaceObservation,
    CookieObservation,
    CorsObservation,
    EndpointObservation,
    GraphQlObservation,
    Observation,
    OpenApiObservation,
    RequestOutcomeObservation,
    SecurityHeaderObservation,
    WebApiMode,
    WebApiRequest,
    WebApiResult,
    WebApiStatus,
    WebApplicationObservation,
    WebObservationKind,
)
from blackforge.webapi.normalization import (
    ApiSurfaceAdapter,
    AuthSurfaceAdapter,
    CookieAdapter,
    CorsAdapter,
    EndpointEnumerationAdapter,
    GraphQlAdapter,
    OpenApiAdapter,
    RequestResponseAdapter,
    SecurityHeaderAdapter,
    WebApplicationDiscoveryAdapter,
)
from blackforge.webapi.redaction import redact_document, redact_headers, redact_secret
from blackforge.world_model.models import EntityType
from blackforge.world_model.query import RelationshipQuery
from blackforge.world_model.repository import (
    InMemoryWorldRepository,
    SQLiteWorldRepository,
)
from blackforge.world_model.store import WorldModelStore

MID = MissionID("mission_webapi")
MID_OTHER = MissionID("mission_webapi_other")
SID = SessionID("sess_webapi")


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
    mode: WebApiMode = WebApiMode.ACTIVE,
    scope: TargetScope | None = None,
    max_observations: int = 500,
    timeout_seconds: float = 30.0,
    session_id: SessionID | None = SID,
) -> WebApiRequest:
    return WebApiRequest(
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
) -> tuple[WebApiEngine, EvidenceStore, WorldModelStore]:
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
    engine = WebApiEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class TestWebApiModels:
    def test_mode_enum(self) -> None:
        assert WebApiMode.PASSIVE.value == "passive"
        assert WebApiMode.ACTIVE.value == "active"

    def test_status_enum(self) -> None:
        expected = {
            "success",
            "partial",
            "limited",
            "no_evidence",
            "request_failed",
            "rate_limited",
            "unauthorized",
            "out_of_scope",
            "malformed_response",
            "timeout",
            "failed",
        }
        assert {s.value for s in WebApiStatus} == expected

    def test_kind_enum(self) -> None:
        expected = {
            "application",
            "endpoint",
            "api",
            "security_header",
            "cookie",
            "cors",
            "auth_surface",
            "openapi",
            "graphql",
            "request_response",
        }
        assert {k.value for k in WebObservationKind} == expected

    def test_observation_union_discrimination(self) -> None:
        adapter = TypeAdapter(Observation)
        app = WebApplicationObservation(url="https://a.example.com/", host="a.example.com")
        assert adapter.validate_python(app.model_dump()).kind == "application"
        header = SecurityHeaderObservation(
            url="https://a.example.com/",
            host="a.example.com",
            header_name="X-Frame-Options",
            present=False,
        )
        assert adapter.validate_python(header.model_dump()).kind == "security_header"
        cookie = CookieObservation(url="https://a.example.com/", host="a.example.com", name="sid")
        assert adapter.validate_python(cookie.model_dump()).kind == "cookie"

    def test_request_validation(self) -> None:
        req = _request()
        assert req.mode == WebApiMode.ACTIVE
        assert req.max_observations == 500
        assert req.timeout_seconds == 30.0
        with pytest.raises(ValidationError):
            WebApiRequest(mission_id=MID, scope=_scope(), max_observations=0)
        with pytest.raises(ValidationError):
            WebApiRequest(mission_id=MID, scope=_scope(), max_observations=10_001)
        with pytest.raises(ValidationError):
            WebApiRequest(mission_id=MID, scope=_scope(), timeout_seconds=0)

    def test_result_observation_count(self) -> None:
        result = WebApiResult(
            mission_id=MID,
            session_id=SID,
            target="api.example.com",
            capability_id="webapi.cors_analysis",
            mode=WebApiMode.PASSIVE,
            observations=[
                CorsObservation(
                    url="https://api.example.com/",
                    host="api.example.com",
                    allow_origins=["https://web.example.com"],
                )
            ],
        )
        assert result.observation_count == 1
        assert result.status == WebApiStatus.SUCCESS
        assert result.authorized is True


# --------------------------------------------------------------------------- #
# Capability metadata & registration
# --------------------------------------------------------------------------- #
class TestWebApiCapabilities:
    def test_exactly_ten_webapi_capabilities(self) -> None:
        metas = build_webapi_meta()
        assert len(metas) == 10
        assert [m.name for m in metas] == WEBAPI_CAPABILITY_IDS
        assert len(set(WEBAPI_CAPABILITY_IDS)) == 10

    def test_metadata_fields(self) -> None:
        by_name = {m.name: m for m in build_webapi_meta()}
        assert by_name["webapi.application_discovery"].risk_level == RiskLevel.LOW
        assert by_name["webapi.application_discovery"].mode == WebApiMode.ACTIVE
        assert by_name["webapi.endpoint_enumeration"].risk_level == RiskLevel.MEDIUM
        assert by_name["webapi.request_response_observation"].risk_level == RiskLevel.MEDIUM
        assert by_name["webapi.request_response_observation"].mode == WebApiMode.ACTIVE
        for meta in by_name.values():
            assert meta.category == "web_security"
            assert meta.world_model is True
            assert meta.authorization_required is True
            assert [p.value for p in meta.produces]
            assert TargetType.DOMAIN in meta.supported_target_types
            assert TargetType.IP in meta.supported_target_types
            assert TargetType.URL in meta.supported_target_types
        for name in (
            "webapi.api_surface_discovery",
            "webapi.security_header_analysis",
            "webapi.cookie_analysis",
            "webapi.cors_analysis",
            "webapi.auth_surface_observation",
            "webapi.openapi_review",
            "webapi.graphql_discovery",
        ):
            assert by_name[name].mode == WebApiMode.PASSIVE
            assert by_name[name].risk_level == RiskLevel.LOW

    def test_build_webapi_capabilities(self) -> None:
        caps = build_webapi_capabilities()
        assert len(caps) == 10
        for cap in caps:
            assert isinstance(cap, WebApiCapability)
            assert cap.tool_method
            assert cap.adapter.tool == cap.tool_method

    def test_capability_executes_through_adapter(self) -> None:
        cap = next(
            c for c in build_webapi_capabilities()
            if c.capability_id == "webapi.application_discovery"
        )
        result = cap.execute("web.example.com")
        assert result.success is True
        raw = result.output
        assert isinstance(raw, list) and len(raw) == 1
        assert raw[0]["kind"] == "application"
        assert result.metadata["mock"] is True
        assert result.metadata["tool"] == "discover_web_applications"

    def test_engine_registers_into_registry(self, tmp_path) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        assert len(registry.list_capabilities()) == 1
        ReconEngine(capability_registry=registry)
        assert len(registry.list_capabilities()) == 7
        engine, _, _ = _engine(tmp_path, registry=registry)
        assert registry.has("mock_discovery")
        assert registry.has("recon.dns")
        assert len(registry.list_capabilities()) == 17
        engine2, _, _ = _engine(tmp_path, registry=registry)
        assert len(registry.list_capabilities()) == 17

    def test_engine_exposes_all_webapi_capabilities(self, tmp_path) -> None:
        engine, _, _ = _engine(tmp_path)
        assert len(engine.capabilities) == 10
        assert all(engine.has_capability(c) for c in WEBAPI_CAPABILITY_IDS)

    @pytest.mark.parametrize("pairs", REPO_FACTORIES)
    def test_register_into_existing_registry(self, tmp_path, pairs) -> None:
        registry = CapabilityRegistry()
        engine, _, _ = _engine(tmp_path, pairs=pairs, registry=registry)
        assert (
            registry.get("webapi.application_discovery").meta().name
            == "webapi.application_discovery"
        )


# --------------------------------------------------------------------------- #
# Mock transport
# --------------------------------------------------------------------------- #
class TestMockWebTransport:
    def test_demo_host_deterministic(self) -> None:
        first = MockWebTransport().discover_web_applications("web.example.com")
        second = MockWebTransport().discover_web_applications("web.example.com")
        assert first == second

    def test_fallback_is_stable(self) -> None:
        a = MockWebTransport().discover_web_applications("fictional.example.com")
        b = MockWebTransport().discover_web_applications("fictional.example.com")
        c = MockWebTransport().discover_web_applications("fictional.example.com")
        assert a == b == c
        assert json.loads(a)["host"] == "fictional.example.com"

    def test_public_test_ranges_used(self) -> None:
        tool = MockWebTransport()
        for host in (
            "web.example.com",
            "api.example.com",
            "www.example.com",
            "mail.example.com",
        ):
            ip = tool._record_for(host)["ip"]
            assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip

    def test_mail_host_has_no_web(self) -> None:
        doc = json.loads(MockWebTransport().discover_web_applications("mail.example.com"))
        assert doc["apps"] == []
        assert doc["note"] == "no web application observed"

    def test_error_records(self) -> None:
        unreachable = json.loads(
            MockWebTransport().enumerate_endpoints("unreachable.example.com")
        )
        assert unreachable["error"]["kind"] == "connection_refused"
        throttled = json.loads(
            MockWebTransport().enumerate_endpoints("throttled.example.com")
        )
        assert throttled["error"]["kind"] == "rate_limited"

    def test_no_plaintext_secrets_in_raw_output(self) -> None:
        tool = MockWebTransport()
        for host in ("web.example.com", "api.example.com"):
            raw = tool.observe_request_response(host)
            assert "REDACTED:" in raw
            for secret in ("mock-bearer", "mock-session-web", "mock-password"):
                assert secret not in raw
        openapi_raw = tool.parse_openapi("api.example.com")
        assert "REDACTED:" in openapi_raw
        assert "mock-password" not in openapi_raw


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
class TestRedaction:
    def test_redact_secret_is_deterministic_sha256(self) -> None:
        assert redact_secret("secret") == redact_secret("secret")
        assert redact_secret("secret") != "secret"
        digest = redact_secret("secret")
        assert len(digest) == 64
        assert digest == hashlib.sha256(b"secret").hexdigest()

    def test_redact_headers_hashes_only_secret_values(self) -> None:
        headers = {
            "Authorization": "Bearer abc123",
            "Set-Cookie": "sid=xyz",
            "Server": "nginx/1.24.0",
        }
        out = redact_headers(headers)
        assert out["Authorization"].startswith("REDACTED:")
        assert out["Set-Cookie"].startswith("REDACTED:")
        assert "abc123" not in json.dumps(out)
        assert "xyz" not in json.dumps(out)
        assert out["Server"] == "nginx/1.24.0"

    def test_redact_document_is_recursive(self) -> None:
        doc = {
            "info": {"title": "Example", "password": "pw"},
            "schemes": [
                {"name": "headers", "api_key": "k123", "public": True},
                {"name": "note", "value": "kept"},
            ],
        }
        out = redact_document(doc)
        assert out["info"]["title"] == "Example"
        assert out["info"]["password"] == redact_secret("pw")
        assert out["schemes"][0]["name"] == "headers"
        assert out["schemes"][0]["public"] is True
        assert out["schemes"][0]["api_key"] == redact_secret("k123")
        assert out["schemes"][1]["value"] == "kept"
        assert "pw" not in json.dumps(out)
        assert "k123" not in json.dumps(out)


# --------------------------------------------------------------------------- #
# Normalization adapters
# --------------------------------------------------------------------------- #
class TestNormalizationAdapters:
    def test_application_discovery(self) -> None:
        raw = MockWebTransport().discover_web_applications("web.example.com")
        out = WebApplicationDiscoveryAdapter().adapt(raw)
        assert len(out.observations) == 1
        app = out.observations[0]
        assert isinstance(app, WebApplicationObservation)
        assert app.url == "https://web.example.com/"
        assert app.host == "web.example.com"
        assert app.title == "Example Web Server"
        assert app.technologies == ["nginx", "php", "jquery"]
        assert app.tls_version == "TLSv1.3"

    def test_endpoint_enumeration(self) -> None:
        raw = MockWebTransport().enumerate_endpoints("web.example.com")
        out = EndpointEnumerationAdapter().adapt(raw)
        assert len(out.observations) == 3
        assert [o.url for o in out.observations] == [
            "https://web.example.com/",
            "https://web.example.com/login",
            "https://web.example.com/api/v1/status",
        ]
        assert all(o.status_code == 200 for o in out.observations)
        assert out.observations[2].content_type == "application/json"

    def test_api_surface_discovery(self) -> None:
        raw = MockWebTransport().identify_api_surfaces("api.example.com")
        out = ApiSurfaceAdapter().adapt(raw)
        assert len(out.observations) == 3
        by_kind = {o.kind_label: o for o in out.observations}
        assert by_kind["openapi"].docs_url == "https://api.example.com/docs"
        assert by_kind["swagger"].style == "rest"
        assert by_kind["graphql"].style == "graphql"
        assert all(isinstance(o, ApiObservation) for o in out.observations)

    def test_security_header_analysis(self) -> None:
        raw = MockWebTransport().inspect_security_headers("api.example.com")
        out = SecurityHeaderAdapter().adapt(raw)
        assert len(out.observations) == 6
        present = {o.header_name for o in out.observations if o.present}
        missing = {o.header_name for o in out.observations if not o.present}
        assert present == {
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
        }
        assert missing == {"X-Frame-Options", "Referrer-Policy", "Permissions-Policy"}
        hsts = next(o for o in out.observations if o.header_name == "Strict-Transport-Security")
        assert hsts.present is True
        assert hsts.value == "max-age=31536000"

    def test_cookie_analysis_never_stores_plaintext(self) -> None:
        raw = MockWebTransport().inspect_cookies("web.example.com")
        out = CookieAdapter().adapt(raw)
        assert len(out.observations) == 1
        cookie = out.observations[0]
        assert isinstance(cookie, CookieObservation)
        assert cookie.name == "session"
        assert cookie.secure is True
        assert cookie.httponly is True
        assert cookie.samesite == "Lax"
        assert cookie.value_hashed is not None
        assert len(cookie.value_hashed) == 64
        assert cookie.value_hashed != "mock-session-web"
        assert "mock-session-web" not in cookie.model_dump_json()

    def test_cors_analysis_present_and_absent(self) -> None:
        present = CorsAdapter().adapt(MockWebTransport().analyze_cors("www.example.com"))
        assert len(present.observations) == 1
        cors = present.observations[0]
        assert isinstance(cors, CorsObservation)
        assert cors.allow_origins == ["https://web.example.com"]
        assert cors.allow_credentials is True
        assert cors.wildcard_origin is False
        absent = CorsAdapter().adapt(MockWebTransport().analyze_cors("web.example.com"))
        assert absent.observations == []
        assert absent.warnings and "no CORS policy" in absent.warnings[0]

    def test_auth_surface_inventory(self) -> None:
        raw = MockWebTransport().inspect_authentication("api.example.com")
        out = AuthSurfaceAdapter().adapt(raw)
        assert len(out.observations) == 1
        auth = out.observations[0]
        assert isinstance(auth, AuthSurfaceObservation)
        assert auth.scheme == "bearer"
        assert auth.scheme_type == "oauth_bearer"
        assert auth.parameter_name == "Authorization"

    def test_openapi_review(self) -> None:
        raw = MockWebTransport().parse_openapi("api.example.com")
        out = OpenApiAdapter().adapt(raw)
        assert len(out.observations) == 1
        oa = out.observations[0]
        assert isinstance(oa, OpenApiObservation)
        assert oa.spec_version == "3.0.3"
        assert oa.document_title == "Example API"
        assert oa.path_count == 3
        assert oa.operation_count == 3
        assert set(oa.security_schemes) == {"bearerAuth:http", "apiKeyAuth:apiKey"}

    def test_openapi_absent_document(self) -> None:
        raw = MockWebTransport().parse_openapi("web.example.com")
        out = OpenApiAdapter().adapt(raw)
        assert out.observations == []
        assert out.warnings and "no OpenAPI document" in out.warnings[0]

    def test_graphql_discovery(self) -> None:
        raw = MockWebTransport().discover_graphql("api.example.com")
        out = GraphQlAdapter().adapt(raw)
        assert len(out.observations) == 1
        gql = out.observations[0]
        assert isinstance(gql, GraphQlObservation)
        assert gql.introspection_enabled is True
        assert gql.type_count == 14
        assert gql.query_count == 2
        assert gql.mutation_count == 0
        assert gql.operation_names == ["health", "user"]

    def test_graphql_absent_endpoint(self) -> None:
        raw = MockWebTransport().discover_graphql("web.example.com")
        out = GraphQlAdapter().adapt(raw)
        assert out.observations == []
        assert out.warnings and "no GraphQL endpoint" in out.warnings[0]

    def test_request_response_redaction_preserved(self) -> None:
        raw = MockWebTransport().observe_request_response("api.example.com")
        out = RequestResponseAdapter().adapt(raw)
        assert len(out.observations) == 3
        first = out.observations[0]
        assert isinstance(first, RequestOutcomeObservation)
        assert first.status_code == 200
        auth = first.redacted_headers.get("Authorization")
        assert auth is not None
        assert auth.startswith("REDACTED:")
        assert "Bearer" not in auth
        assert "mock-bearer" not in first.model_dump_json()
        assert out.observations[-1].status_code == 401

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(WebApiNormalizationError, match="malformed JSON"):
            WebApplicationDiscoveryAdapter().adapt("{not json")

    def test_non_document_raises(self) -> None:
        with pytest.raises(WebApiNormalizationError, match="not a parseable"):
            EndpointEnumerationAdapter().adapt(42)

    def test_error_document_propagates(self) -> None:
        raw = MockWebTransport().enumerate_endpoints("throttled.example.com")
        out = EndpointEnumerationAdapter().adapt(raw)
        assert out.observations == []
        assert out.error is not None
        assert out.error["kind"] == "rate_limited"

    def test_discards_invalid_entries(self) -> None:
        raw = {
            "tool": "enumerate_endpoints",
            "host": "web.example.com",
            "endpoints": [
                {"url": "https://web.example.com/", "status_code": 200, "host": "web.example.com"},
                {"url": "https://web.example.com/bad", "status_code": 99999},
                {"url": "https://web.example.com/text", "status_code": "200"},
            ],
        }
        out = EndpointEnumerationAdapter().adapt(raw)
        assert len(out.observations) == 1
        assert len(out.warnings) == 2
        assert all("discarded" in w for w in out.warnings)


# --------------------------------------------------------------------------- #
# Confidence & evidence helpers
# --------------------------------------------------------------------------- #
class TestConfidencePolicy:
    def test_active_direct_kinds_high(self) -> None:
        app = WebApplicationObservation(url="https://w.example.com/", host="w.example.com")
        endpoint = EndpointObservation(
            url="https://w.example.com/", host="w.example.com", status_code=200
        )
        request = RequestOutcomeObservation(url="https://w.example.com/", host="w.example.com")
        for obs in (app, endpoint, request):
            assert observation_confidence(obs, WebApiMode.ACTIVE) == Confidence.HIGH
            assert observation_confidence(obs, WebApiMode.PASSIVE) == Confidence.LOW

    def test_document_kinds_medium(self) -> None:
        header = SecurityHeaderObservation(
            url="https://w.example.com/",
            host="w.example.com",
            header_name="X-A",
            present=True,
        )
        cookie = CookieObservation(url="https://w.example.com/", host="w.example.com", name="sid")
        cors = CorsObservation(url="https://w.example.com/", host="w.example.com")
        auth = AuthSurfaceObservation(
            url="https://w.example.com/", host="w.example.com", scheme="jwt"
        )
        api = ApiObservation(url="https://w.example.com/v1", host="w.example.com", style="rest")
        oa = OpenApiObservation(url="https://w.example.com/openapi", host="w.example.com")
        gql = GraphQlObservation(url="https://w.example.com/graphql", host="w.example.com")
        for obs in (header, cookie, cors, auth, api, oa, gql):
            assert observation_confidence(obs, WebApiMode.ACTIVE) == Confidence.MEDIUM
            assert observation_confidence(obs, WebApiMode.PASSIVE) == Confidence.LOW

    def test_summary_and_evidence_construction(self) -> None:
        obs = EndpointObservation(
            url="https://web.example.com/login",
            host="web.example.com",
            status_code=200,
            content_type="text/html",
        )
        assert "https://web.example.com/login" in observation_summary(obs)
        evidence = observation_evidence(
            MID, "web.example.com", "webapi.endpoint_enumeration", obs, mode=WebApiMode.ACTIVE
        )
        assert evidence.evidence_type == EvidenceType.OBSERVATION
        assert evidence.confidence == Confidence.HIGH
        assert json.loads(evidence.raw_data)["kind"] == "endpoint"
        assert evidence.reference == "https://web.example.com/login"
        assert evidence.metadata["webapi"] is True


# --------------------------------------------------------------------------- #
# End-to-end engine (in-memory + SQLite)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pairs", REPO_FACTORIES)
class TestEnginePipeline:
    def test_discover_apps_e2e(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        result = engine.discover_web_applications(_request(), "web.example.com")
        assert result.status == WebApiStatus.SUCCESS
        assert result.authorized is True
        assert result.capability_id == "webapi.application_discovery"
        assert result.mode == WebApiMode.ACTIVE
        assert result.raw_output is not None
        apps = [o for o in result.observations if isinstance(o, WebApplicationObservation)]
        assert len(apps) == 1
        assert len(result.evidence_ids) == len(result.observations) + 1
        assert len(evidence.repository.list(limit=10_000)) == len(result.evidence_ids)

    def test_evidence_artifact_and_derived_from(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        result = engine.enumerate_endpoints(_request(), "web.example.com")
        artifact_id = result.evidence_ids[0]
        artifact = evidence.get(artifact_id)
        assert artifact is not None
        assert artifact.evidence_type == EvidenceType.ARTIFACT
        assert json.loads(artifact.raw_data)["tool"] == "enumerate_endpoints"
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
        first = engine.discover_web_applications(_request(), "web.example.com")
        count_a = len(evidence.repository.list(limit=10_000))
        second = engine.discover_web_applications(_request(), "web.example.com")
        count_b = len(evidence.repository.list(limit=10_000))
        assert count_a == count_b
        assert first.evidence_ids == second.evidence_ids
        assert world.count_entities(MID) == 1

    def test_mission_isolation(self, tmp_path, pairs) -> None:
        engine, evidence, world = _engine(tmp_path, pairs=pairs)
        engine.enumerate_endpoints(_request(MID), "web.example.com")
        other_scope = _scope(MID_OTHER)
        engine.enumerate_endpoints(_request(MID_OTHER, scope=other_scope), "web.example.com")
        other_evidence = [
            e for e in evidence.repository.list(limit=10_000) if e.mission_id == MID_OTHER
        ]
        assert len(other_evidence) == 4
        assert world.count_entities(MID) == 4
        assert world.count_entities(MID_OTHER) == 4

    def test_world_model_mapping_application(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.discover_web_applications(_request(), "api.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "api.example.com")
        assert app is not None
        assert app.properties["url"] == "https://api.example.com/"

    def test_world_model_mapping_endpoints_and_contains(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.enumerate_endpoints(_request(), "web.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "web.example.com")
        assert app is not None
        endpoint = world.find_entity(MID, EntityType.ENDPOINT, "https://web.example.com/login")
        assert endpoint is not None
        assert endpoint.properties["status_code"] == 200
        rels = world.list_relationships(RelationshipQuery(mission_id=MID, limit=100))
        contains = [
            r for r in rels
            if getattr(r.relationship_type, "value", r.relationship_type) == "contains"
        ]
        assert len(contains) == 3
        assert all(r.source_entity_id == str(app.id) for r in contains)

    def test_world_model_mapping_api_surface(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.identify_api_surfaces(_request(), "api.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "api.example.com")
        assert app is not None
        api = world.find_entity(MID, EntityType.API, "https://api.example.com/openapi.json")
        assert api is not None
        assert api.properties["style"] == "rest"
        rels = world.list_relationships(RelationshipQuery(mission_id=MID, limit=100))
        contains_api = [
            r for r in rels
            if getattr(r.relationship_type, "value", r.relationship_type) == "contains"
            and r.target_entity_id == str(api.id)
        ]
        assert len(contains_api) == 1

    def test_world_model_assertions_bound_to_application(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.inspect_security_headers(_request(), "api.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "api.example.com")
        assert app is not None
        assertions = world.list_assertions(str(app.id))
        assert len(assertions) == 6
        keys = {a.property_key for a in assertions}
        assert "security_header.Content-Security-Policy" in keys
        assert "security_header.X-Frame-Options" in keys

    def test_world_model_request_response_assertions(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_request_response(_request(), "api.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "api.example.com")
        assert app is not None
        endpoint = world.find_entity(
            MID, EntityType.ENDPOINT, "https://api.example.com/v1/health"
        )
        assert endpoint is not None
        assertions = world.list_assertions(str(endpoint.id))
        keys = {a.property_key for a in assertions}
        assert "http_status" in keys
        assert "server_header" in keys
        rels = world.list_relationships(RelationshipQuery(mission_id=MID, limit=100))
        contains = [
            r for r in rels
            if getattr(r.relationship_type, "value", r.relationship_type) == "contains"
        ]
        assert len(contains) == 2

    def test_world_model_no_churn_on_rerun(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.inspect_cookies(_request(), "web.example.com")
        entity_count = world.count_entities(MID)
        rel_count = len(world.list_relationships(RelationshipQuery(mission_id=MID, limit=100)))
        app = world.find_entity(MID, EntityType.APPLICATION, "web.example.com")
        assertions = len(world.list_assertions(str(app.id)))
        engine.inspect_cookies(_request(), "web.example.com")
        assert world.count_entities(MID) == entity_count
        assert (
            len(world.list_relationships(RelationshipQuery(mission_id=MID, limit=100)))
            == rel_count
        )
        assert len(world.list_assertions(str(app.id))) == assertions

    def test_no_evidence_status(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.discover_web_applications(_request(), "mail.example.com")
        assert result.status == WebApiStatus.NO_EVIDENCE
        assert result.observations == []
        assert result.warnings
        assert result.raw_output is not None

    def test_rate_limited_status(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.enumerate_endpoints(_request(), "throttled.example.com")
        assert result.status == WebApiStatus.RATE_LIMITED
        assert result.observations == []
        assert "rate limited" in (result.error or "")

    def test_request_failed_status(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.enumerate_endpoints(_request(), "unreachable.example.com")
        assert result.status == WebApiStatus.REQUEST_FAILED
        assert result.observations == []
        assert "connection refused" in (result.error or "")

    def test_limited_truncation(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        request = _request(max_observations=2)
        result = engine.inspect_security_headers(request, "api.example.com")
        assert result.status == WebApiStatus.LIMITED
        assert len(result.observations) == 2
        assert any("limit" in w for w in result.warnings)

    def test_dispatcher_run(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.run(_request(), "webapi.application_discovery", "web.example.com")
        assert result.capability_id == "webapi.application_discovery"
        assert result.status == WebApiStatus.SUCCESS
        assert {o.kind for o in result.observations} == {"application"}

    def test_unknown_capability_via_engine(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(WebApiExecutionError, match="unknown web api capability"):
            engine.run(_request(), "webapi.not_real", "web.example.com")

    def test_target_type_mismatch(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(WebApiExecutionError, match="does not support target"):
            engine.enumerate_endpoints(_request(), "192.0.2.0/24")

    def test_passive_mode_low_confidence(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        request = _request()
        result = engine.enumerate_endpoints(request, "web.example.com", mode="passive")
        assert result.mode == WebApiMode.PASSIVE
        assert all(
            evidence.get(e).confidence == Confidence.LOW for e in result.evidence_ids[1:]
        )

    def test_authorization_denied_out_of_scope(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        scope = _scope(allowed_targets=["other.example.com"])
        with pytest.raises(AuthorizationError, match="not authorized"):
            engine.discover_web_applications(_request(scope=scope), "web.example.com")

    def test_authorization_denied_capability(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        scope = _scope(allowed_capabilities=["webapi.cookie_analysis"])
        with pytest.raises(AuthorizationError, match="not authorized"):
            engine.enumerate_endpoints(_request(scope=scope), "web.example.com")

    def test_malformed_tool_output_raises(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        engine._transport.enumerate_endpoints = lambda target, mode: "{not json"
        with pytest.raises(WebApiNormalizationError, match="malformed JSON"):
            engine.enumerate_endpoints(_request(), "web.example.com")

    def test_timeout_raises(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        original = engine._transport.discover_web_applications

        def slow(target, mode):
            time.sleep(0.05)
            return original(target, mode=mode)

        engine._transport.discover_web_applications = slow
        with pytest.raises(WebApiTimeoutError, match="timed out"):
            engine.discover_web_applications(
                _request(timeout_seconds=0.001), "web.example.com"
            )

    def test_no_plaintext_secrets_in_evidence(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        engine.observe_request_response(_request(), "api.example.com")
        records = evidence.repository.list(limit=10_000)
        assert records
        serialized = json.dumps([r.raw_data for r in records])
        for secret in ("mock-bearer", "mock-password", "mock-session-web"):
            assert secret not in serialized

    def test_sqlite_persistence(self, tmp_path, pairs) -> None:
        if pairs[0] != "sqlite":
            pytest.skip("sqlite pair only")
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        engine.inspect_cookies(_request(), "web.example.com")
        engine.evidence_store.close()
        engine.world_model.close()
        fresh = WebApiEngine(
            evidence_store=EvidenceStore(
                repository=SQLiteEvidenceRepository(str(tmp_path / "ev.db"))
            ),
            world_model=WorldModelStore(
                repository=SQLiteWorldRepository(str(tmp_path / "wm.db"))
            ),
            authorization=AuthorizationBoundary(mode="strict"),
        )
        assert fresh.evidence_store.count(MID) == 2
        assert fresh.world_model.count_entities(MID) == 1


# --------------------------------------------------------------------------- #
# Status mapping
# --------------------------------------------------------------------------- #
class TestStatusMapping:
    def test_partial_when_observations_and_warnings(self) -> None:
        assert (
            WebApiEngine._map_status(None, False, [object()], ["w"])
            == WebApiStatus.PARTIAL
        )

    def test_success(self) -> None:
        assert WebApiEngine._map_status(None, False, [object()], []) == WebApiStatus.SUCCESS

    def test_error_kind_maps(self) -> None:
        assert (
            WebApiEngine._map_status({"kind": "rate_limited"}, False, [], [])
            == WebApiStatus.RATE_LIMITED
        )
        assert (
            WebApiEngine._map_status({"kind": "unauthorized"}, False, [], [])
            == WebApiStatus.UNAUTHORIZED
        )
        assert (
            WebApiEngine._map_status({"kind": "malformed_response"}, False, [], [])
            == WebApiStatus.MALFORMED_RESPONSE
        )
        assert (
            WebApiEngine._map_status({"kind": "other"}, False, [], [])
            == WebApiStatus.REQUEST_FAILED
        )


# --------------------------------------------------------------------------- #
# Unauthorized/dispatcher safety & security surface
# --------------------------------------------------------------------------- #
class TestEngineSafety:
    def test_no_generic_shell_executor(self) -> None:
        assert not hasattr(WebApiEngine, "execute_command")
        assert not hasattr(WebApiEngine, "shell")
        assert not hasattr(WebApiEngine, "run_command")

    def test_webapi_package_has_no_network_dependencies(self) -> None:
        import os

        for root, _dirs, files in os.walk("blackforge/webapi"):
            for name in files:
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    text = fh.read()
                for banned in (
                    "os.system",
                    "subprocess",
                    "socket",
                    "urllib.request",
                    "http.client",
                    "eval(",
                    "exec(",
                    "pickle",
                ):
                    assert banned not in text, (name, banned)
                assert "import requests" not in text, (name, "requests")
                assert "from requests" not in text, (name, "requests")

    def test_webapi_engine_executes_only_typed_methods(self) -> None:
        for method in (
            "discover_web_applications",
            "enumerate_endpoints",
            "identify_api_surfaces",
            "inspect_security_headers",
            "inspect_cookies",
            "analyze_cors",
            "inspect_authentication",
            "parse_openapi",
            "discover_graphql",
            "observe_request_response",
        ):
            assert callable(getattr(WebApiEngine, method))

    def test_no_auth_bypass_method_names(self) -> None:
        for method in (
            "bruteforce",
            "password_spray",
            "inject",
            "bypass",
            "exploit",
            "guess_credentials",
            "enum_users",
        ):
            assert not hasattr(WebApiEngine, method)
            assert not hasattr(MockWebTransport, method)

    def test_original_capability_registry_unmodified(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        assert len(registry.list_capabilities()) == 1


# --------------------------------------------------------------------------- #
# License & module assembly
# --------------------------------------------------------------------------- #
class TestWebApiPackageAssembly:
    def test_import_surface(self) -> None:
        from blackforge import webapi

        assert webapi.WebApiEngine is WebApiEngine
        assert webapi.MockWebTransport is MockWebTransport
        assert webapi.WebApplicationObservation is WebApplicationObservation
        assert "NormalizedOutput" not in webapi.__all__

    def test_materializer_import_and_report(self) -> None:
        from blackforge.webapi.materializer import WebMaterializeReport

        report = WebMaterializeReport()
        assert report.relationships_created == 0
        assert report.entities_created == 0
        assert report.entities_updated == 0
        assert report.assertions_created == 0
        assert report.assertions_corroborated == 0
