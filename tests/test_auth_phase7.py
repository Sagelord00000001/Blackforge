from __future__ import annotations

import hashlib
import json
import time

import pytest
from pydantic import TypeAdapter, ValidationError

from blackforge.auth.capabilities import (
    AUTH_CAPABILITY_IDS,
    AuthCapability,
    build_auth_capabilities,
    build_auth_meta,
)
from blackforge.auth.engine import METHOD_TO_CAPABILITY, AuthEngine
from blackforge.auth.evidence import (
    observation_confidence,
    observation_evidence,
    observation_summary,
)
from blackforge.auth.models import (
    AccessControlObservation,
    AuthAccess,
    AuthenticationSchemeObservation,
    AuthMode,
    AuthObservationKind,
    AuthorizationSurfaceObservation,
    AuthRequest,
    AuthResult,
    AuthStatus,
    AuthSurfaceObservation,
    MfaStatus,
    MfaSurfaceObservation,
    OAuthMetadataObservation,
    Observation,
    OidcMetadataObservation,
    PermissionObservation,
    ResourceAccessObservation,
    RoleObservation,
    SessionObservation,
)
from blackforge.auth.normalization import (
    AccessControlAdapter,
    AuthenticationSurfaceAdapter,
    AuthorizationSurfaceAdapter,
    AuthSchemeDetectionAdapter,
    MfaSurfaceAdapter,
    OAuthMetadataAdapter,
    OidcMetadataAdapter,
    PermissionAdapter,
    ResourceAccessAdapter,
    RoleAdapter,
    SessionObservationAdapter,
    adapter_for_tool,
)
from blackforge.auth.redaction import (
    CREDENTIAL_LIKE_KEYS,
    CREDENTIAL_REDACTED,
    credential_value_redacted,
    redact_credential_fields,
    redact_document,
    redact_headers,
    redact_nested_credential_values,
    redact_secret,
)
from blackforge.auth.transport import MockAuthTransport
from blackforge.authorization import AuthorizationBoundary
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import (
    AuthError,
    AuthExecutionError,
    AuthNormalizationError,
    AuthorizationError,
    AuthTimeoutError,
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
from blackforge.webapi.engine import WebApiEngine
from blackforge.world_model.models import EntityType
from blackforge.world_model.query import RelationshipQuery
from blackforge.world_model.repository import (
    InMemoryWorldRepository,
    SQLiteWorldRepository,
)
from blackforge.world_model.store import WorldModelStore

MID = MissionID("mission_auth")
MID_OTHER = MissionID("mission_auth_other")
SID = SessionID("sess_auth")


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
    mode: AuthMode = AuthMode.ACTIVE,
    scope: TargetScope | None = None,
    max_observations: int = 500,
    timeout_seconds: float = 30.0,
    session_id: SessionID | None = SID,
    test_identities: list[str] | None = None,
) -> AuthRequest:
    return AuthRequest(
        mission_id=mission_id,
        scope=scope or _scope(mission_id),
        session_id=session_id,
        mode=mode,
        test_identities=test_identities or [],
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
) -> tuple[AuthEngine, EvidenceStore, WorldModelStore]:
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
    engine = AuthEngine(
        capability_registry=registry,
        evidence_store=evidence_store,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence_store, world


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class TestAuthModels:
    def test_mode_enum(self) -> None:
        assert AuthMode.PASSIVE.value == "passive"
        assert AuthMode.ACTIVE.value == "active"

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
        assert {s.value for s in AuthStatus} == expected

    def test_access_enum(self) -> None:
        expected = {"allowed", "denied", "unknown", "error", "not_tested"}
        assert {a.value for a in AuthAccess} == expected

    def test_mfa_status_enum(self) -> None:
        expected = {"observed", "not_observed", "unknown"}
        assert {s.value for s in MfaStatus} == expected

    def test_kind_enum(self) -> None:
        expected = {
            "auth_surface",
            "auth_scheme",
            "session",
            "oauth_metadata",
            "oidc_metadata",
            "mfa_surface",
            "authorization_surface",
            "role",
            "permission",
            "resource_access",
            "access_control",
        }
        assert {k.value for k in AuthObservationKind} == expected

    def test_observation_union_discrimination(self) -> None:
        adapter = TypeAdapter(Observation)
        surface = AuthSurfaceObservation(
            url="https://a.example.com/", host="a.example.com", scheme="jwt"
        )
        assert adapter.validate_python(surface.model_dump()).kind == "auth_surface"
        session = SessionObservation(
            url="https://a.example.com/", host="a.example.com", name="sid"
        )
        assert adapter.validate_python(session.model_dump()).kind == "session"
        access = ResourceAccessObservation(
            url="https://a.example.com/",
            host="a.example.com",
            identity="alice",
            resource="reports",
            access=AuthAccess.ALLOWED,
        )
        assert adapter.validate_python(access.model_dump()).kind == "resource_access"

    def test_credential_value_defaults_redacted(self) -> None:
        permission = PermissionObservation(
            url="https://a.example.com/",
            host="a.example.com",
            permission="create",
            granted=True,
        )
        assert permission.credential_value == "REDACTED"
        access = ResourceAccessObservation(
            url="https://a.example.com/",
            host="a.example.com",
            identity="alice",
            resource="reports",
        )
        assert access.credential_value == "REDACTED"
        comparison = AccessControlObservation(
            url="https://a.example.com/",
            host="a.example.com",
            identity="alice",
            resource="reports",
        )
        assert comparison.credential_value == "REDACTED"

    def test_request_validation(self) -> None:
        req = _request()
        assert req.mode == AuthMode.ACTIVE
        assert req.test_identities == []
        assert req.max_observations == 500
        assert req.timeout_seconds == 30.0
        with pytest.raises(ValidationError):
            AuthRequest(mission_id=MID, scope=_scope(), max_observations=0)
        with pytest.raises(ValidationError):
            AuthRequest(mission_id=MID, scope=_scope(), max_observations=10_001)
        with pytest.raises(ValidationError):
            AuthRequest(mission_id=MID, scope=_scope(), timeout_seconds=0)

    def test_result_observation_count(self) -> None:
        result = AuthResult(
            mission_id=MID,
            session_id=SID,
            target="web.example.com",
            capability_id="auth.authentication_surface",
            mode=AuthMode.PASSIVE,
            observations=[
                AuthSurfaceObservation(
                    url="https://web.example.com/",
                    host="web.example.com",
                    scheme="session_cookie",
                )
            ],
        )
        assert result.observation_count == 1
        assert result.status == AuthStatus.SUCCESS
        assert result.authorized is True

    def test_error_hierarchy(self) -> None:
        assert issubclass(AuthNormalizationError, AuthError)
        assert issubclass(AuthExecutionError, AuthError)
        assert issubclass(AuthTimeoutError, AuthError)


# --------------------------------------------------------------------------- #
# Capability metadata & registration
# --------------------------------------------------------------------------- #
class TestAuthCapabilities:
    def test_exactly_eleven_auth_capabilities(self) -> None:
        metas = build_auth_meta()
        assert len(metas) == 11
        assert [m.name for m in metas] == AUTH_CAPABILITY_IDS
        assert len(set(AUTH_CAPABILITY_IDS)) == 11

    def test_metadata_fields(self) -> None:
        by_name = {m.name: m for m in build_auth_meta()}
        assert by_name["auth.authentication_surface"].risk_level == RiskLevel.LOW
        assert by_name["auth.authentication_surface"].mode == AuthMode.ACTIVE
        assert by_name["auth.resource_access_observation"].risk_level == RiskLevel.HIGH
        assert by_name["auth.access_control_comparison"].risk_level == RiskLevel.HIGH
        assert by_name["auth.access_control_comparison"].mode == AuthMode.ACTIVE
        for meta in by_name.values():
            assert meta.category == "auth_security"
            assert meta.world_model is True
            assert meta.authorization_required is True
            assert [p.value for p in meta.produces]
            assert TargetType.DOMAIN in meta.supported_target_types
            assert TargetType.IP in meta.supported_target_types
            assert TargetType.URL in meta.supported_target_types
        for name in (
            "auth.authentication_scheme_detection",
            "auth.oauth_metadata_observation",
            "auth.oidc_metadata_observation",
            "auth.authorization_surface",
            "auth.role_observation",
            "auth.permission_observation",
        ):
            assert by_name[name].mode == AuthMode.PASSIVE
        for name in (
            "auth.authentication_surface",
            "auth.session_observation",
            "auth.mfa_surface_observation",
            "auth.resource_access_observation",
            "auth.access_control_comparison",
        ):
            assert by_name[name].mode == AuthMode.ACTIVE

    def test_build_auth_capabilities(self) -> None:
        caps = build_auth_capabilities()
        assert len(caps) == 11
        for cap in caps:
            assert isinstance(cap, AuthCapability)
            assert cap.tool_method
            assert cap.adapter.tool == cap.tool_method

    def test_capability_executes_through_adapter(self) -> None:
        cap = next(
            c
            for c in build_auth_capabilities()
            if c.capability_id == "auth.authentication_surface"
        )
        result = cap.execute("web.example.com")
        assert result.success is True
        raw = result.output
        assert isinstance(raw, list) and len(raw) == 1
        assert raw[0]["kind"] == "auth_surface"
        assert raw[0]["scheme"] == "session_cookie"
        assert result.metadata["mock"] is True
        assert result.metadata["tool"] == "observe_authentication_surface"

    def test_engine_registers_into_registry(self, tmp_path) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        assert len(registry.list_capabilities()) == 1
        ReconEngine(capability_registry=registry)
        assert len(registry.list_capabilities()) == 7
        WebApiEngine(capability_registry=registry)
        assert len(registry.list_capabilities()) == 17
        engine, _, _ = _engine(tmp_path, registry=registry)
        assert registry.has("auth.role_observation")
        assert len(registry.list_capabilities()) == 28
        engine2, _, _ = _engine(tmp_path, registry=registry)
        assert len(registry.list_capabilities()) == 28

    def test_engine_exposes_all_auth_capabilities(self, tmp_path) -> None:
        engine, _, _ = _engine(tmp_path)
        assert len(engine.capabilities) == 11
        assert all(engine.has_capability(c) for c in AUTH_CAPABILITY_IDS)

    @pytest.mark.parametrize("pairs", REPO_FACTORIES)
    def test_register_into_existing_registry(self, tmp_path, pairs) -> None:
        registry = CapabilityRegistry()
        engine, _, _ = _engine(tmp_path, pairs=pairs, registry=registry)
        assert (
            registry.get("auth.authentication_surface").meta().name
            == "auth.authentication_surface"
        )


# --------------------------------------------------------------------------- #
# Mock transport
# --------------------------------------------------------------------------- #
class TestMockAuthTransport:
    def test_demo_host_deterministic(self) -> None:
        first = MockAuthTransport().observe_authentication_surface("web.example.com")
        second = MockAuthTransport().observe_authentication_surface("web.example.com")
        assert first == second

    def test_fallback_is_stable(self) -> None:
        a = MockAuthTransport().observe_authentication_surface("fictional.example.com")
        b = MockAuthTransport().observe_authentication_surface("fictional.example.com")
        c = MockAuthTransport().observe_authentication_surface("fictional.example.com")
        assert a == b == c
        assert json.loads(a)["host"] == "fictional.example.com"

    def test_public_test_ranges_used(self) -> None:
        tool = MockAuthTransport()
        for host in (
            "web.example.com",
            "api.example.com",
            "www.example.com",
            "mail.example.com",
        ):
            ip = tool._record_for(host)["ip"]
            assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip

    def test_mail_host_has_no_web(self) -> None:
        doc = json.loads(
            MockAuthTransport().observe_authentication_surface("mail.example.com")
        )
        assert doc["schemes"] == []
        assert doc["note"] == "no web application observed"
        assert "url" not in doc

    def test_error_records(self) -> None:
        unreachable = json.loads(
            MockAuthTransport().observe_mfa_surface("unreachable.example.com")
        )
        assert unreachable["error"]["kind"] == "connection_refused"
        throttled = json.loads(
            MockAuthTransport().observe_roles("throttled.example.com")
        )
        assert throttled["error"]["kind"] == "rate_limited"

    def test_no_plaintext_credentials_in_raw_output(self) -> None:
        tool = MockAuthTransport()
        for host in ("web.example.com", "api.example.com"):
            raw = tool.observe_permissions(host)
            assert "REDACTED" in raw
            for secret in ("mock-bearer", "mock-session-web", "mock-password"):
                assert secret not in raw
        access_raw = tool.observe_resource_access("web.example.com")
        assert "REDACTED" in access_raw
        assert "mock-password" not in access_raw

    def test_session_values_hashed_in_raw(self) -> None:
        raw = MockAuthTransport().observe_session_details("web.example.com")
        doc = json.loads(raw)
        assert doc["sessions"][0]["value_hashed"] != "mock-session-web"
        assert len(doc["sessions"][0]["value_hashed"]) == 64
        assert "mock-session-web" not in raw

    def test_compare_requires_test_identities(self) -> None:
        raw = MockAuthTransport().compare_access_control("web.example.com")
        doc = json.loads(raw)
        assert doc["comparisons"] == []
        assert "NOT_TESTED" in doc["note"]

    def test_compare_with_identities(self) -> None:
        raw = MockAuthTransport().compare_access_control(
            "web.example.com", test_identities=["alice", "bob"]
        )
        doc = json.loads(raw)
        assert [(c["identity"], c["resource"]) for c in doc["comparisons"]] == [
            ("alice", "reports"),
            ("alice", "admin_panel"),
            ("bob", "reports"),
        ]
        assert doc["comparisons"][0]["consistent"] is True
        assert all(c["credential_value"] == "REDACTED" for c in doc["comparisons"])


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
class TestAuthRedaction:
    def test_redacted_marker_is_literal(self) -> None:
        assert CREDENTIAL_REDACTED == "REDACTED"
        assert credential_value_redacted() == "REDACTED"

    def test_credential_like_keys_policy(self) -> None:
        for key in (
            "password",
            "token",
            "access_token",
            "client_secret",
            "authorization",
            "cookie",
            "api_key",
            "mfa_code",
            "credential",
            "credential_value",
        ):
            assert key in CREDENTIAL_LIKE_KEYS
        assert "title" not in CREDENTIAL_LIKE_KEYS

    def test_redact_credential_fields_recursive(self) -> None:
        doc = {
            "observed_url": "https://web.example.com/",
            "schemes": [
                {
                    "scheme": "bearer",
                    "parameter_name": "Authorization",
                    "credential_value": "Bearer mock-bearer",
                    "public": True,
                }
            ],
            "note": "kept",
        }
        out = redact_credential_fields(doc)
        assert out["schemes"][0]["credential_value"] == "REDACTED"
        assert out["schemes"][0]["scheme"] == "bearer"
        assert out["schemes"][0]["public"] is True
        assert out["note"] == "kept"
        serialized = json.dumps(out)
        assert "mock-bearer" not in serialized

    def test_redact_credential_fields_top_level_key(self) -> None:
        out = redact_credential_fields({"authorization": "Bearer abc", "ok": 1})
        assert out["authorization"] == "REDACTED"
        assert out["ok"] == 1

    def test_redact_nested_credential_values(self) -> None:
        doc = {
            "access": [
                {"identity": "alice", "credential_value": "secret", "role": "editor"}
            ]
        }
        out = redact_nested_credential_values(doc)
        assert out["access"][0]["credential_value"] == "REDACTED"
        assert out["access"][0]["identity"] == "alice"
        assert out["access"][0]["role"] == "editor"
        assert "secret" not in json.dumps(out)

    def test_webapi_redaction_rexported(self) -> None:
        assert redact_secret("secret") == hashlib.sha256(b"secret").hexdigest()
        headers = redact_headers(
            {"Authorization": "Bearer abc", "Server": "nginx/1.24.0"}
        )
        assert headers["Authorization"].startswith("REDACTED:")
        assert headers["Server"] == "nginx/1.24.0"
        doc = redact_document({"info": {"password": "pw"}, "title": "kept"})
        assert doc["title"] == "kept"
        assert "pw" not in json.dumps(doc)


# --------------------------------------------------------------------------- #
# Normalization adapters
# --------------------------------------------------------------------------- #
class TestAuthNormalizationAdapters:
    def test_authentication_surface(self) -> None:
        raw = MockAuthTransport().observe_authentication_surface("web.example.com")
        out = AuthenticationSurfaceAdapter().adapt(raw)
        assert len(out.observations) == 1
        surface = out.observations[0]
        assert isinstance(surface, AuthSurfaceObservation)
        assert surface.url == "https://web.example.com/"
        assert surface.host == "web.example.com"
        assert surface.scheme == "session_cookie"
        assert surface.scheme_type == "cookie_session"
        assert surface.parameter_name == "session"

    def test_authentication_surface_multiple_schemes(self) -> None:
        raw = MockAuthTransport().observe_authentication_surface("api.example.com")
        out = AuthenticationSurfaceAdapter().adapt(raw)
        assert [o.scheme for o in out.observations] == ["bearer", "api_key"]

    def test_session_observation(self) -> None:
        raw = MockAuthTransport().observe_session_details("web.example.com")
        out = SessionObservationAdapter().adapt(raw)
        assert len(out.observations) == 1
        session = out.observations[0]
        assert isinstance(session, SessionObservation)
        assert session.name == "session"
        assert session.secure is True
        assert session.httponly is True
        assert session.samesite == "Lax"
        assert "Secure" in session.flags
        assert session.value_hashed is not None
        assert len(session.value_hashed) == 64
        assert session.value_hashed != "mock-session-web"
        assert "mock-session-web" not in session.model_dump_json()

    def test_session_absent(self) -> None:
        raw = MockAuthTransport().observe_session_details("api.example.com")
        out = SessionObservationAdapter().adapt(raw)
        assert out.observations == []
        assert out.warnings and "sessions observed" in (
            out.warnings[0] if out.warnings else ""
        )

    def test_auth_scheme_detection(self) -> None:
        raw = MockAuthTransport().detect_authentication_schemes("web.example.com")
        out = AuthSchemeDetectionAdapter().adapt(raw)
        assert len(out.observations) == 1
        scheme = out.observations[0]
        assert isinstance(scheme, AuthenticationSchemeObservation)
        assert scheme.scheme == "session_cookie"
        assert scheme.present is True
        assert scheme.password_policy_observed is True
        assert scheme.password_policy == "min_length=8;complexity=required;pw_reuse_disallowed"
        assert scheme.session_timeout_minutes == 30

    def test_oauth_metadata(self) -> None:
        raw = MockAuthTransport().observe_oauth_metadata("api.example.com")
        out = OAuthMetadataAdapter().adapt(raw)
        assert len(out.observations) == 1
        oauth = out.observations[0]
        assert isinstance(oauth, OAuthMetadataObservation)
        assert oauth.authorization_endpoint == "https://auth.example.com/oauth/authorize"
        assert oauth.grant_types == ["authorization_code", "client_credentials"]
        assert oauth.scopes == ["reports:read", "reports:write"]
        assert oauth.pkce_supported is True

    def test_oauth_absent(self) -> None:
        raw = MockAuthTransport().observe_oauth_metadata("web.example.com")
        out = OAuthMetadataAdapter().adapt(raw)
        assert out.observations == []
        assert out.warnings and "no OAuth2 metadata" in out.warnings[0]

    def test_oidc_metadata(self) -> None:
        raw = MockAuthTransport().observe_oidc_metadata("api.example.com")
        out = OidcMetadataAdapter().adapt(raw)
        assert len(out.observations) == 1
        oidc = out.observations[0]
        assert isinstance(oidc, OidcMetadataObservation)
        assert oidc.issuer == "https://auth.example.com/"
        assert oidc.subject_type == "public"
        assert oidc.id_token_signing_alg == "RS256"
        assert oidc.discovery_url == (
            "https://auth.example.com/.well-known/openid-configuration"
        )

    def test_oidc_absent(self) -> None:
        raw = MockAuthTransport().observe_oidc_metadata("web.example.com")
        out = OidcMetadataAdapter().adapt(raw)
        assert out.observations == []
        assert out.warnings and "no OIDC metadata" in out.warnings[0]

    def test_mfa_surface_observed(self) -> None:
        raw = MockAuthTransport().observe_mfa_surface("web.example.com")
        out = MfaSurfaceAdapter().adapt(raw)
        assert len(out.observations) == 1
        mfa = out.observations[0]
        assert isinstance(mfa, MfaSurfaceObservation)
        assert mfa.mfa_status == MfaStatus.OBSERVED
        assert mfa.factors == ["totp", "email_otp"]
        assert mfa.prompt_observed is True

    def test_mfa_surface_not_observed(self) -> None:
        raw = MockAuthTransport().observe_mfa_surface("api.example.com")
        out = MfaSurfaceAdapter().adapt(raw)
        assert out.observations[0].mfa_status == MfaStatus.NOT_OBSERVED

    def test_mfa_surface_unknown_fallback(self) -> None:
        raw = MockAuthTransport().observe_mfa_surface("fictional.example.com")
        out = MfaSurfaceAdapter().adapt(raw)
        assert out.observations[0].mfa_status == MfaStatus.UNKNOWN

    def test_authorization_surface(self) -> None:
        raw = MockAuthTransport().observe_authorization_surface("web.example.com")
        out = AuthorizationSurfaceAdapter().adapt(raw)
        assert len(out.observations) == 1
        authz = out.observations[0]
        assert isinstance(authz, AuthorizationSurfaceObservation)
        assert authz.authz_model == "role_based"
        assert authz.enforcement == "declarative"

    def test_authorization_surface_none_observed(self) -> None:
        raw = MockAuthTransport().observe_authorization_surface("legacy.example.com")
        out = AuthorizationSurfaceAdapter().adapt(raw)
        assert len(out.observations) == 1
        assert out.observations[0].authz_model == "none_observed"

    def test_roles(self) -> None:
        raw = MockAuthTransport().observe_roles("web.example.com")
        out = RoleAdapter().adapt(raw)
        assert [o.role for o in out.observations] == ["viewer", "editor"]

    def test_roles_absent(self) -> None:
        raw = MockAuthTransport().observe_roles("api.example.com")
        out = RoleAdapter().adapt(raw)
        assert [o.role for o in out.observations] == ["service_account"]

    def test_permissions(self) -> None:
        raw = MockAuthTransport().observe_permissions("web.example.com")
        out = PermissionAdapter().adapt(raw)
        assert len(out.observations) == 5
        permissions = out.observations
        granted = {o.permission for o in permissions if o.identity == "alice" and o.granted}
        assert granted == {"create", "update"}
        denied = {
            o.permission for o in permissions if o.identity == "alice" and not o.granted
        }
        assert denied == {"delete"}
        assert all(o.credential_value == "REDACTED" for o in permissions)

    def test_permission_credential_forced_redacted(self) -> None:
        raw = {
            "tool": "observe_permissions",
            "target": "web.example.com",
            "host": "web.example.com",
            "observed_url": "https://web.example.com/",
            "permissions": [
                {
                    "identity": "alice",
                    "role": "editor",
                    "permission": "create",
                    "resource": "reports",
                    "granted": True,
                    "credential_used": True,
                    "credential_type": "session_cookie",
                    "credential_value": "mock-password",
                }
            ],
        }
        out = PermissionAdapter().adapt(raw)
        assert out.observations[0].credential_value == "REDACTED"
        assert "mock-password" not in out.observations[0].model_dump_json()

    def test_resource_access_outcomes(self) -> None:
        raw = MockAuthTransport().observe_resource_access("web.example.com")
        out = ResourceAccessAdapter().adapt(raw)
        assert len(out.observations) == 5
        by_pair = {
            (o.identity, o.resource): o.access for o in out.observations
        }
        assert by_pair[("alice", "reports")] == AuthAccess.ALLOWED
        assert by_pair[("alice", "admin_panel")] == AuthAccess.DENIED
        assert by_pair[("charlie", "reports")] == AuthAccess.UNKNOWN
        assert by_pair[("dave", "billing")] == AuthAccess.NOT_TESTED
        assert all(o.credential_value == "REDACTED" for o in out.observations)

    def test_redirect_never_allowed(self) -> None:
        raw = {
            "tool": "observe_resource_access",
            "target": "web.example.com",
            "host": "web.example.com",
            "observed_url": "https://web.example.com/",
            "access": [
                {
                    "identity": "alice",
                    "resource": "reports",
                    "access": "redirect",
                    "credential_value": "REDACTED",
                    "note": "server issued a redirect — not an access grant",
                }
            ],
        }
        out = ResourceAccessAdapter().adapt(raw)
        access = out.observations[0].access
        assert access not in {AuthAccess.ALLOWED, AuthAccess.DENIED}
        assert access == AuthAccess.UNKNOWN

    def test_access_literal_parse_strict(self) -> None:
        raw = {
            "tool": "observe_resource_access",
            "target": "web.example.com",
            "host": "web.example.com",
            "observed_url": "https://web.example.com/",
            "access": [
                {"identity": "a", "resource": "r1", "access": "malformed"},
                {"identity": "a", "resource": "r2", "access": "error"},
                {"identity": "a", "resource": "r3", "access": "not_tested"},
                {"identity": "a", "resource": "r4"},
            ],
        }
        out = ResourceAccessAdapter().adapt(raw)
        outcomes = {o.resource: o.access for o in out.observations}
        assert outcomes["r1"] == AuthAccess.UNKNOWN
        assert outcomes["r2"] == AuthAccess.ERROR
        assert outcomes["r3"] == AuthAccess.NOT_TESTED
        assert outcomes["r4"] == AuthAccess.UNKNOWN

    def test_access_control_comparison(self) -> None:
        raw = MockAuthTransport().compare_access_control(
            "web.example.com", test_identities=["alice", "bob"]
        )
        out = AccessControlAdapter().adapt(raw)
        assert len(out.observations) == 3
        by_pair = {
            (o.identity, o.resource): o for o in out.observations
        }
        assert by_pair[("alice", "reports")].access == AuthAccess.ALLOWED
        assert by_pair[("alice", "reports")].expected_access == AuthAccess.ALLOWED
        assert by_pair[("alice", "reports")].consistent is True
        assert by_pair[("alice", "admin_panel")].access == AuthAccess.DENIED
        assert by_pair[("alice", "admin_panel")].consistent is True
        bob = by_pair[("bob", "reports")]
        assert bob.access == AuthAccess.DENIED
        assert bob.expected_access == AuthAccess.DENIED
        assert bob.consistent is True
        assert all(o.credential_value == "REDACTED" for o in out.observations)

    def test_error_document_propagates(self) -> None:
        raw = MockAuthTransport().observe_roles("throttled.example.com")
        out = RoleAdapter().adapt(raw)
        assert out.observations == []
        assert out.error is not None
        assert out.error["kind"] == "rate_limited"

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(AuthNormalizationError, match="malformed JSON"):
            AuthenticationSurfaceAdapter().adapt("{not json")

    def test_non_document_raises(self) -> None:
        with pytest.raises(AuthNormalizationError, match="not a parseable"):
            RoleAdapter().adapt(42)

    def test_discards_invalid_entries(self) -> None:
        raw = {
            "tool": "observe_roles",
            "target": "web.example.com",
            "host": "web.example.com",
            "observed_url": "https://web.example.com/",
            "roles": [
                {"name": "viewer"},
                {"name": ""},
                "not-an-object",
            ],
        }
        out = RoleAdapter().adapt(raw)
        assert [o.role for o in out.observations] == ["viewer"]
        assert len(out.warnings) == 2
        assert all("discarded" in w for w in out.warnings)

    def test_access_control_discards_invalid_entries(self) -> None:
        raw = {
            "tool": "compare_access_control",
            "target": "web.example.com",
            "host": "web.example.com",
            "observed_url": "https://web.example.com/",
            "comparisons": [
                {
                    "identity": "alice",
                    "resource": "reports",
                    "access": "allowed",
                    "expected_access": "allowed",
                    "consistent": True,
                },
                {"identity": "bob", "access": "denied"},
            ],
        }
        out = AccessControlAdapter().adapt(raw)
        assert len(out.observations) == 1
        assert out.observations[0].resource == "reports"
        assert len(out.warnings) == 1

    def test_adapter_for_tool(self) -> None:
        assert isinstance(adapter_for_tool("observe_roles"), RoleAdapter)
        assert isinstance(
            adapter_for_tool("compare_access_control"), AccessControlAdapter
        )
        with pytest.raises(AuthNormalizationError, match="no adapter"):
            adapter_for_tool("bruteforce")


# --------------------------------------------------------------------------- #
# Confidence & evidence helpers
# --------------------------------------------------------------------------- #
class TestAuthConfidencePolicy:
    def test_passive_low_everywhere(self) -> None:
        samples = [
            AuthSurfaceObservation(
                url="https://w.example.com/", host="w.example.com", scheme="jwt"
            ),
            SessionObservation(
                url="https://w.example.com/", host="w.example.com", name="sid"
            ),
            RoleObservation(url="https://w.example.com/", host="w.example.com", role="viewer"),
            ResourceAccessObservation(
                url="https://w.example.com/",
                host="w.example.com",
                identity="alice",
                resource="reports",
                access=AuthAccess.ALLOWED,
            ),
        ]
        for obs in samples:
            assert observation_confidence(obs, AuthMode.PASSIVE) == Confidence.LOW

    def test_active_direct_kinds_high(self) -> None:
        samples = [
            AuthSurfaceObservation(
                url="https://w.example.com/", host="w.example.com", scheme="jwt"
            ),
            AuthenticationSchemeObservation(
                url="https://w.example.com/", host="w.example.com", scheme="jwt"
            ),
            SessionObservation(
                url="https://w.example.com/", host="w.example.com", name="sid"
            ),
            OAuthMetadataObservation(url="https://w.example.com/", host="w.example.com"),
            OidcMetadataObservation(url="https://w.example.com/", host="w.example.com"),
            MfaSurfaceObservation(url="https://w.example.com/", host="w.example.com"),
            AuthorizationSurfaceObservation(
                url="https://w.example.com/", host="w.example.com"
            ),
            ResourceAccessObservation(
                url="https://w.example.com/",
                host="w.example.com",
                identity="alice",
                resource="reports",
                access=AuthAccess.ALLOWED,
            ),
            AccessControlObservation(
                url="https://w.example.com/",
                host="w.example.com",
                identity="alice",
                resource="reports",
                access=AuthAccess.ALLOWED,
                expected_access=AuthAccess.ALLOWED,
            ),
        ]
        for obs in samples:
            assert observation_confidence(obs, AuthMode.ACTIVE) == Confidence.HIGH

    def test_derived_kinds_medium(self) -> None:
        role = RoleObservation(
            url="https://w.example.com/", host="w.example.com", role="viewer"
        )
        permission = PermissionObservation(
            url="https://w.example.com/",
            host="w.example.com",
            identity="alice",
            permission="create",
            resource="reports",
            granted=True,
        )
        for obs in (role, permission):
            assert observation_confidence(obs, AuthMode.ACTIVE) == Confidence.MEDIUM
            assert observation_confidence(obs, AuthMode.PASSIVE) == Confidence.LOW

    def test_summary_and_evidence_construction(self) -> None:
        obs = ResourceAccessObservation(
            url="https://web.example.com/reports",
            host="web.example.com",
            identity="alice",
            resource="reports",
            access=AuthAccess.DENIED,
        )
        assert "reports" in observation_summary(obs)
        evidence = observation_evidence(
            MID,
            "web.example.com",
            "auth.resource_access_observation",
            obs,
            mode=AuthMode.ACTIVE,
        )
        assert evidence.evidence_type == EvidenceType.OBSERVATION
        assert evidence.confidence == Confidence.HIGH
        assert json.loads(evidence.raw_data)["kind"] == "resource_access"
        assert json.loads(evidence.raw_data)["credential_value"] == "REDACTED"
        assert evidence.reference == "https://web.example.com/reports"
        assert evidence.metadata["auth"] is True
        assert "mock" not in evidence.raw_data


# --------------------------------------------------------------------------- #
# End-to-end engine (in-memory + SQLite)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pairs", REPO_FACTORIES)
class TestAuthEnginePipeline:
    def test_observe_auth_surface_e2e(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        result = engine.observe_authentication_surface(_request(), "web.example.com")
        assert result.status == AuthStatus.SUCCESS
        assert result.authorized is True
        assert result.capability_id == "auth.authentication_surface"
        assert result.mode == AuthMode.ACTIVE
        assert result.raw_output is not None
        surfaces = [
            o for o in result.observations if isinstance(o, AuthSurfaceObservation)
        ]
        assert len(surfaces) == 1
        assert len(result.evidence_ids) == len(result.observations) + 1
        assert len(evidence.repository.list(limit=10_000)) == len(result.evidence_ids)

    def test_evidence_artifact_and_derived_from(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        result = engine.observe_mfa_surface(_request(), "web.example.com")
        artifact_id = result.evidence_ids[0]
        artifact = evidence.get(artifact_id)
        assert artifact is not None
        assert artifact.evidence_type == EvidenceType.ARTIFACT
        assert json.loads(artifact.raw_data)["tool"] == "observe_mfa_surface"
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
        first = engine.observe_session_details(_request(), "web.example.com")
        count_a = len(evidence.repository.list(limit=10_000))
        second = engine.observe_session_details(_request(), "web.example.com")
        count_b = len(evidence.repository.list(limit=10_000))
        assert count_a == count_b
        assert first.evidence_ids == second.evidence_ids
        assert world.count_entities(MID) == 1

    def test_mission_isolation(self, tmp_path, pairs) -> None:
        engine, evidence, world = _engine(tmp_path, pairs=pairs)
        engine.observe_roles(_request(MID), "web.example.com")
        other_scope = _scope(MID_OTHER)
        engine.observe_mfa_surface(
            _request(MID_OTHER, scope=other_scope), "web.example.com"
        )
        other_evidence = [
            e for e in evidence.repository.list(limit=10_000) if e.mission_id == MID_OTHER
        ]
        assert len(other_evidence) == 2
        assert world.count_entities(MID) == 3
        assert world.count_entities(MID_OTHER) == 1

    def test_world_model_auth_scheme_chain(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_authentication_surface(_request(), "web.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "web.example.com")
        assert app is not None
        endpoint = world.find_entity(
            MID, EntityType.ENDPOINT, "https://web.example.com/"
        )
        assert endpoint is not None
        authn = world.find_entity(
            MID,
            EntityType.AUTHENTICATION,
            "session_cookie",
            namespace="web.example.com",
        )
        assert authn is not None
        assert authn.properties["scheme_type"] == "cookie_session"
        rels = world.list_relationships(RelationshipQuery(mission_id=MID, limit=100))
        requires = [
            r
            for r in rels
            if getattr(r.relationship_type, "value", r.relationship_type) == "requires"
        ]
        assert len(requires) == 1
        assert requires[0].source_entity_id == str(endpoint.id)
        assert requires[0].target_entity_id == str(authn.id)
        contains = [
            r
            for r in rels
            if getattr(r.relationship_type, "value", r.relationship_type) == "contains"
        ]
        assert len(contains) == 1
        assert contains[0].source_entity_id == str(app.id)
        assertions = world.list_assertions(str(app.id))
        assert {a.property_key for a in assertions} == {"auth_scheme.session_cookie"}

    def test_world_model_session_assertion(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_session_details(_request(), "web.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "web.example.com")
        assertions = world.list_assertions(str(app.id))
        keys = {a.property_key for a in assertions}
        assert "session.session" in keys

    def test_world_model_oauth_assertion(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_oauth_metadata(_request(), "api.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "api.example.com")
        keys = {a.property_key for a in world.list_assertions(str(app.id))}
        assert "oauth.metadata" in keys

    def test_world_model_oidc_assertion(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_oidc_metadata(_request(), "api.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "api.example.com")
        keys = {a.property_key for a in world.list_assertions(str(app.id))}
        assert "oidc.metadata" in keys

    def test_world_model_mfa_assertion(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_mfa_surface(_request(), "web.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "web.example.com")
        keys = {a.property_key for a in world.list_assertions(str(app.id))}
        assert "mfa" in keys

    def test_world_model_authorization_assertion(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_authorization_surface(_request(), "web.example.com")
        app = world.find_entity(MID, EntityType.APPLICATION, "web.example.com")
        keys = {a.property_key for a in world.list_assertions(str(app.id))}
        assert "authorization.model" in keys

    def test_world_model_identity_chain(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_permissions(_request(), "web.example.com")
        alice = world.find_entity(
            MID, EntityType.IDENTITY, "alice", namespace="web.example.com"
        )
        assert alice is not None
        editor = world.find_entity(
            MID, EntityType.ROLE, "editor", namespace="web.example.com"
        )
        assert editor is not None
        permission = world.find_entity(
            MID, EntityType.PERMISSION, "create::reports", namespace="web.example.com"
        )
        assert permission is not None
        reports = world.find_entity(
            MID, EntityType.RESOURCE, "reports", namespace="web.example.com"
        )
        assert reports is not None

        rels = world.list_relationships(RelationshipQuery(mission_id=MID, limit=100))
        pairs_verify = [
            ("has_role", str(alice.id), str(editor.id)),
            ("has_permission", str(editor.id), str(permission.id)),
            ("applies_to", str(permission.id), str(reports.id)),
        ]
        for rel_type, source, target in pairs_verify:
            matches = [
                r
                for r in rels
                if str(getattr(r.relationship_type, "value", r.relationship_type))
                == rel_type
                and r.source_entity_id == source
                and r.target_entity_id == target
            ]
            assert len(matches) == 1, (rel_type, source, target)
        has_role_count = sum(
            1
            for r in rels
            if str(getattr(r.relationship_type, "value", r.relationship_type))
            == "has_role"
        )
        assert has_role_count == 2
        assert world.count_entities(MID) == 9

    def test_world_model_resource_access_assertions(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        request = _request(test_identities=["alice"])
        result = engine.observe_resource_access(request, "web.example.com")
        assert result.status == AuthStatus.SUCCESS
        alice = world.find_entity(
            MID, EntityType.IDENTITY, "alice", namespace="web.example.com"
        )
        assert alice is not None
        keys = {a.property_key for a in world.list_assertions(str(alice.id))}
        assert "access.reports" in keys
        assert "access.admin_panel" in keys
        assert all(
            a.epistemic_status.value == "validated"
            for a in world.list_assertions(str(alice.id))
        )

    def test_world_model_access_control_assertions(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        request = _request(test_identities=["alice", "bob"])
        result = engine.compare_access_control(request, "web.example.com")
        assert result.status == AuthStatus.SUCCESS
        assert len(result.observations) == 3
        alice = world.find_entity(
            MID, EntityType.IDENTITY, "alice", namespace="web.example.com"
        )
        assert alice is not None
        keys = {a.property_key for a in world.list_assertions(str(alice.id))}
        assert "access_control.reports" in keys
        assert "access_control.admin_panel" in keys

    def test_world_model_no_churn_on_rerun(self, tmp_path, pairs) -> None:
        engine, _, world = _engine(tmp_path, pairs=pairs)
        engine.observe_authentication_surface(_request(), "web.example.com")
        entity_count = world.count_entities(MID)
        rel_count = len(world.list_relationships(RelationshipQuery(mission_id=MID, limit=100)))
        app = world.find_entity(MID, EntityType.APPLICATION, "web.example.com")
        assertions = len(world.list_assertions(str(app.id)))
        engine.observe_authentication_surface(_request(), "web.example.com")
        assert world.count_entities(MID) == entity_count
        assert (
            len(world.list_relationships(RelationshipQuery(mission_id=MID, limit=100)))
            == rel_count
        )
        assert len(world.list_assertions(str(app.id))) == assertions

    def test_no_evidence_status(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.observe_roles(_request(), "mail.example.com")
        assert result.status == AuthStatus.NO_EVIDENCE
        assert result.observations == []
        assert result.warnings
        assert result.raw_output is not None

    def test_no_web_surface_status(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.observe_authentication_surface(_request(), "mail.example.com")
        assert result.status == AuthStatus.NO_EVIDENCE
        assert result.observations == []

    def test_rate_limited_status(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.observe_authentication_surface(
            _request(), "throttled.example.com"
        )
        assert result.status == AuthStatus.RATE_LIMITED
        assert result.observations == []
        assert "rate limited" in (result.error or "")

    def test_request_failed_status(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.observe_mfa_surface(_request(), "unreachable.example.com")
        assert result.status == AuthStatus.REQUEST_FAILED
        assert result.observations == []
        assert "connection refused" in (result.error or "")

    def test_limited_truncation(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        request = _request(max_observations=2, test_identities=["svc-reports"])
        result = engine.observe_resource_access(request, "api.example.com")
        assert result.status == AuthStatus.LIMITED
        assert len(result.observations) == 2
        assert any("limit" in w for w in result.warnings)

    def test_dispatcher_run(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.run(_request(), "auth.session_observation", "web.example.com")
        assert result.capability_id == "auth.session_observation"
        assert result.status == AuthStatus.SUCCESS
        assert {o.kind for o in result.observations} == {"session"}

    def test_unknown_capability_via_engine(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(AuthExecutionError, match="unknown auth capability"):
            engine.run(_request(), "auth.not_real", "web.example.com")

    def test_target_type_mismatch(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(AuthExecutionError, match="does not support target"):
            engine.observe_roles(_request(), "192.0.2.0/24")

    def test_invalid_mode_param_raises(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(AuthExecutionError, match="invalid auth mode"):
            engine.observe_roles(_request(), "web.example.com", mode="sneaky")

    def test_passive_mode_low_confidence(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        result = engine.observe_roles(_request(), "web.example.com", mode="passive")
        assert result.mode == AuthMode.PASSIVE
        assert all(
            evidence.get(e).confidence == Confidence.LOW
            for e in result.evidence_ids[1:]
        )

    def test_authorization_denied_out_of_scope(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        scope = _scope(allowed_targets=["other.example.com"])
        with pytest.raises(AuthorizationError, match="not authorized"):
            engine.observe_roles(_request(scope=scope), "web.example.com")

    def test_authorization_denied_capability(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        scope = _scope(allowed_capabilities=["auth.session_observation"])
        with pytest.raises(AuthorizationError, match="not authorized"):
            engine.observe_roles(_request(scope=scope), "web.example.com")

    def test_missing_test_identities_rejected(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        with pytest.raises(AuthExecutionError, match="requires explicit"):
            engine.observe_resource_access(_request(), "web.example.com")
        with pytest.raises(AuthExecutionError, match="requires explicit"):
            engine.compare_access_control(_request(), "web.example.com")

    def test_test_identities_from_request(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        request = _request(test_identities=["alice"])
        result = engine.observe_resource_access(request, "web.example.com")
        assert result.status == AuthStatus.SUCCESS
        assert len(result.observations) == 5

    def test_access_never_denied_from_network_error(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        request = _request(test_identities=["alice"])
        result = engine.observe_resource_access(request, "unreachable.example.com")
        assert result.status == AuthStatus.REQUEST_FAILED
        assert result.observations == []
        assert "denied" not in (result.error or "").lower()

    def test_malformed_tool_output_raises(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        engine._transport.observe_roles = lambda target, mode: "{not json"
        with pytest.raises(AuthNormalizationError, match="malformed JSON"):
            engine.observe_roles(_request(), "web.example.com")

    def test_timeout_raises(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        original = engine._transport.observe_mfa_surface

        def slow(target, mode):
            time.sleep(0.05)
            return original(target, mode=mode)

        engine._transport.observe_mfa_surface = slow
        with pytest.raises(AuthTimeoutError, match="timed out"):
            engine.observe_mfa_surface(
                _request(timeout_seconds=0.001), "web.example.com"
            )

    def test_no_plaintext_credentials_in_evidence(self, tmp_path, pairs) -> None:
        engine, evidence, _ = _engine(tmp_path, pairs=pairs)
        engine.observe_permissions(_request(), "web.example.com")
        request = _request(test_identities=["alice"])
        engine.observe_resource_access(request, "web.example.com")
        records = evidence.repository.list(limit=10_000)
        assert records
        serialized = json.dumps([r.raw_data for r in records])
        for secret in ("mock-bearer", "mock-password", "mock-session-web"):
            assert secret not in serialized
        for record in records:
            if record.evidence_type != EvidenceType.OBSERVATION:
                continue
            raw = json.loads(record.raw_data)
            if "credential_value" in raw:
                assert raw["credential_value"] == "REDACTED"

    def test_test_identities_param_passthrough(self, tmp_path, pairs) -> None:
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        result = engine.compare_access_control(
            _request(), "web.example.com", test_identities=["alice"]
        )
        assert result.status == AuthStatus.SUCCESS
        assert len(result.observations) == 2
        assert result.observations[0].identity == "alice"

    def test_sqlite_persistence(self, tmp_path, pairs) -> None:
        if pairs[0] != "sqlite":
            pytest.skip("sqlite pair only")
        engine, _, _ = _engine(tmp_path, pairs=pairs)
        engine.observe_authentication_surface(_request(), "web.example.com")
        engine.evidence_store.close()
        engine.world_model.close()
        fresh = AuthEngine(
            evidence_store=EvidenceStore(
                repository=SQLiteEvidenceRepository(str(tmp_path / "ev.db"))
            ),
            world_model=WorldModelStore(
                repository=SQLiteWorldRepository(str(tmp_path / "wm.db"))
            ),
            authorization=AuthorizationBoundary(mode="strict"),
        )
        assert fresh.evidence_store.count(MID) == 2
        assert fresh.world_model.count_entities(MID) == 3


# --------------------------------------------------------------------------- #
# Status mapping
# --------------------------------------------------------------------------- #
class TestAuthStatusMapping:
    def test_partial_when_observations_and_warnings(self) -> None:
        assert (
            AuthEngine._map_status(None, False, [object()], ["w"])
            == AuthStatus.PARTIAL
        )

    def test_success(self) -> None:
        assert AuthEngine._map_status(None, False, [object()], []) == AuthStatus.SUCCESS

    def test_no_evidence(self) -> None:
        assert (
            AuthEngine._map_status(None, False, [], ["no roles observed"])
            == AuthStatus.NO_EVIDENCE
        )

    def test_error_kind_maps(self) -> None:
        assert (
            AuthEngine._map_status({"kind": "rate_limited"}, False, [], [])
            == AuthStatus.RATE_LIMITED
        )
        assert (
            AuthEngine._map_status({"kind": "unauthorized"}, False, [], [])
            == AuthStatus.UNAUTHORIZED
        )
        assert (
            AuthEngine._map_status({"kind": "connection_refused"}, False, [], [])
            == AuthStatus.REQUEST_FAILED
        )
        assert (
            AuthEngine._map_status({"kind": "malformed"}, False, [], [])
            == AuthStatus.MALFORMED_RESPONSE
        )
        assert (
            AuthEngine._map_status({"kind": "other"}, False, [], [])
            == AuthStatus.REQUEST_FAILED
        )


# --------------------------------------------------------------------------- #
# Method mapping & safety surface
# --------------------------------------------------------------------------- #
class TestAuthEngineSafety:
    def test_method_to_capability_covers_all(self) -> None:
        assert len(METHOD_TO_CAPABILITY) == 11
        assert set(METHOD_TO_CAPABILITY.values()) == set(AUTH_CAPABILITY_IDS)

    def test_no_generic_shell_executor(self) -> None:
        assert not hasattr(AuthEngine, "execute_command")
        assert not hasattr(AuthEngine, "shell")
        assert not hasattr(AuthEngine, "run_command")

    def test_auth_package_has_no_network_dependencies(self) -> None:
        import os

        for root, _dirs, files in os.walk("blackforge/auth"):
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

    def test_auth_engine_executes_only_typed_methods(self) -> None:
        for method in (
            "observe_authentication_surface",
            "observe_session_details",
            "detect_authentication_schemes",
            "observe_oauth_metadata",
            "observe_oidc_metadata",
            "observe_mfa_surface",
            "observe_authorization_surface",
            "observe_roles",
            "observe_permissions",
            "observe_resource_access",
            "compare_access_control",
        ):
            assert callable(getattr(AuthEngine, method))

    def test_no_auth_bypass_method_names(self) -> None:
        for method in (
            "bruteforce",
            "password_spray",
            "inject",
            "bypass",
            "exploit",
            "guess_credentials",
            "enum_users",
            "token_forgery",
            "oauth_playground",
        ):
            assert not hasattr(AuthEngine, method)
            assert not hasattr(MockAuthTransport, method)

    def test_original_capability_registry_unmodified(self) -> None:
        registry = CapabilityRegistry()
        registry.register_defaults()
        assert len(registry.list_capabilities()) == 1


# --------------------------------------------------------------------------- #
# License & module assembly
# --------------------------------------------------------------------------- #
class TestAuthPackageAssembly:
    def test_import_surface(self) -> None:
        from blackforge import auth

        assert auth.AuthEngine is AuthEngine
        assert auth.MockAuthTransport is MockAuthTransport
        assert auth.AuthSurfaceObservation is AuthSurfaceObservation
        assert auth.AUTH_CAPABILITY_IDS == AUTH_CAPABILITY_IDS
        assert "AuthenticationSchemeAdapter" not in auth.__all__
        assert "SessionAdapter" not in auth.__all__
        assert "NormalizedOutput" not in auth.__all__
        assert "redact_credentials" not in auth.__all__
        assert "AuthSurfaceAdapter" in auth.__all__

    def test_materializer_import_and_report(self) -> None:
        from blackforge.auth.materializer import AuthMaterializeReport

        report = AuthMaterializeReport()
        assert report.relationships_created == 0
        assert report.entities_created == 0
        assert report.entities_updated == 0
        assert report.assertions_created == 0
        assert report.assertions_corroborated == 0
