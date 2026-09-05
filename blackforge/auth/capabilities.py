from __future__ import annotations

from pydantic import Field

from blackforge.auth.models import (
    AuthMode,
    AuthObservationKind,
)
from blackforge.auth.normalization import (
    AccessControlAdapter,
    AuthenticationSurfaceAdapter,
    AuthorizationSurfaceAdapter,
    AuthSchemeDetectionAdapter,
    AuthToolAdapter,
    MfaSurfaceAdapter,
    OAuthMetadataAdapter,
    OidcMetadataAdapter,
    PermissionAdapter,
    ResourceAccessAdapter,
    RoleAdapter,
    SessionObservationAdapter,
)
from blackforge.auth.transport import MockAuthTransport
from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType

AUTH_CAPABILITY_IDS = [
    "auth.authentication_surface",
    "auth.session_observation",
    "auth.authentication_scheme_detection",
    "auth.oauth_metadata_observation",
    "auth.oidc_metadata_observation",
    "auth.mfa_surface_observation",
    "auth.authorization_surface",
    "auth.role_observation",
    "auth.permission_observation",
    "auth.resource_access_observation",
    "auth.access_control_comparison",
]


class AuthCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for authentication/authorization capabilities."""

    category: str = "auth_security"
    mode: AuthMode = AuthMode.PASSIVE
    produces: list[AuthObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    risk_level: RiskLevel,
    mode: AuthMode,
    supported_target_types: list[TargetType],
    produces: list[AuthObservationKind],
    *,
    version: str = "1.0.0",
) -> AuthCapabilityMeta:
    return AuthCapabilityMeta(
        id=CapabilityID(capability_id),
        name=capability_id,
        description=description,
        version=version,
        risk_level=risk_level,
        authorization_required=True,
        supported_target_types=supported_target_types,
        input_schema={"target": {"type": "string"}, "params": {"type": "object"}},
        output_schema={"observations": {"type": "array"}},
        evidence_types_produced=["artifact", "observation"],
        mode=mode,
        produces=produces,
    )


def build_auth_meta() -> list[AuthCapabilityMeta]:
    """Metadata for all eleven typed auth security capabilities."""
    return [
        _meta(
            "auth.authentication_surface",
            "Inventory authentication surfaces (login pages, schemes) exposed by the target.",
            RiskLevel.LOW,
            AuthMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.AUTH_SURFACE],
        ),
        _meta(
            "auth.session_observation",
            "Record session cookie properties and flags (raw values never stored).",
            RiskLevel.MEDIUM,
            AuthMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.SESSION],
        ),
        _meta(
            "auth.authentication_scheme_detection",
            "Detect auth schemes and publicly exposed session/policy metadata.",
            RiskLevel.LOW,
            AuthMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.AUTH_SCHEME],
        ),
        _meta(
            "auth.oauth_metadata_observation",
            "Record OAuth2 authorization-server metadata (never re-exercised).",
            RiskLevel.LOW,
            AuthMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.OAUTH_METADATA],
        ),
        _meta(
            "auth.oidc_metadata_observation",
            "Record OpenID Connect discovery metadata (never re-exercised).",
            RiskLevel.LOW,
            AuthMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.OIDC_METADATA],
        ),
        _meta(
            "auth.mfa_surface_observation",
            "Record the target's multi-factor authentication posture.",
            RiskLevel.MEDIUM,
            AuthMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.MFA_SURFACE],
        ),
        _meta(
            "auth.authorization_surface",
            "Record how access decisions are expressed (authorization model).",
            RiskLevel.MEDIUM,
            AuthMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.AUTHORIZATION_SURFACE],
        ),
        _meta(
            "auth.role_observation",
            "Record roles observed on the authorized target (descriptive only).",
            RiskLevel.MEDIUM,
            AuthMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.ROLE],
        ),
        _meta(
            "auth.permission_observation",
            "Record observed permission grants for authorized test identities.",
            RiskLevel.MEDIUM,
            AuthMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.PERMISSION],
        ),
        _meta(
            "auth.resource_access_observation",
            "Validate resource access outcomes for explicitly supplied authorized test identities.",
            RiskLevel.HIGH,
            AuthMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.RESOURCE_ACCESS],
        ),
        _meta(
            "auth.access_control_comparison",
            "Compare expected vs observed access for controlled identities.",
            RiskLevel.HIGH,
            AuthMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [AuthObservationKind.ACCESS_CONTROL],
        ),
    ]


class AuthCapability(Capability):
    """A typed auth security capability bound to a mock transport method.

    ``execute`` runs the deterministic mock transport through the
    normalization adapter and returns normalized observations. It performs no
    authorization itself — the :class:`AuthEngine` enforces scope /
    authorization before any execution path reaches the mock.
    """

    def __init__(
        self,
        meta: AuthCapabilityMeta,
        tool_method: str,
        adapter: AuthToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._transport = MockAuthTransport()

    def meta(self) -> AuthCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> AuthToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        mode_param = params.get("mode") if params else None
        mode = AuthMode(mode_param) if mode_param else self._meta.mode
        tool_method = self._tool_method
        if tool_method == "compare_access_control":
            test_identities = params.get("test_identities") if params else None
            identities = (
                [str(i) for i in test_identities]
                if isinstance(test_identities, list)
                else None
            )
            raw = self._transport.compare_access_control(
                target, mode=mode, test_identities=identities
            )
        else:
            raw = getattr(self._transport, tool_method)(target, mode=mode)
        normalized = self._adapter.adapt(raw, context={"target": target, "mode": mode})
        return CapabilityResult(
            success=True,
            output=[o.model_dump() for o in normalized.observations],
            metadata={
                "tool": tool_method,
                "mode": mode.value,
                "warnings": normalized.warnings,
                "error": normalized.error,
                "mock": True,
            },
        )


def build_auth_capabilities() -> list[AuthCapability]:
    """Instantiate all eleven typed auth capabilities (mock-backed)."""
    adapters = [
        AuthenticationSurfaceAdapter(),
        SessionObservationAdapter(),
        AuthSchemeDetectionAdapter(),
        OAuthMetadataAdapter(),
        OidcMetadataAdapter(),
        MfaSurfaceAdapter(),
        AuthorizationSurfaceAdapter(),
        RoleAdapter(),
        PermissionAdapter(),
        ResourceAccessAdapter(),
        AccessControlAdapter(),
    ]
    tool_methods = [
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
    ]
    return [
        AuthCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            build_auth_meta(), tool_methods, adapters, strict=True
        )
    ]
