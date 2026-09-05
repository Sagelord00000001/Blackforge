from __future__ import annotations

from pydantic import Field

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType
from blackforge.webapi.mock import MockWebTransport
from blackforge.webapi.models import WebApiMode, WebObservationKind
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
    WebToolAdapter,
)

WEBAPI_CAPABILITY_IDS = [
    "webapi.application_discovery",
    "webapi.endpoint_enumeration",
    "webapi.api_surface_discovery",
    "webapi.security_header_analysis",
    "webapi.cookie_analysis",
    "webapi.cors_analysis",
    "webapi.auth_surface_observation",
    "webapi.openapi_review",
    "webapi.graphql_discovery",
    "webapi.request_response_observation",
]


class WebApiCapabilityMeta(CapabilityMeta):
    """Capability metadata extended for web/api security capabilities."""

    category: str = "web_security"
    mode: WebApiMode = WebApiMode.PASSIVE
    produces: list[WebObservationKind] = Field(default_factory=list)
    world_model: bool = True


def _meta(
    capability_id: str,
    description: str,
    risk_level: RiskLevel,
    mode: WebApiMode,
    supported_target_types: list[TargetType],
    produces: list[WebObservationKind],
    *,
    version: str = "1.0.0",
) -> WebApiCapabilityMeta:
    return WebApiCapabilityMeta(
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


def build_webapi_meta() -> list[WebApiCapabilityMeta]:
    """Metadata for all ten typed web/api security capabilities."""
    return [
        _meta(
            "webapi.application_discovery",
            "Discover web applications hosted on the authorized target.",
            RiskLevel.LOW,
            WebApiMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.APPLICATION],
        ),
        _meta(
            "webapi.endpoint_enumeration",
            "Enumerate reachable web endpoints (paths/methods) on the target.",
            RiskLevel.MEDIUM,
            WebApiMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.ENDPOINT],
        ),
        _meta(
            "webapi.api_surface_discovery",
            "Identify API surfaces (REST, OpenAPI, GraphQL) on the target.",
            RiskLevel.LOW,
            WebApiMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.API],
        ),
        _meta(
            "webapi.security_header_analysis",
            "Record security-related response headers (present/missing) on the target.",
            RiskLevel.LOW,
            WebApiMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.SECURITY_HEADER],
        ),
        _meta(
            "webapi.cookie_analysis",
            "Record cookie flags and metadata (raw values never stored) on the target.",
            RiskLevel.LOW,
            WebApiMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.COOKIE],
        ),
        _meta(
            "webapi.cors_analysis",
            "Summarize the target's CORS configuration without cross-origin probing.",
            RiskLevel.LOW,
            WebApiMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.CORS],
        ),
        _meta(
            "webapi.auth_surface_observation",
            "Inventory authentication surfaces exposed by the target.",
            RiskLevel.LOW,
            WebApiMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.AUTH_SURFACE],
        ),
        _meta(
            "webapi.openapi_review",
            "Summarize an OpenAPI/Swagger document served by the target.",
            RiskLevel.LOW,
            WebApiMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.OPENAPI],
        ),
        _meta(
            "webapi.graphql_discovery",
            "Record GraphQL endpoint metadata (schema shape, never introspection content).",
            RiskLevel.LOW,
            WebApiMode.PASSIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.GRAPHQL],
        ),
        _meta(
            "webapi.request_response_observation",
            "Capture plain GET request/response metadata for the target.",
            RiskLevel.MEDIUM,
            WebApiMode.ACTIVE,
            [TargetType.DOMAIN, TargetType.IP, TargetType.URL],
            [WebObservationKind.REQUEST_RESPONSE],
        ),
    ]


class WebApiCapability(Capability):
    """A typed web/api security capability bound to a mock transport method.

    ``execute`` runs the deterministic mock transport through the
    normalization adapter and returns normalized observations. It performs no
    authorization itself — the :class:`WebApiEngine` enforces
    scope/authorization before any execution path reaches the mock.
    """

    def __init__(
        self,
        meta: WebApiCapabilityMeta,
        tool_method: str,
        adapter: WebToolAdapter,
    ) -> None:
        self._meta = meta
        self._tool_method = tool_method
        self._adapter = adapter
        self._transport = MockWebTransport()

    def meta(self) -> WebApiCapabilityMeta:
        return self._meta

    @property
    def capability_id(self) -> str:
        return self._meta.name

    @property
    def tool_method(self) -> str:
        return self._tool_method

    @property
    def adapter(self) -> WebToolAdapter:
        return self._adapter

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        mode_param = params.get("mode") if params else None
        mode = WebApiMode(mode_param) if mode_param else self._meta.mode
        raw = getattr(self._transport, self._tool_method)(target, mode=mode)
        normalized = self._adapter.adapt(raw, context={"target": target, "mode": mode})
        return CapabilityResult(
            success=True,
            output=[o.model_dump() for o in normalized.observations],
            metadata={
                "tool": self._tool_method,
                "mode": mode.value,
                "warnings": normalized.warnings,
                "error": normalized.error,
                "mock": True,
            },
        )


def build_webapi_capabilities() -> list[WebApiCapability]:
    """Instantiate all ten typed web/api capabilities (mock-backed)."""
    adapters = [
        WebApplicationDiscoveryAdapter(),
        EndpointEnumerationAdapter(),
        ApiSurfaceAdapter(),
        SecurityHeaderAdapter(),
        CookieAdapter(),
        CorsAdapter(),
        AuthSurfaceAdapter(),
        OpenApiAdapter(),
        GraphQlAdapter(),
        RequestResponseAdapter(),
    ]
    tool_methods = [
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
    ]
    return [
        WebApiCapability(meta, tool_method, adapter)
        for meta, tool_method, adapter in zip(
            build_webapi_meta(), tool_methods, adapters, strict=True
        )
    ]
