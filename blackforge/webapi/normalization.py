from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.core.errors import WebApiNormalizationError
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
    WebApplicationObservation,
)
from blackforge.world_model.canonical import normalize_hostname, normalize_url

_STANDARD_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

_COOKIE_FLAG_SECURE = "Secure"
_COOKIE_FLAG_HTTPONLY = "HttpOnly"
_COOKIE_FLAG_SAMESITE_PREFIX = "SameSite="


class WebNormalizedOutput(BaseModel):
    """Web/api adapter result with optional transport error metadata.

    An ``error`` document is a *handled* negative outcome (rate limited,
    unreachable, throttled) — it becomes a web-api status, never a crash.
    """

    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: dict | None = None


class WebToolAdapter(ABC):
    """Boundary between mock raw output and typed web/api observations."""

    tool: str = "unknown"

    @abstractmethod
    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise WebApiNormalizationError(f"tool produced malformed JSON: {exc}") from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise WebApiNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise WebApiNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _require_int(document: dict[str, Any], field: str) -> int:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise WebApiNormalizationError(f"invalid integer field: {field}")
    return value


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise WebApiNormalizationError(f"invalid list field: {field}")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise WebApiNormalizationError(f"invalid entry in {field}")
        result.append(item.strip())
    return result


def _normalize_url_raise(value: object) -> str:
    try:
        url = normalize_url(_require_string({"url": value}, "url"))
    except (ValueError, WebApiNormalizationError) as exc:
        raise WebApiNormalizationError(f"invalid web url: {exc}") from exc
    if not url.startswith(("http://", "https://")):
        raise WebApiNormalizationError("web url must be http(s)")
    return url


def _normalize_host_raise(value: object) -> str:
    try:
        return normalize_hostname(_require_string({"host": value}, "host"))
    except (ValueError, WebApiNormalizationError) as exc:
        raise WebApiNormalizationError(f"invalid host: {exc}") from exc


def _base_output(
    document: dict[str, Any],
    *,
    observations: list[Observation],
    warnings: list[str],
) -> WebNormalizedOutput:
    if document.get("error") is not None:
        error = document["error"]
        if not isinstance(error, dict):
            raise WebApiNormalizationError("tool error must be an object")
    return WebNormalizedOutput(observations=observations, warnings=warnings)


class WebApplicationDiscoveryAdapter(WebToolAdapter):
    """Parses ``discover_web_applications`` output."""

    tool = "discover_web_applications"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("application discovery output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("apps", []):
            if not isinstance(item, dict):
                warnings.append("discarded application entry: not an object")
                continue
            try:
                url = _normalize_url_raise(item.get("url"))
                host = _normalize_host_raise(item.get("host"))
            except WebApiNormalizationError as exc:
                warnings.append(f"discarded application entry: {exc}")
                continue
            observations.append(
                WebApplicationObservation(
                    url=url,
                    host=host,
                    title=_optional_string(item.get("title")),
                    technologies=[t for t in item.get("technologies", []) if isinstance(t, str)],
                    scheme=item.get("scheme") if isinstance(item.get("scheme"), str) else "https",
                    tls_version=_optional_string(item.get("tls_version")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no web application observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class EndpointEnumerationAdapter(WebToolAdapter):
    """Parses ``enumerate_endpoints`` output."""

    tool = "enumerate_endpoints"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("endpoint enumeration output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("endpoints", []):
            if not isinstance(item, dict):
                warnings.append("discarded endpoint entry: not an object")
                continue
            try:
                url = _normalize_url_raise(item.get("url"))
                host = _normalize_host_raise(item.get("host"))
                status_code = _require_int(item, "status_code")
            except WebApiNormalizationError as exc:
                warnings.append(f"discarded endpoint entry: {exc}")
                continue
            if not 100 <= status_code <= 599:
                warnings.append(f"discarded endpoint entry: invalid status code {status_code}")
                continue
            observations.append(
                EndpointObservation(
                    url=url,
                    host=host,
                    method=item.get("method") if isinstance(item.get("method"), str) else "GET",
                    status_code=status_code,
                    content_type=_optional_string(item.get("content_type")),
                    title=_optional_string(item.get("title")),
                    scheme=item.get("scheme") if isinstance(item.get("scheme"), str) else "https",
                    tls_version=_optional_string(item.get("tls_version")),
                    http_version=_optional_string(item.get("http_version")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no endpoints observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class ApiSurfaceAdapter(WebToolAdapter):
    """Parses ``identify_api_surfaces`` output."""

    tool = "identify_api_surfaces"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("api surface discovery output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("api_surfaces", []):
            if not isinstance(item, dict):
                warnings.append("discarded api surface entry: not an object")
                continue
            try:
                url = _normalize_url_raise(item.get("url"))
                host = _normalize_host_raise(item.get("host"))
                style = _require_string(item, "style")
            except WebApiNormalizationError as exc:
                warnings.append(f"discarded api surface entry: {exc}")
                continue
            observations.append(
                ApiObservation(
                    url=url,
                    host=host,
                    style=style,
                    kind_label=_optional_string(item.get("kind")),
                    docs_url=(
                        _normalize_url_raise(item["docs_url"])
                        if isinstance(item.get("docs_url"), str) and item["docs_url"].strip()
                        else None
                    ),
                )
            )
        if not observations:
            warnings.append("no api surfaces identified")
        return _base_output(document, observations=observations, warnings=warnings)


class SecurityHeaderAdapter(WebToolAdapter):
    """Parses ``inspect_security_headers`` output into present/missing findings."""

    tool = "inspect_security_headers"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("security header output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        try:
            url = _normalize_url_raise(document.get("observed_url"))
            host = _normalize_host_raise(document.get("host"))
        except WebApiNormalizationError as exc:
            raise WebApiNormalizationError(f"security header url invalid: {exc}") from exc
        headers = document.get("headers")
        if not isinstance(headers, dict):
            raise WebApiNormalizationError("security header map must be an object")

        present = {str(k).strip().lower(): str(v) for k, v in headers.items()}
        observations: list[Observation] = []
        for header_name in _STANDARD_SECURITY_HEADERS:
            key = header_name.lower()
            if key in present:
                observations.append(
                    SecurityHeaderObservation(
                        url=url,
                        host=host,
                        header_name=header_name,
                        present=True,
                        finding="present",
                        value=present[key],
                    )
                )
            else:
                observations.append(
                    SecurityHeaderObservation(
                        url=url,
                        host=host,
                        header_name=header_name,
                        present=False,
                        finding="missing",
                    )
                )
        warnings: list[str] = []
        if not observations:
            warnings.append("no security headers observed")
        return _base_output(document, observations=observations, warnings=warnings)


class CookieAdapter(WebToolAdapter):
    """Parses ``inspect_cookies`` output (values already hashed by the mock)."""

    tool = "inspect_cookies"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("cookie inspection output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        try:
            url = _normalize_url_raise(document.get("observed_url"))
            host = _normalize_host_raise(document.get("host"))
        except WebApiNormalizationError as exc:
            raise WebApiNormalizationError(f"cookie observation url invalid: {exc}") from exc

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("cookies", []):
            if not isinstance(item, dict):
                warnings.append("discarded cookie entry: not an object")
                continue
            try:
                name = _require_string(item, "name")
            except WebApiNormalizationError as exc:
                warnings.append(f"discarded cookie entry: {exc}")
                continue
            flags = [f for f in item.get("flags", []) if isinstance(f, str)]
            observations.append(
                CookieObservation(
                    url=url,
                    host=host,
                    name=name,
                    value_hashed=_optional_string(item.get("value_hashed")),
                    domain=_optional_string(item.get("domain")),
                    path=_optional_string(item.get("path")),
                    flags=flags,
                    secure=_COOKIE_FLAG_SECURE in flags,
                    httponly=_COOKIE_FLAG_HTTPONLY in flags,
                    samesite=next(
                        (
                            f[len(_COOKIE_FLAG_SAMESITE_PREFIX):]
                            for f in flags
                            if f.startswith(_COOKIE_FLAG_SAMESITE_PREFIX)
                        ),
                        None,
                    ),
                )
            )
        if not observations:
            warnings.append("no cookies observed")
        return _base_output(document, observations=observations, warnings=warnings)


class CorsAdapter(WebToolAdapter):
    """Parses ``analyze_cors`` output."""

    tool = "analyze_cors"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("cors analysis output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        try:
            url = _normalize_url_raise(document.get("observed_url"))
            host = _normalize_host_raise(document.get("host"))
        except WebApiNormalizationError as exc:
            raise WebApiNormalizationError(f"cors observation url invalid: {exc}") from exc

        cors = document.get("cors")
        if cors is None:
            return _base_output(
                document,
                observations=[],
                warnings=["no CORS policy observed"],
            )
        if not isinstance(cors, dict):
            raise WebApiNormalizationError("cors entry must be an object or null")

        allow_origins = [o for o in cors.get("allow_origins", []) if isinstance(o, str)]
        allow_methods = [m for m in cors.get("allow_methods", []) if isinstance(m, str)]
        allow_headers = [h for h in cors.get("allow_headers", []) if isinstance(h, str)]
        expose_headers = [h for h in cors.get("expose_headers", []) if isinstance(h, str)]
        observations = [
            CorsObservation(
                url=url,
                host=host,
                allow_origins=allow_origins,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                expose_headers=expose_headers,
                allow_credentials=bool(cors.get("allow_credentials", False)),
                wildcard_origin="*" in allow_origins,
                note=_optional_string(cors.get("note")),
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


class AuthSurfaceAdapter(WebToolAdapter):
    """Parses ``inspect_authentication`` output (surface inventory only)."""

    tool = "inspect_authentication"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("authentication inspection output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        try:
            url = _normalize_url_raise(document.get("observed_url"))
            host = _normalize_host_raise(document.get("host"))
        except WebApiNormalizationError as exc:
            raise WebApiNormalizationError(
                f"authentication observation url invalid: {exc}"
            ) from exc

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("schemes", []):
            if not isinstance(item, dict):
                warnings.append("discarded auth scheme entry: not an object")
                continue
            try:
                scheme = _require_string(item, "scheme")
            except WebApiNormalizationError as exc:
                warnings.append(f"discarded auth scheme entry: {exc}")
                continue
            observations.append(
                AuthSurfaceObservation(
                    url=url,
                    host=host,
                    scheme=scheme,
                    scheme_type=_optional_string(item.get("type")),
                    parameter_name=_optional_string(item.get("parameter_name")),
                    note="auth surface observed; no credentials exercised",
                )
            )
        if not observations:
            warnings.append("no authentication surfaces observed")
        return _base_output(document, observations=observations, warnings=warnings)


class OpenApiAdapter(WebToolAdapter):
    """Parses ``parse_openapi`` output into a document summary."""

    tool = "parse_openapi"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("openapi review output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        try:
            url = _normalize_url_raise(document.get("observed_url"))
            host = _normalize_host_raise(document.get("host"))
        except WebApiNormalizationError as exc:
            raise WebApiNormalizationError(f"openapi observation url invalid: {exc}") from exc

        spec = document.get("document")
        if spec is None:
            return _base_output(
                document,
                observations=[],
                warnings=["no OpenAPI document observed"],
            )
        if not isinstance(spec, dict):
            raise WebApiNormalizationError("openapi document must be an object or null")

        info = spec.get("info")
        paths = spec.get("paths")
        security_schemes = _collect_security_schemes(spec)
        operation_count = _count_operations(paths) if isinstance(paths, dict) else 0
        path_count = len(paths) if isinstance(paths, dict) else 0
        observations = [
            OpenApiObservation(
                url=url,
                host=host,
                spec_version=_optional_string(spec.get("openapi"))
                or _optional_string(spec.get("swagger")),
                document_title=(
                    _optional_string(info.get("title"))
                    if isinstance(info, dict)
                    else None
                ),
                operation_count=operation_count,
                path_count=path_count,
                security_schemes=security_schemes,
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


def _collect_security_schemes(spec: dict[str, Any]) -> list[str]:
    components = spec.get("components")
    if not isinstance(components, dict):
        return []
    schemes = components.get("securitySchemes")
    if not isinstance(schemes, dict):
        return []
    collected: list[str] = []
    for name, details in schemes.items():
        if isinstance(details, dict) and isinstance(details.get("type"), str):
            collected.append(f"{name}:{details['type']}")
        else:
            collected.append(str(name))
    return collected


def _int_or_len(value: object) -> int:
    """Return an integer count for either an int field or a sequence field."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple, set, frozenset, dict)):
        return len(value)
    return 0


def _count_operations(paths: dict[str, Any]) -> int:
    count = 0
    for methods in paths.values():
        if isinstance(methods, dict):
            count += sum(
                1
                for key in methods
                if key in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
            )
    return count


class GraphQlAdapter(WebToolAdapter):
    """Parses ``discover_graphql`` output into schema surface metadata."""

    tool = "discover_graphql"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("graphql discovery output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        try:
            url = _normalize_url_raise(document.get("observed_url"))
            host = _normalize_host_raise(document.get("host"))
        except WebApiNormalizationError as exc:
            raise WebApiNormalizationError(f"graphql observation url invalid: {exc}") from exc

        graphql = document.get("graphql")
        if graphql is None:
            return _base_output(
                document,
                observations=[],
                warnings=["no GraphQL endpoint observed"],
            )
        if not isinstance(graphql, dict):
            raise WebApiNormalizationError("graphql entry must be an object or null")

        observations = [
            GraphQlObservation(
                url=url,
                host=host,
                introspection_enabled=bool(graphql.get("introspection", False)),
                type_count=_int_or_len(graphql.get("types", 0)),
                query_count=_int_or_len(graphql.get("queries", 0)),
                mutation_count=_int_or_len(graphql.get("mutations", 0)),
                operation_names=[
                    n for n in graphql.get("operation_names", []) if isinstance(n, str)
                ],
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


class RequestResponseAdapter(WebToolAdapter):
    """Parses ``observe_request_response`` output (GET-only, headers redacted)."""

    tool = "observe_request_response"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> WebNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise WebApiNormalizationError("request/response output must be a dict")
        if document.get("error") is not None:
            if not isinstance(document["error"], dict):
                raise WebApiNormalizationError("tool error must be an object")
            return WebNormalizedOutput(observations=[], warnings=[], error=dict(document["error"]))

        try:
            host = _normalize_host_raise(document.get("host"))
        except WebApiNormalizationError as exc:
            raise WebApiNormalizationError(f"request/response url invalid: {exc}") from exc

        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("responses", []):
            if not isinstance(item, dict):
                warnings.append("discarded response entry: not an object")
                continue
            try:
                url = _normalize_url_raise(item.get("url"))
            except WebApiNormalizationError as exc:
                warnings.append(f"discarded response entry: {exc}")
                continue
            headers = item.get("headers")
            observations.append(
                RequestOutcomeObservation(
                    url=url,
                    host=host,
                    method=(
                        item.get("method")
                        if isinstance(item.get("method"), str)
                        else "GET"
                    ),
                    status_code=item.get("status_code")
                    if isinstance(item.get("status_code"), int)
                    else None,
                    http_version=_optional_string(item.get("http_version")),
                    tls_version=_optional_string(item.get("tls_version")),
                    server_header=_optional_string(item.get("server_header")),
                    content_type=_optional_string(item.get("content_type")),
                    rtt_ms=item.get("rtt_ms") if isinstance(item.get("rtt_ms"), int) else None,
                    redacted_headers=headers if isinstance(headers, dict) else {},
                )
            )
        if not observations:
            warnings.append("no request/response pairs observed")
        return _base_output(document, observations=observations, warnings=warnings)


def adapter_for_tool(tool: str) -> WebToolAdapter:
    """Return the adapter registered for a tool name."""
    mapping: dict[str, WebToolAdapter] = {
        "discover_web_applications": WebApplicationDiscoveryAdapter(),
        "enumerate_endpoints": EndpointEnumerationAdapter(),
        "identify_api_surfaces": ApiSurfaceAdapter(),
        "inspect_security_headers": SecurityHeaderAdapter(),
        "inspect_cookies": CookieAdapter(),
        "analyze_cors": CorsAdapter(),
        "inspect_authentication": AuthSurfaceAdapter(),
        "parse_openapi": OpenApiAdapter(),
        "discover_graphql": GraphQlAdapter(),
        "observe_request_response": RequestResponseAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise WebApiNormalizationError(f"no adapter for tool: {tool}")
    return adapter
