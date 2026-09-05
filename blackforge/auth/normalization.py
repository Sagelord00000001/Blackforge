from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.auth.models import (
    AccessControlObservation,
    AuthAccess,
    AuthenticationSchemeObservation,
    AuthorizationSurfaceObservation,
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
from blackforge.auth.redaction import credential_value_redacted
from blackforge.core.errors import AuthNormalizationError
from blackforge.world_model.canonical import normalize_hostname, normalize_url


class AuthNormalizedOutput(BaseModel):
    """Auth adapter result with optional transport error metadata.

    An ``error`` document is a *handled* negative outcome (rate limited,
    unreachable, throttled) — it becomes an auth status, never a crash.
    """

    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: dict | None = None


class AuthToolAdapter(ABC):
    """Boundary between mock raw output and typed auth observations."""

    tool: str = "unknown"

    @abstractmethod
    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise AuthNormalizationError(f"tool produced malformed JSON: {exc}") from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise AuthNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AuthNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise AuthNormalizationError(f"invalid list field: {field}")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise AuthNormalizationError(f"invalid entry in {field}")
        result.append(item.strip())
    return result


def _normalize_url_raise(value: object) -> str:
    try:
        url = normalize_url(_require_string({"url": value}, "url"))
    except (ValueError, AuthNormalizationError) as exc:
        raise AuthNormalizationError(f"invalid url: {exc}") from exc
    if not url.startswith(("http://", "https://")):
        raise AuthNormalizationError("url must be http(s)")
    return url


def _normalize_host_raise(value: object) -> str:
    try:
        return normalize_hostname(_require_string({"host": value}, "host"))
    except (ValueError, AuthNormalizationError) as exc:
        raise AuthNormalizationError(f"invalid host: {exc}") from exc


def _base_output(
    document: dict[str, Any],
    *,
    observations: list[Observation],
    warnings: list[str],
) -> AuthNormalizedOutput:
    if document.get("error") is not None:
        error = document["error"]
        if not isinstance(error, dict):
            raise AuthNormalizationError("tool error must be an object")
    return AuthNormalizedOutput(observations=observations, warnings=warnings)


def _error_output(document: dict[str, Any]) -> AuthNormalizedOutput:
    error = document.get("error")
    if not isinstance(error, dict):
        raise AuthNormalizationError("tool error must be an object")
    return AuthNormalizedOutput(observations=[], warnings=[], error=dict(error))


def _require_url_host(document: dict[str, Any]) -> tuple[str, str]:
    try:
        url = _normalize_url_raise(document.get("observed_url"))
        host = _normalize_host_raise(document.get("host"))
    except AuthNormalizationError as exc:
        raise AuthNormalizationError(f"observation url invalid: {exc}") from exc
    return url, host


def _access_from_document(value: object) -> AuthAccess:
    """Strict literal access parse: never derive DENIED/ALLOWED by inference.

    Only explicit ``allowed``/``denied`` literals grant validated outcomes;
    any other literal (or a network-shaped marker) falls through to UNKNOWN /
    ERROR / NOT_TESTED so a redirect or probe failure can never look like a
    real access decision.
    """
    if not isinstance(value, str):
        return AuthAccess.UNKNOWN
    try:
        parsed = AuthAccess(value.strip().lower())
    except ValueError:
        return AuthAccess.UNKNOWN
    if parsed in {AuthAccess.ALLOWED, AuthAccess.DENIED, AuthAccess.ERROR, AuthAccess.NOT_TESTED}:
        return parsed
    return AuthAccess.UNKNOWN


class AuthenticationSurfaceAdapter(AuthToolAdapter):
    """Parses ``observe_authentication_surface`` output."""

    tool = "observe_authentication_surface"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("authentication surface output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("schemes", []):
            if not isinstance(item, dict):
                warnings.append("discarded auth scheme entry: not an object")
                continue
            try:
                scheme = _require_string(item, "scheme")
            except AuthNormalizationError as exc:
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
            note = _optional_string(document.get("note")) or "no auth surface observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class SessionObservationAdapter(AuthToolAdapter):
    """Parses ``observe_session_details`` output (values already hashed)."""

    tool = "observe_session_details"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("session observation output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("sessions", []):
            if not isinstance(item, dict):
                warnings.append("discarded session entry: not an object")
                continue
            try:
                name = _require_string(item, "name")
            except AuthNormalizationError as exc:
                warnings.append(f"discarded session entry: {exc}")
                continue
            flags = [f for f in item.get("flags", []) if isinstance(f, str)]
            observations.append(
                SessionObservation(
                    url=url,
                    host=host,
                    name=name,
                    value_hashed=_optional_string(item.get("value_hashed")),
                    domain=_optional_string(item.get("domain")),
                    path=_optional_string(item.get("path")),
                    flags=flags,
                    secure=bool(item.get("secure", False)),
                    httponly=bool(item.get("httponly", False)),
                    samesite=_optional_string(item.get("samesite")),
                    expires=_optional_string(item.get("expires")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no sessions observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class AuthSchemeDetectionAdapter(AuthToolAdapter):
    """Parses ``detect_authentication_schemes`` output."""

    tool = "detect_authentication_schemes"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("authentication scheme output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("schemes_detected", []):
            if not isinstance(item, dict):
                warnings.append("discarded scheme entry: not an object")
                continue
            try:
                scheme = _require_string(item, "scheme")
            except AuthNormalizationError as exc:
                warnings.append(f"discarded scheme entry: {exc}")
                continue
            observations.append(
                AuthenticationSchemeObservation(
                    url=url,
                    host=host,
                    scheme=scheme,
                    present=bool(item.get("present", True)),
                    password_policy=_optional_string(item.get("password_policy")),
                    password_policy_observed=bool(
                        item.get("password_policy_observed", False)
                    ),
                    session_timeout_minutes=(
                        item.get("session_timeout_minutes")
                        if isinstance(item.get("session_timeout_minutes"), int)
                        else None
                    ),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no auth schemes detected"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class OAuthMetadataAdapter(AuthToolAdapter):
    """Parses ``observe_oauth_metadata`` output."""

    tool = "observe_oauth_metadata"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("oauth metadata output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        oauth = document.get("oauth")
        if oauth is None:
            return _base_output(
                document,
                observations=[],
                warnings=["no OAuth2 metadata observed"],
            )
        if not isinstance(oauth, dict):
            raise AuthNormalizationError("oauth entry must be an object or null")
        observations: list[Observation] = [
            OAuthMetadataObservation(
                url=url,
                host=host,
                authorization_endpoint=_optional_string(
                    oauth.get("authorization_endpoint")
                ),
                token_endpoint=_optional_string(oauth.get("token_endpoint")),
                grant_types=_string_list(oauth.get("grant_types", []), "grant_types"),
                scopes=_string_list(oauth.get("scopes", []), "scopes"),
                pkce_supported=bool(oauth.get("pkce_supported", False)),
                note=_optional_string(oauth.get("note")),
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


class OidcMetadataAdapter(AuthToolAdapter):
    """Parses ``observe_oidc_metadata`` output."""

    tool = "observe_oidc_metadata"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("oidc metadata output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        oidc = document.get("oidc")
        if oidc is None:
            return _base_output(
                document,
                observations=[],
                warnings=["no OIDC metadata observed"],
            )
        if not isinstance(oidc, dict):
            raise AuthNormalizationError("oidc entry must be an object or null")
        observations: list[Observation] = [
            OidcMetadataObservation(
                url=url,
                host=host,
                issuer=_optional_string(oidc.get("issuer")),
                jwks_uri=_optional_string(oidc.get("jwks_uri")),
                discovery_url=_optional_string(oidc.get("discovery_url")),
                userinfo_endpoint=_optional_string(oidc.get("userinfo_endpoint")),
                subject_type=_optional_string(oidc.get("subject_type")),
                id_token_signing_alg=_optional_string(oidc.get("id_token_signing_alg")),
                note=_optional_string(oidc.get("note")),
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


class MfaSurfaceAdapter(AuthToolAdapter):
    """Parses ``observe_mfa_surface`` output."""

    tool = "observe_mfa_surface"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("mfa surface output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        mfa = document.get("mfa")
        if mfa is None:
            return _base_output(
                document,
                observations=[],
                warnings=["MFA posture not observed"],
            )
        if not isinstance(mfa, dict):
            raise AuthNormalizationError("mfa entry must be an object or null")

        raw_status = mfa.get("status")
        if isinstance(raw_status, str):
            try:
                status = MfaStatus(raw_status.strip().lower())
            except ValueError:
                status = MfaStatus.UNKNOWN
        elif isinstance(raw_status, MfaStatus):
            status = raw_status
        else:
            status = MfaStatus.UNKNOWN
        prompt = mfa.get("prompt_observed")
        prompt_observed = None
        if isinstance(prompt, bool):
            prompt_observed = prompt
        observations: list[Observation] = [
            MfaSurfaceObservation(
                url=url,
                host=host,
                mfa_status=status,
                factors=[f for f in mfa.get("factors", []) if isinstance(f, str)],
                prompt_observed=prompt_observed,
                note=_optional_string(mfa.get("note")),
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


class AuthorizationSurfaceAdapter(AuthToolAdapter):
    """Parses ``observe_authorization_surface`` output."""

    tool = "observe_authorization_surface"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("authorization surface output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        authorization = document.get("authorization_model")
        if authorization is None or not isinstance(authorization, dict):
            return _base_output(
                document,
                observations=[],
                warnings=["authorization model not observed"],
            )
        observations: list[Observation] = [
            AuthorizationSurfaceObservation(
                url=url,
                host=host,
                authz_model=_optional_string(authorization.get("model")) or "unknown",
                enforcement=_optional_string(authorization.get("enforcement")),
                note=_optional_string(authorization.get("note")),
            )
        ]
        return _base_output(document, observations=observations, warnings=[])


class RoleAdapter(AuthToolAdapter):
    """Parses ``observe_roles`` output."""

    tool = "observe_roles"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("role observation output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("roles", []):
            if not isinstance(item, dict):
                warnings.append("discarded role entry: not an object")
                continue
            try:
                role = _require_string(item, "name")
            except AuthNormalizationError as exc:
                warnings.append(f"discarded role entry: {exc}")
                continue
            observations.append(
                RoleObservation(
                    url=url,
                    host=host,
                    role=role,
                    description=_optional_string(item.get("description")),
                    scope=_optional_string(item.get("scope")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no roles observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class PermissionAdapter(AuthToolAdapter):
    """Parses ``observe_permissions`` output.

    ``credential_value`` is forced to the ``REDACTED`` marker regardless of
    transport output (defense in depth): raw credential material can never
    reach a typed observation.
    """

    tool = "observe_permissions"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("permission observation output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("permissions", []):
            if not isinstance(item, dict):
                warnings.append("discarded permission entry: not an object")
                continue
            try:
                permission = _require_string(item, "permission")
            except AuthNormalizationError as exc:
                warnings.append(f"discarded permission entry: {exc}")
                continue
            observations.append(
                PermissionObservation(
                    url=url,
                    host=host,
                    identity=_optional_string(item.get("identity")),
                    role=_optional_string(item.get("role")),
                    permission=permission,
                    resource=_optional_string(item.get("resource")),
                    granted=bool(item.get("granted", False)),
                    credential_used=bool(item.get("credential_used", False)),
                    credential_type=_optional_string(item.get("credential_type")),
                    credential_value=credential_value_redacted(),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = _optional_string(document.get("note")) or "no permissions observed"
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class ResourceAccessAdapter(AuthToolAdapter):
    """Parses ``observe_resource_access`` output (validated access only).

    ``access`` is a strict literal parse; ALLOWED/DENIED are never derived
    from redirects or network states. ``credential_value`` is always the
    ``REDACTED`` marker.
    """

    tool = "observe_resource_access"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("resource access output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("access", []):
            if not isinstance(item, dict):
                warnings.append("discarded access entry: not an object")
                continue
            try:
                resource = _require_string(item, "resource")
            except AuthNormalizationError as exc:
                warnings.append(f"discarded access entry: {exc}")
                continue
            observations.append(
                ResourceAccessObservation(
                    url=url,
                    host=host,
                    identity=_optional_string(item.get("identity")),
                    role=_optional_string(item.get("role")),
                    resource=resource,
                    access=_access_from_document(item.get("access")),
                    credential_used=bool(item.get("credential_used", False)),
                    credential_type=_optional_string(item.get("credential_type")),
                    credential_value=credential_value_redacted(),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = (
                _optional_string(document.get("note"))
                or "no controlled access observations"
            )
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


class AccessControlAdapter(AuthToolAdapter):
    """Parses ``compare_access_control`` output (expected vs observed)."""

    tool = "compare_access_control"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> AuthNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise AuthNormalizationError("access control comparison output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        url, host = _require_url_host(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in document.get("comparisons", []):
            if not isinstance(item, dict):
                warnings.append("discarded comparison entry: not an object")
                continue
            try:
                resource = _require_string(item, "resource")
            except AuthNormalizationError as exc:
                warnings.append(f"discarded comparison entry: {exc}")
                continue
            access = _access_from_document(item.get("access"))
            expected = _access_from_document(item.get("expected_access"))
            observations.append(
                AccessControlObservation(
                    url=url,
                    host=host,
                    identity=_optional_string(item.get("identity")),
                    role=_optional_string(item.get("role")),
                    resource=resource,
                    access=access,
                    expected_access=expected,
                    consistent=bool(item.get("consistent", False)),
                    credential_used=bool(item.get("credential_used", False)),
                    credential_type=_optional_string(item.get("credential_type")),
                    credential_value=credential_value_redacted(),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            note = (
                _optional_string(document.get("note"))
                or "no access control comparisons"
            )
            warnings.append(note)
        return _base_output(document, observations=observations, warnings=warnings)


def adapter_for_tool(tool: str) -> AuthToolAdapter:
    """Return the adapter registered for a tool name."""
    mapping: dict[str, AuthToolAdapter] = {
        "observe_authentication_surface": AuthenticationSurfaceAdapter(),
        "observe_session_details": SessionObservationAdapter(),
        "detect_authentication_schemes": AuthSchemeDetectionAdapter(),
        "observe_oauth_metadata": OAuthMetadataAdapter(),
        "observe_oidc_metadata": OidcMetadataAdapter(),
        "observe_mfa_surface": MfaSurfaceAdapter(),
        "observe_authorization_surface": AuthorizationSurfaceAdapter(),
        "observe_roles": RoleAdapter(),
        "observe_permissions": PermissionAdapter(),
        "observe_resource_access": ResourceAccessAdapter(),
        "compare_access_control": AccessControlAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise AuthNormalizationError(f"no adapter for tool: {tool}")
    return adapter
