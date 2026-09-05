from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse

from blackforge.auth.models import AuthAccess, AuthMode, MfaStatus
from blackforge.auth.redaction import (
    credential_value_redacted,
    redact_credential_fields,
    redact_nested_credential_values,
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _marker(value: str) -> str:
    return f"REDACTED:{_hash(value)[:16]}"


_DEMO_AUTH: dict[str, dict[str, Any]] = {
    "web.example.com": {
        "ip": "192.0.2.20",
        "url": "https://web.example.com/",
        "title": "Example Web Server",
        "schemes": [
            {
                "scheme": "session_cookie",
                "type": "cookie_session",
                "parameter_name": "session",
                "note": "server-side session cookie; login page redirects unauthenticated users",
            }
        ],
        "schemes_detected": [
            {
                "scheme": "session_cookie",
                "present": True,
                "password_policy": "min_length=8;complexity=required;pw_reuse_disallowed",
                "password_policy_observed": True,
                "session_timeout_minutes": 30,
                "note": "cookie session with explicit idle timeout observed",
            }
        ],
        "sessions": [
            {
                "name": "session",
                "value_hashed": _hash("mock-session-web"),
                "domain": "web.example.com",
                "path": "/",
                "flags": ["HttpOnly", "Secure", "SameSite=Lax"],
                "secure": True,
                "httponly": True,
                "samesite": "Lax",
                "expires": "30m",
                "note": "session properties only; value hashed",
            }
        ],
        "oauth": None,
        "oidc": None,
        "mfa": {
            "status": MfaStatus.OBSERVED.value,
            "factors": ["totp", "email_otp"],
            "prompt_observed": True,
            "note": "MFA prompt observed on login; totp and email one-time codes",
        },
        "authorization": {
            "model": "role_based",
            "enforcement": "declarative",
            "note": "RBAC enforced server-side on session identity",
        },
        "roles": [
            {
                "name": "viewer",
                "description": "read-only access to public and project content",
                "scope": "web.example.com",
            },
            {
                "name": "editor",
                "description": "can create and update content",
                "scope": "web.example.com",
            },
        ],
        "permissions": [
            {
                "identity": "alice",
                "role": "editor",
                "permission": "create",
                "resource": "reports",
                "granted": True,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
            },
            {
                "identity": "alice",
                "role": "editor",
                "permission": "update",
                "resource": "reports",
                "granted": True,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
            },
            {
                "identity": "alice",
                "role": "editor",
                "permission": "delete",
                "resource": "reports",
                "granted": False,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
            },
            {
                "identity": "bob",
                "role": "viewer",
                "permission": "read",
                "resource": "reports",
                "granted": True,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
            },
            {
                "identity": "bob",
                "role": "viewer",
                "permission": "update",
                "resource": "reports",
                "granted": False,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
            },
        ],
        "access": [
            {
                "identity": "alice",
                "role": "editor",
                "resource": "reports",
                "access": AuthAccess.ALLOWED.value,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
                "note": "validated with authorized test identity",
            },
            {
                "identity": "alice",
                "role": "editor",
                "resource": "admin_panel",
                "access": AuthAccess.DENIED.value,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
                "note": "validated with authorized test identity",
            },
            {
                "identity": "bob",
                "role": "viewer",
                "resource": "reports",
                "access": AuthAccess.DENIED.value,
                "credential_used": True,
                "credential_type": "session_cookie",
                "credential_value": credential_value_redacted(),
                "note": "viewer may read reports content but not the reports admin surface",
            },
            {
                "identity": "charlie",
                "role": None,
                "resource": "reports",
                "access": AuthAccess.UNKNOWN.value,
                "credential_used": False,
                "credential_type": None,
                "credential_value": credential_value_redacted(),
                "note": "uncontrolled identity; access never exercised",
            },
            {
                "identity": "dave",
                "role": "editor",
                "resource": "billing",
                "access": AuthAccess.NOT_TESTED.value,
                "credential_used": False,
                "credential_type": None,
                "credential_value": credential_value_redacted(),
                "note": "not exercised for this identity/resource pair",
            },
        ],
        "expected_access": {
            "alice": {"reports": "allowed", "admin_panel": "denied"},
            "bob": {"reports": "denied"},
        },
    },
    "api.example.com": {
        "ip": "192.0.2.22",
        "url": "https://api.example.com/",
        "title": "Example API",
        "schemes": [
            {
                "scheme": "bearer",
                "type": "oauth_bearer",
                "parameter_name": "Authorization",
                "note": "OAuth2 bearer tokens",
            },
            {
                "scheme": "api_key",
                "type": "api_key",
                "parameter_name": "X-API-Key",
                "note": "API key header",
            },
        ],
        "schemes_detected": [
            {
                "scheme": "bearer",
                "present": True,
                "password_policy": None,
                "password_policy_observed": False,
                "session_timeout_minutes": None,
                "note": "OAuth2 bearer tokens; no password prompt exposed",
            },
            {
                "scheme": "api_key",
                "present": True,
                "password_policy": None,
                "password_policy_observed": False,
                "session_timeout_minutes": None,
                "note": "API key header authentication",
            },
        ],
        "sessions": [],
        "oauth": {
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token",
            "grant_types": ["authorization_code", "client_credentials"],
            "scopes": ["reports:read", "reports:write"],
            "pkce_supported": True,
            "note": "OAuth2 authorization server metadata observed",
        },
        "oidc": {
            "issuer": "https://auth.example.com/",
            "jwks_uri": "https://auth.example.com/oidc/keys",
            "discovery_url": "https://auth.example.com/.well-known/openid-configuration",
            "userinfo_endpoint": "https://auth.example.com/oidc/userinfo",
            "subject_type": "public",
            "id_token_signing_alg": "RS256",
            "note": "OIDC discovery document observed",
        },
        "mfa": {
            "status": MfaStatus.NOT_OBSERVED.value,
            "factors": [],
            "prompt_observed": False,
            "note": "no MFA prompt exposed on the machine-to-machine API surface",
        },
        "authorization": {
            "model": "role_based",
            "enforcement": "declarative",
            "note": "scope-based RBAC on bearer tokens",
        },
        "roles": [
            {
                "name": "service_account",
                "description": "machine-to-machine API access",
                "scope": "api.example.com",
            }
        ],
        "permissions": [
            {
                "identity": "svc-reports",
                "role": "service_account",
                "permission": "read",
                "resource": "reports_api",
                "granted": True,
                "credential_used": True,
                "credential_type": "bearer_token",
                "credential_value": credential_value_redacted(),
            },
            {
                "identity": "svc-reports",
                "role": "service_account",
                "permission": "write",
                "resource": "reports_api",
                "granted": False,
                "credential_used": True,
                "credential_type": "bearer_token",
                "credential_value": credential_value_redacted(),
            },
        ],
        "access": [
            {
                "identity": "svc-reports",
                "role": "service_account",
                "resource": "reports_api",
                "access": AuthAccess.ALLOWED.value,
                "credential_used": True,
                "credential_type": "bearer_token",
                "credential_value": credential_value_redacted(),
                "note": "validated with authorized test service identity",
            },
            {
                "identity": "svc-reports",
                "role": "service_account",
                "resource": "admin_api",
                "access": AuthAccess.DENIED.value,
                "credential_used": True,
                "credential_type": "bearer_token",
                "credential_value": credential_value_redacted(),
                "note": "validated with authorized test service identity",
            },
            {
                "identity": "guest",
                "role": None,
                "resource": "reports_api",
                "access": AuthAccess.UNKNOWN.value,
                "credential_used": False,
                "credential_type": None,
                "credential_value": credential_value_redacted(),
                "note": "uncontrolled identity; access never exercised",
            },
        ],
        "expected_access": {
            "svc-reports": {"reports_api": "allowed", "admin_api": "denied"}
        },
    },
    "auth.example.com": {
        "ip": "192.0.2.23",
        "url": "https://auth.example.com/",
        "title": "Example Identity Provider",
        "schemes": [
            {
                "scheme": "sso",
                "type": "single_sign_on",
                "parameter_name": None,
                "note": "SSO entry point",
            },
            {
                "scheme": "oidc",
                "type": "openid_connect",
                "parameter_name": None,
                "note": "OIDC provider",
            },
        ],
        "schemes_detected": [
            {
                "scheme": "sso",
                "present": True,
                "password_policy": "min_length=12;complexity=required",
                "password_policy_observed": True,
                "session_timeout_minutes": None,
                "note": "SSO entry point with published password policy",
            },
            {
                "scheme": "oidc",
                "present": True,
                "password_policy": None,
                "password_policy_observed": False,
                "session_timeout_minutes": None,
                "note": "OIDC identity provider",
            },
        ],
        "sessions": [],
        "oauth": {
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token",
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "profile"],
            "pkce_supported": True,
            "note": "OAuth2 authorization endpoint observed",
        },
        "oidc": {
            "issuer": "https://auth.example.com/",
            "jwks_uri": "https://auth.example.com/oidc/keys",
            "discovery_url": "https://auth.example.com/.well-known/openid-configuration",
            "userinfo_endpoint": "https://auth.example.com/oidc/userinfo",
            "subject_type": "pairwise",
            "id_token_signing_alg": "RS256",
            "note": "OIDC discovery document observed",
        },
        "mfa": {
            "status": MfaStatus.OBSERVED.value,
            "factors": ["totp"],
            "prompt_observed": True,
            "note": "MFA prompt observed at SSO entry",
        },
        "authorization": {
            "model": "policy_based",
            "enforcement": "declarative",
            "note": "claims-based policy evaluation",
        },
        "roles": [],
        "permissions": [],
        "access": [],
        "expected_access": {},
    },
    "legacy.example.com": {
        "ip": "192.0.2.24",
        "url": "https://legacy.example.com/",
        "title": "Legacy Portal",
        "schemes": [
            {
                "scheme": "basic",
                "type": "http_basic",
                "parameter_name": "Authorization",
                "note": "HTTP Basic over TLS",
            }
        ],
        "schemes_detected": [
            {
                "scheme": "basic",
                "present": True,
                "password_policy": None,
                "password_policy_observed": False,
                "session_timeout_minutes": None,
                "note": "HTTP Basic over TLS; no session concept observed",
            }
        ],
        "sessions": [],
        "oauth": None,
        "oidc": None,
        "mfa": {
            "status": MfaStatus.NOT_OBSERVED.value,
            "factors": [],
            "prompt_observed": False,
            "note": "no MFA observed",
        },
        "authorization": {
            "model": "none_observed",
            "enforcement": None,
            "note": "no authorization model observed on this legacy surface",
        },
        "roles": [],
        "permissions": [],
        "access": [],
        "expected_access": {},
    },
    "mail.example.com": {
        "ip": "198.51.100.23",
        "url": None,
        "title": None,
        "note": "no web application observed",
    },
    "throttled.example.com": {
        "ip": "203.0.113.41",
        "error": {"kind": "rate_limited", "message": "rate limited"},
    },
    "unreachable.example.com": {
        "ip": "203.0.113.42",
        "error": {"kind": "connection_refused", "message": "connection refused"},
    },
}


def _fallback_record(target: str) -> dict[str, Any]:
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
    host_normalized = target.strip().lower()
    return {
        "ip": f"192.0.2.{(int(digest[:2], 16) % 254) + 1}",
        "url": f"https://{host_normalized}/",
        "title": f"{host_normalized} default page",
        "schemes": [
            {
                "scheme": "session_cookie",
                "type": "cookie_session",
                "parameter_name": "session",
                "note": "deterministic fallback auth surface",
            }
        ],
        "schemes_detected": [
            {
                "scheme": "session_cookie",
                "present": True,
                "password_policy": None,
                "password_policy_observed": False,
                "session_timeout_minutes": 30,
                "note": "deterministic fallback cookie session",
            }
        ],
        "sessions": [
            {
                "name": "session",
                "value_hashed": _hash(f"mock-session-{host_normalized}"),
                "domain": host_normalized,
                "path": "/",
                "flags": ["HttpOnly", "Secure"],
                "secure": True,
                "httponly": True,
                "samesite": None,
                "expires": "30m",
                "note": "session properties only; value hashed",
            }
        ],
        "oauth": None,
        "oidc": None,
        "mfa": {
            "status": MfaStatus.UNKNOWN.value,
            "factors": [],
            "prompt_observed": None,
            "note": "MFA posture not observable from the fallback surface",
        },
        "authorization": {
            "model": "unknown",
            "enforcement": None,
            "note": "authorization model not observed",
        },
        "roles": [],
        "permissions": [],
        "access": [],
        "expected_access": {},
    }


class MockAuthTransport:
    """Deterministic, mock-only authentication/authorization observation source.

    Never touches the network and never returns real credentials: session
    cookies, authorization headers, and token values are produced as one-way
    digests (``REDACTED:<hash>``) or the literal ``REDACTED`` marker so raw
    artifacts are safe to persist. Controlled access outcomes are fixed data
    — the transport never guesses, submits, or brute-forces credentials.
    Known demo hosts use a fixed dataset; any other host yields a stable
    hash-derived dataset so behaviour is reproducible across runs.
    """

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = dict(_DEMO_AUTH)

    def _record_for(self, target: str) -> dict[str, Any]:
        host = self._host_for(target)
        record = self._records.get(host)
        if record is not None:
            return {"host": host, **record}
        for name, rec in self._records.items():
            if rec.get("ip") == host:
                return {"host": name, **rec}
        return {"host": host, **_fallback_record(host)}

    @staticmethod
    def _host_for(target: str) -> str:
        text = target.strip()
        if "://" in text:
            return urlparse(text).netloc.rsplit(":", 1)[0]
        return text

    def _document(
        self,
        tool: str,
        target: str,
        mode: AuthMode,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        document: dict[str, Any] = {
            "tool": tool,
            "mode": mode.value,
            "target": target,
            "host": record["host"],
        }
        if "error" in record:
            document["error"] = dict(record["error"])
            return document
        return document

    def observe_authentication_surface(
        self, target: str, mode: AuthMode = AuthMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_authentication_surface", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["schemes"] = [dict(c) for c in record.get("schemes", [])]
        if not record.get("schemes"):
            doc["note"] = record.get("note", "no authentication surfaces observed")
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_session_details(
        self, target: str, mode: AuthMode = AuthMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_session_details", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["sessions"] = [dict(c) for c in record.get("sessions", [])]
        if not record.get("sessions"):
            doc["note"] = record.get("note", "no sessions observed")
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def detect_authentication_schemes(
        self, target: str, mode: AuthMode = AuthMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("detect_authentication_schemes", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["schemes_detected"] = [
            dict(c) for c in record.get("schemes_detected", [])
        ]
        if not record.get("schemes_detected"):
            doc["note"] = record.get("note", "no authentication schemes detected")
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_oauth_metadata(
        self, target: str, mode: AuthMode = AuthMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_oauth_metadata", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["oauth"] = dict(record["oauth"]) if record.get("oauth") else None
        if doc["oauth"] is None:
            doc["note"] = "no OAuth2 metadata observed"
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_oidc_metadata(
        self, target: str, mode: AuthMode = AuthMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_oidc_metadata", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["oidc"] = dict(record["oidc"]) if record.get("oidc") else None
        if doc["oidc"] is None:
            doc["note"] = "no OIDC metadata observed"
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_mfa_surface(
        self, target: str, mode: AuthMode = AuthMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_mfa_surface", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        mfa = record.get("mfa")
        doc["mfa"] = dict(mfa) if mfa else None
        if doc["mfa"] is None:
            doc["mfa"] = {
                "status": MfaStatus.UNKNOWN.value,
                "factors": [],
                "prompt_observed": None,
                "note": "MFA posture not observed",
            }
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_authorization_surface(
        self, target: str, mode: AuthMode = AuthMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_authorization_surface", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        authz = record.get("authorization")
        doc["authorization_model"] = dict(authz) if authz else None
        if doc["authorization_model"] is None:
            doc["authorization_model"] = {
                "model": "unknown",
                "enforcement": None,
                "note": "authorization model not observed",
            }
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_roles(self, target: str, mode: AuthMode = AuthMode.PASSIVE) -> str:
        record = self._record_for(target)
        doc = self._document("observe_roles", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["roles"] = [dict(c) for c in record.get("roles", [])]
        if not record.get("roles"):
            doc["note"] = "no roles observed"
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_permissions(
        self, target: str, mode: AuthMode = AuthMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_permissions", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["permissions"] = [
            redact_nested_credential_values(dict(c))
            for c in record.get("permissions", [])
        ]
        if not record.get("permissions"):
            doc["note"] = "no permissions observed"
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def observe_resource_access(
        self, target: str, mode: AuthMode = AuthMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        doc = self._document("observe_resource_access", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["access"] = [
            redact_nested_credential_values(dict(c))
            for c in record.get("access", [])
        ]
        if not record.get("access"):
            doc["note"] = "no controlled access observations"
        return json.dumps(redact_credential_fields(doc), sort_keys=True)

    def compare_access_control(
        self,
        target: str,
        mode: AuthMode = AuthMode.ACTIVE,
        test_identities: list[str] | None = None,
    ) -> str:
        record = self._record_for(target)
        doc = self._document("compare_access_control", target, mode, record)
        if "error" in doc:
            return json.dumps(doc, sort_keys=True)
        url = record.get("url") or f"https://{record['host']}/"
        doc["observed_url"] = url
        doc["test_identities"] = list(test_identities or [])
        observed = {
            (str(c["identity"]), c["resource"]): AuthAccess(c["access"])
            for c in record.get("access", [])
            if c.get("identity") and c.get("resource")
        }
        comparisons: list[dict[str, Any]] = []
        expected = record.get("expected_access", {}) or {}
        active_identities = [
            i for i in (test_identities or []) if i and str(i) in expected
        ]
        for identity in active_identities:
            for resource, desired in (expected.get(identity, {}) or {}).items():
                try:
                    expected_access = AuthAccess(desired)
                except ValueError:
                    expected_access = AuthAccess.NOT_TESTED
                outcome = observed.get((identity, resource))
                access = (
                    outcome
                    if outcome is not None
                    else AuthAccess.NOT_TESTED
                )
                comparisons.append(
                    {
                        "identity": identity,
                        "role": next(
                            (
                                str(c["role"])
                                for c in record.get("access", [])
                                if c.get("identity") == identity
                                and c.get("resource") == resource
                                and c.get("role")
                            ),
                            None,
                        ),
                        "resource": resource,
                        "access": access.value,
                        "expected_access": expected_access.value,
                        "consistent": access == expected_access,
                        "credential_used": access in {
                            AuthAccess.ALLOWED,
                            AuthAccess.DENIED,
                        },
                        "credential_type": (
                            next(
                                (
                                    str(c["credential_type"])
                                    for c in record.get("access", [])
                                    if c.get("identity") == identity
                                    and c.get("resource") == resource
                                    and c.get("credential_type")
                                ),
                                None,
                            )
                            if access in {AuthAccess.ALLOWED, AuthAccess.DENIED}
                            else None
                        ),
                        "credential_value": credential_value_redacted(),
                        "note": "expected vs observed comparison for a controlled identity",
                    }
                )
        doc["comparisons"] = [
            redact_nested_credential_values(dict(c)) for c in comparisons
        ]
        if not comparisons:
            doc["note"] = (
                "no controlled identities supplied; access control comparison "
                "recorded as NOT_TESTED"
            )
        return json.dumps(redact_credential_fields(doc), sort_keys=True)
