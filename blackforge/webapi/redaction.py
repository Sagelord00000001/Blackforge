from __future__ import annotations

import hashlib
from typing import Any

SECRET_LIKE_KEYS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "token",
        "password",
        "passwd",
        "client_secret",
        "secret",
        "credentials",
        "apikeyvalue",
    }
)

_SECRET_KEY_COMPONENTS: frozenset[str] = SECRET_LIKE_KEYS


def redact_secret(value: Any) -> str:
    """Deterministic one-way hash of a secret-like value.

    Only the digest is ever stored or surfaced; the plaintext is never
    written to evidence, memory, or world model records.
    """
    payload = str(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _header_is_secret(name: str) -> bool:
    return name.strip().lower() in _SECRET_KEY_COMPONENTS


def redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Return a header mapping with security-sensitive values hashed.

    Header *names* are kept (they are not secrets); values of cookie,
    credential, or key-bearing headers are replaced with one-way digests.
    """
    out: dict[str, Any] = {}
    for name, value in headers.items():
        key = str(name)
        if _header_is_secret(key):
            rendered = str(value)
            out[key] = f"REDACTED:{redact_secret(rendered)[:16]}"
        else:
            out[key] = value
    return out


def redact_document(document: dict[str, Any]) -> dict[str, Any]:
    """Recursively hash secret-like values inside a parsed document.

    Defense in depth for artifacts: keys whose names look like credentials,
    tokens, or keys have their values replaced with digests regardless of
    depth, so raw documents can be persisted safely.
    """
    out: dict[str, Any] = {}
    for key, value in document.items():
        if _header_is_secret(key) and value is not None:
            out[key] = redact_secret(value)
        elif isinstance(value, dict):
            out[key] = redact_document(value)
        elif isinstance(value, list):
            out[key] = [
                redact_document(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            out[key] = value
    return out
