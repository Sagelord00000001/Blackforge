from __future__ import annotations

from typing import Any

from blackforge.webapi.redaction import (
    redact_document,
    redact_headers,
    redact_secret,
)

CREDENTIAL_LIKE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "secret",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "mfa_code",
        "otp",
        "totp",
        "credential",
        "credential_value",
    }
)

CREDENTIAL_REDACTED = "REDACTED"


def credential_value_redacted() -> str:
    """Literal redaction marker for credential-like values."""
    return CREDENTIAL_REDACTED


def _key_is_credential(key: str) -> bool:
    return key.strip().lower() in CREDENTIAL_LIKE_KEYS


def redact_credential_fields(document: dict[str, Any]) -> dict[str, Any]:
    """Replace every value stored under a credential-like key recursively.

    Credential values are always rendered as the literal ``REDACTED`` marker
    (a stable, non-invertible label, never a copied string). Non-secret
    sibling keys are left untouched so the observation keeps its structure.
    """
    out: dict[str, Any] = {}
    for key, item in document.items():
        if _key_is_credential(key) and item is not None:
            out[key] = credential_value_redacted()
        elif isinstance(item, dict):
            out[key] = redact_credential_fields(item)
        elif isinstance(item, list):
            out[key] = [
                (
                    redact_credential_fields(entry)
                    if isinstance(entry, dict)
                    else (
                        credential_value_redacted()
                        if _key_is_credential(key)
                        else entry
                    )
                )
                for entry in item
            ]
        else:
            out[key] = item
    return out


def redact_nested_credential_values(document: dict[str, Any]) -> dict[str, Any]:
    """Force the stable ``credential_value`` marker key to ``REDACTED``.

    Defense in depth for typed observations: whatever the transport emits
    under the ``credential_value`` key, only the redaction marker is kept.
    """
    out: dict[str, Any] = {}
    for key, item in document.items():
        if str(key) == "credential_value":
            out[key] = credential_value_redacted()
        elif isinstance(item, dict):
            out[key] = redact_nested_credential_values(item)
        elif isinstance(item, list):
            out[key] = [
                redact_nested_credential_values(entry)
                if isinstance(entry, dict)
                else entry
                for entry in item
            ]
        else:
            out[key] = item
    return out


__all__ = [
    "CREDENTIAL_LIKE_KEYS",
    "CREDENTIAL_REDACTED",
    "credential_value_redacted",
    "redact_credential_fields",
    "redact_document",
    "redact_headers",
    "redact_nested_credential_values",
    "redact_secret",
]
