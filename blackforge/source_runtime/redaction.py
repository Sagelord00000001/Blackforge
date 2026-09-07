from __future__ import annotations

from typing import Any

from blackforge.network.redaction import credential_value_redacted

# Correlation-specific credential-like keys. The generic redaction boundary
# already covers password/token/secret/credential/authorization/api_key/
# client_secret/private_key; these add the source/runtime fields that must
# never leak through a correlation result (declared IaC values, API keys,
# OAuth/bearer material, TLS private keys, cloud access keys).
SOURCE_RUNTIME_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "api_secret",
        "access_key",
        "access_key_id",
        "secret_access_key",
        "secret_key",
        "client_secret",
        "private_key",
        "public_key_material",
        "bearer_token",
        "authorization",
        "oauth2_token",
        "oidc_id_token",
        "basic_auth_password",
        "connection_string",
        "password",
        "passwd",
        "token",
        "secret",
        "credentials",
    }
)

_SOURCE_RUNTIME_KEYWORDS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "token",
        "secret",
        "credential",
        "authorization",
        "apikey",
        "key",
        "cookie",
        "otp",
        "totp",
    }
)


def _key_is_credential(key: str) -> bool:
    normalized = key.strip().lower()
    if normalized in SOURCE_RUNTIME_CREDENTIAL_KEYS:
        return True
    tokens = normalized.replace("-", " ").replace("_", " ").split()
    return any(token in _SOURCE_RUNTIME_KEYWORDS for token in tokens)


def redact_source_runtime_document(document: Any) -> Any:
    """Recursively redact credential-like fields from a correlation document.

    Values are always replaced with the stable, non-invertible ``REDACTED``
    marker; non-secret sibling keys are preserved so the document keeps its
    structure.
    """
    if isinstance(document, dict):
        out: dict[str, Any] = {}
        for key, item in document.items():
            if _key_is_credential(str(key)) and item is not None:
                out[key] = credential_value_redacted()
            elif isinstance(item, dict):
                out[key] = redact_source_runtime_document(item)
            elif isinstance(item, list):
                out[key] = [
                    (
                        redact_source_runtime_document(entry)
                        if isinstance(entry, dict)
                        else (
                            credential_value_redacted()
                            if _key_is_credential(str(key))
                            else entry
                        )
                    )
                    for entry in item
                ]
            else:
                out[key] = item
        return out
    if isinstance(document, list):
        return [
            redact_source_runtime_document(entry) if isinstance(entry, dict) else entry
            for entry in document
        ]
    return document


def redact_source_runtime_raw(raw: str) -> str:
    """Redact a JSON source/runtime document's credential fields without losing shape."""
    import json

    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw
    redacted = redact_source_runtime_document(doc)
    if isinstance(redacted, (dict, list)):
        return json.dumps(redacted, sort_keys=True, default=str)
    return raw


__all__ = [
    "SOURCE_RUNTIME_CREDENTIAL_KEYS",
    "credential_value_redacted",
    "redact_source_runtime_document",
    "redact_source_runtime_raw",
]
