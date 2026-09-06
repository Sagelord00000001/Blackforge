from __future__ import annotations

from typing import Any

from blackforge.network.redaction import credential_value_redacted

# Cloud-specific credential-like keys. Generic redaction already covers
# password/token/secret/credential/authorization/api_key/client_secret/
# refresh_token and the ``key`` keyword; these additions pin the cloud adapters
# (access keys, connection strings, service secrets) explicitly as defense in
# depth at the cloud transport boundary.
CLOUD_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {
        "access_key",
        "access_key_id",
        "secret_key",
        "secret_value",
        "connection_string",
        "private_key",
        "public_key_material",
        "client_secret",
        "service_account_secret",
        "iam_credential",
        "managed_identity_secret",
        "token",
        "password",
        "secret",
        "credentials",
    }
)

_CLOUD_CREDENTIAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "token",
        "secret",
        "credential",
        "authorization",
        "cookie",
        "otp",
        "totp",
        "apikey",
        "mfacode",
        "key",
        "connection",
        "access",
        "azuread",
    }
)


def _key_is_cloud_credential(key: str) -> bool:
    normalized = key.strip().lower()
    if normalized in CLOUD_CREDENTIAL_KEYS:
        return True
    tokens = normalized.replace("-", " ").replace("_", " ").split()
    return any(token in _CLOUD_CREDENTIAL_KEYWORDS for token in tokens)


def redact_cloud_document(document: Any) -> Any:
    """Recursively redact credential-like fields from a cloud document.

    Values are always replaced with the stable, non-invertible ``REDACTED``
    marker; non-secret sibling keys are preserved so the document keeps its
    structure. Scalar secrets that hide under list-of-dict shapes are handled
    the same way as the identity boundary.
    """
    if isinstance(document, dict):
        out: dict[str, Any] = {}
        for key, item in document.items():
            if _key_is_cloud_credential(str(key)) and item is not None:
                out[key] = credential_value_redacted()
            elif isinstance(item, dict):
                out[key] = redact_cloud_document(item)
            elif isinstance(item, list):
                out[key] = [
                    (
                        redact_cloud_document(entry)
                        if isinstance(entry, dict)
                        else (
                            credential_value_redacted()
                            if _key_is_cloud_credential(str(key))
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
            redact_cloud_document(entry) if isinstance(entry, dict) else entry
            for entry in document
        ]
    return document


def redact_cloud_raw(raw: str) -> str:
    """Redact a JSON cloud document's credential fields without losing shape."""
    import json

    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw
    redacted = redact_cloud_document(doc)
    if isinstance(redacted, (dict, list)):
        return json.dumps(redacted, sort_keys=True, default=str)
    return raw


__all__ = [
    "CLOUD_CREDENTIAL_KEYS",
    "credential_value_redacted",
    "redact_cloud_document",
    "redact_cloud_raw",
]
