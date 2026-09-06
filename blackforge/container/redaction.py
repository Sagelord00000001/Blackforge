from __future__ import annotations

from typing import Any

from blackforge.network.redaction import credential_value_redacted

# Container / Kubernetes-specific credential-like keys. Generic redaction
# already covers password/token/secret/credential/authorization/api_key/
# client_secret/refresh_token and the ``key`` keyword; these additions pin the
# container adapters (kubeconfig, registry credentials, service-account token,
# image-pull secret, TLS private key) explicitly as defense in depth at the
# container transport boundary.
CONTAINER_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {
        "kubeconfig",
        "registry_token",
        "registry_secret",
        "service_account_token",
        "service_account_secret",
        "image_pull_secret",
        "image_pull_secrets",
        "dockerconfigjson",
        "pull_token",
        "pull_secret",
        "tls_private_key",
        "client_key_data",
        "token",
        "password",
        "secret",
        "credentials",
    }
)

_CONTAINER_CREDENTIAL_KEYWORDS: frozenset[str] = frozenset(
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
        "key",
    }
)


def _key_is_credential(key: str) -> bool:
    normalized = key.strip().lower()
    if normalized in CONTAINER_CREDENTIAL_KEYS:
        return True
    tokens = normalized.replace("-", " ").replace("_", " ").split()
    return any(token in _CONTAINER_CREDENTIAL_KEYWORDS for token in tokens)


def redact_container_document(document: Any) -> Any:
    """Recursively redact credential-like fields from a container document.

    Values are always replaced with the stable, non-invertible ``REDACTED``
    marker; non-secret sibling keys are preserved so the document keeps its
    structure. Scalar secrets that hide under list-of-dict shapes are handled
    the same way as the identity boundary.
    """
    if isinstance(document, dict):
        out: dict[str, Any] = {}
        for key, item in document.items():
            if _key_is_credential(str(key)) and item is not None:
                out[key] = credential_value_redacted()
            elif isinstance(item, dict):
                out[key] = redact_container_document(item)
            elif isinstance(item, list):
                out[key] = [
                    (
                        redact_container_document(entry)
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
            redact_container_document(entry) if isinstance(entry, dict) else entry
            for entry in document
        ]
    return document


def redact_container_raw(raw: str) -> str:
    """Redact a JSON container document's credential fields without losing shape."""
    import json

    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw
    redacted = redact_container_document(doc)
    if isinstance(redacted, (dict, list)):
        return json.dumps(redacted, sort_keys=True, default=str)
    return raw


__all__ = [
    "CONTAINER_CREDENTIAL_KEYS",
    "credential_value_redacted",
    "redact_container_document",
    "redact_container_raw",
]
