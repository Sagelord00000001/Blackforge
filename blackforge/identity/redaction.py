from __future__ import annotations

from typing import Any

from blackforge.network.redaction import (
    credential_value_redacted,
)

# Directory/identity specific credential-like keys that generic redaction
# already covers through its keyword set; kept explicit here as defense in
# depth for the identity transport boundary.
IDENTITY_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {
        "password_hash",
        "nt_hash",
        "lm_hash",
        "kerberos_ticket",
        "session_token",
        "mfa_secret",
        "recovery_code",
        "service_account_secret",
        "sso_token",
        "password",
        "token",
        "secret",
        "credentials",
    }
)


def _key_is_identity_credential(key: str) -> bool:
    normalized = key.strip().lower()
    if normalized in IDENTITY_CREDENTIAL_KEYS:
        return True
    tokens = normalized.replace("-", " ").replace("_", " ").split()
    return any(
        token in {"password", "token", "secret", "hash", "credential", "ticket"}
        for token in tokens
    ) and "level" not in tokens


def redact_identity_document(document: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact credential-like fields from an identity document.

    Values are always replaced with the stable, non-invertible ``REDACTED``
    marker. Non-secret sibling keys are preserved so the observation keeps its
    structure. Applied at the transport boundary so no hashes, tickets,
    tokens, or secrets ever reach the evidence ledger or world model.
    """
    if not isinstance(document, dict):
        return document
    out: dict[str, Any] = {}
    for key, item in document.items():
        if _key_is_identity_credential(str(key)) and item is not None:
            out[key] = credential_value_redacted()
        elif isinstance(item, dict):
            out[key] = redact_identity_document(item)
        elif isinstance(item, list):
            out[key] = [
                (
                    redact_identity_document(entry)
                    if isinstance(entry, dict)
                    else (
                        credential_value_redacted()
                        if _key_is_identity_credential(str(key))
                        else entry
                    )
                )
                for entry in item
            ]
        else:
            out[key] = item
    return out


def redact_identity_raw(raw: str) -> str:
    """Redact a JSON identity document's credential fields without losing shape.

    Returns the original string verbatim when the raw output is not a JSON
    object or a list of object observations.
    """
    import json

    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw
    if isinstance(doc, list):
        cleaned = [
            redact_identity_document(entry) if isinstance(entry, dict) else entry
            for entry in doc
        ]
        return json.dumps(cleaned, sort_keys=True)
    if isinstance(doc, dict):
        return json.dumps(redact_identity_document(doc), sort_keys=True)
    return raw


__all__ = [
    "IDENTITY_CREDENTIAL_KEYS",
    "credential_value_redacted",
    "redact_identity_document",
    "redact_identity_raw",
]
