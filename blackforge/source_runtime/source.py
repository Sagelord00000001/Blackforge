"""SOURCE (declared / static) side of the correlation engine.

The source fixtures represent the *as-declared* state — specification,
Infrastructure-as-Code, manifests, and configuration-as-code. They are
independent of the runtime (observed) fixtures by construction: the two sides
live in separate modules and are never derived from one another, preserving
the two-independent-sources rule for correlation.
"""
from __future__ import annotations

from blackforge.source_runtime.models import Side, SourceValue


def declared_value(property: str, normalized_value: str | None) -> SourceValue:
    return SourceValue(
        side=Side.SOURCE,
        property=property,
        normalized_value=normalized_value,
        present=normalized_value is not None,
    )


# A deterministic, small declared estate. Values are static declarations; they
# are intentionally independent from the runtime fixture module.
DECLARED_ENTRIES: list[dict] = [
    {
        "identity": {
            "scope_kind": "cluster",
            "scope_parts": ["aelionix-prod", "payments"],
            "name": "payment-gateway",
        },
        "properties": {
            "image": "registry.aelionix.io/payments/payment-gateway@sha256:db9a…",
            "replicas": "2",
            "service_type": "ClusterIP",
            "service_port": "8443",
            "ingress_path": "/payments",
            "readiness": "/ready",
            "env": "LOG_LEVEL=info|FEATURE_KYC=enabled",
            "namespace": "payments",
            "service_account": "payment-gateway-sa",
            "network_policy": "default-deny-inbound",
        },
    },
    {
        "identity": {
            "scope_kind": "cluster",
            "scope_parts": ["aelionix-prod", "marketing"],
            "name": "marketing-site",
        },
        "properties": {
            "image": "registry.aelionix.io/www/marketing-site@sha256:9f2c…",
            "replicas": "3",
            "service_type": "LoadBalancer",
            "service_port": "443",
            "ingress_path": "/",
            "readiness": "/health",
            "env": "TRACKING_ID=UA-000000",
            "service_account": "default",
        },
    },
    {
        "identity": {
            "scope_kind": "cluster",
            "scope_parts": ["aelionix-staging", "payments"],
            "name": "payment-gateway",
        },
        "properties": {
            "image": "registry.aelionix.io/payments/payment-gateway@sha256:3a11…",
            "replicas": "1",
            "service_type": "ClusterIP",
            "service_port": "8443",
            "readiness": "/ready",
            "service_account": "payment-gateway-sa",
        },
    },
    {
        "identity": {
            "scope_kind": "cloud",
            "scope_parts": ["aws", "acct-112233445566", "us-east-1"],
            "name": "payments-database",
        },
        "properties": {
            "engine": "postgres",
            "version": "16",
            "publicly_accessible": "false",
            "port": "5432",
            "backup_enabled": "true",
        },
    },
    {
        "identity": {
            "scope_kind": "image",
            "scope_parts": ["registry.aelionix.io"],
            "name": "payments/payment-gateway",
        },
        "properties": {
            "digest": "sha256:db9a5c…",
            "tag": "1.4.2",
            "from": "scratch",
        },
    },
]


class SourceFixtureProvider:
    """Deterministic provider of declared (source) records.

    This is the *declared* half of a correlation. It never observes the live
    system; it only returns configuration/specification as authored.
    """

    kind = Side.SOURCE

    @staticmethod
    def declared_entries() -> list[dict]:
        return [
            {
                "identity": dict(entry["identity"]),
                "properties": dict(entry["properties"]),
            }
            for entry in DECLARED_ENTRIES
        ]

    @staticmethod
    def find(scope_parts: list[str], name: str) -> dict | None:
        for entry in DECLARED_ENTRIES:
            identity = entry["identity"]
            if identity["name"] == name and identity["scope_parts"] == scope_parts:
                return {
                    "identity": dict(identity),
                    "properties": dict(entry["properties"]),
                }
        return None


__all__ = [
    "DECLARED_ENTRIES",
    "SourceFixtureProvider",
    "declared_value",
]
