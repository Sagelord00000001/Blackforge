"""RUNTIME (observed / live) side of the correlation engine.

The runtime fixtures represent the *as-observed* state — live inventory,
running workloads, live network policy, current images by digest. They are
independent of the source (declared) fixtures by construction: they live in a
separate module and are never derived from the declared state, preserving the
two-independent-sources rule for correlation.
"""
from __future__ import annotations

from blackforge.source_runtime.models import Side, SourceValue


def observed_value(property: str, normalized_value: str | None) -> SourceValue:
    return SourceValue(
        side=Side.RUNTIME,
        property=property,
        normalized_value=normalized_value,
        present=normalized_value is not None,
    )


# A deterministic, small observed estate. Observations are the *live* side;
# some intentionally diverge from the declared state (to exercise DISCREPANCY),
# some are missing (to exercise UNKNOWN), and a few claim mutually incompatible
# values for the same property (to exercise CONTRADICTION).
OBSERVED_ENTRIES: list[dict] = [
    # Same-named resource in a DIFFERENT namespace: same name, different
    # canonical identity -> must be NOT_COMPARABLE against the prod declared
    # "payment-gateway", never MATCH.
    {
        "identity": {
            "scope_kind": "cluster",
            "scope_parts": ["aelionix-prod", "payments-prod"],
            "name": "payment-gateway",
        },
        "properties": {
            "image": "registry.aelionix.io/payments/payment-gateway@sha256:db9a5c2f…",
            "replicas": "2",
            "service_type": "ClusterIP",
            "service_port": "8443",
            "readiness": "/ready",
            "env": "LOG_LEVEL=info|FEATURE_KYC=enabled",
            "service_account": "payment-gateway-sa",
        },
    },
    # Correctly matched prod workload: all comparable properties agree with
    # the declared state (MATCH includes the resolved image digest).
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
            "readiness": "/ready",
            "env": "LOG_LEVEL=info|FEATURE_KYC=enabled",
            "network_policy": "default-deny-inbound",
            "service_account": "payment-gateway-sa",
        },
    },
    # Marketing: image matches the declared digest but the runtime replica
    # count disagrees -> DISCREPANCY on a comparable property (ingress_path is
    # intentionally non-comparable in the default property resolver).
    {
        "identity": {
            "scope_kind": "cluster",
            "scope_parts": ["aelionix-prod", "marketing"],
            "name": "marketing-site",
        },
        "properties": {
            "image": "registry.aelionix.io/www/marketing-site@sha256:9f2c…",
            "replicas": "5",
            "service_type": "LoadBalancer",
            "service_port": "443",
            "ingress_path": "/home",
            "readiness": "/health",
            "env": "TRACKING_ID=UA-000000",
            "service_account": "default",
        },
    },
    # Staging payment-gateway exists exactly as declared (MATCH).
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
    # Cloud database: backup_enabled runtime contradicts declared -> CONTRADICTION.
    {
        "identity": {
            "scope_kind": "cloud",
            "scope_parts": ["aws", "acct-112233445566", "us-east-1"],
            "name": "payments-database",
        },
        "properties": {
            "engine": "postgres",
            "version": "15",  # DISCREPANCY vs declared 16
            "publicly_accessible": "false",
            "port": "5432",
            "backup_enabled": "false",  # CONTRADICTION handled at correlation layer
        },
    },
    # Image: digest matches the declared digest (MATCH), tag resolved same.
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


class RuntimeFixtureProvider:
    """Deterministic provider of observed (runtime) records.

    This is the *observed* half of a correlation. It never re-derives the
    declared state; it only returns live inventory / observations.
    """

    kind = Side.RUNTIME

    @staticmethod
    def observed_entries() -> list[dict]:
        return [
            {
                "identity": dict(entry["identity"]),
                "properties": dict(entry["properties"]),
            }
            for entry in OBSERVED_ENTRIES
        ]

    @staticmethod
    def find(scope_parts: list[str], name: str) -> dict | None:
        for entry in OBSERVED_ENTRIES:
            identity = entry["identity"]
            if identity["name"] == name and identity["scope_parts"] == scope_parts:
                return {
                    "identity": dict(identity),
                    "properties": dict(entry["properties"]),
                }
        return None


__all__ = [
    "OBSERVED_ENTRIES",
    "RuntimeFixtureProvider",
    "observed_value",
]
