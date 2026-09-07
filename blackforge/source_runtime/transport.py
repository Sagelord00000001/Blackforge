from __future__ import annotations

import json
from typing import Any

from blackforge.source_runtime.models import SourceRuntimeMode
from blackforge.source_runtime.runtime import RuntimeFixtureProvider
from blackforge.source_runtime.source import SourceFixtureProvider

# Map a capability family to the scope_kind it correlates. A target selects one
# family's universe; records outside the family (different scope_kind) are not
# returned, mirroring an authorized, bounded probe.
FAMILY_SCOPE_KIND: dict[str, str] = {
    "container_configuration_correlation": "cluster",
    "image_runtime_correlation": "image",
    "workload_manifest_correlation": "cluster",
    "service_exposure_correlation": "cluster",
    "ingress_runtime_correlation": "cluster",
    "network_policy_correlation": "cluster",
    "cloud_resource_correlation": "cloud",
    "api_surface_correlation": "cluster",
    "application_configuration_correlation": "cluster",
    "rbac_manifest_correlation": "cluster",
}


def _scope_parts_for_target(target: str) -> list[str]:
    """Derive deterministic scope parts from a target string.

    Targets are ``cluster/cluster-name/namespace`` or ``image/registry``
    or a bare umbrella ``cloud``. All segments after the scope_kind prefix
    are returned as scope parts for fixture filtering; an umbrella target
    returns no parts.
    """
    segments = [s for s in target.split("/") if s]
    if len(segments) <= 1:
        return []
    return segments


class MockSourceRuntimeTransport:
    """Deterministic mock transport exposing BOTH independent fixture sides.

    Returns a JSON document with ``tool``/``mode``/``target`` together with a
    ``source`` (declared) record set and a ``runtime`` (observed) record set.
    The two sides come from independent fixture modules; the transport only
    joins them for a correlated capability, it never authors either fact.
    """

    def __init__(self) -> None:
        self._source = SourceFixtureProvider
        self._runtime = RuntimeFixtureProvider

    def _emit(self, doc: dict[str, Any]) -> str:
        return json.dumps(doc, sort_keys=True, default=str)

    def execute(self, capability_id: str, target: str) -> str:
        family = capability_id.split(".")[-1]
        scope_kind = FAMILY_SCOPE_KIND.get(family)
        if scope_kind is None:
            doc: dict[str, Any] = {
                "tool": capability_id,
                "mode": SourceRuntimeMode.CONTROLLED.value,
                "target": target,
                "error": {
                    "kind": "unsupported_capability",
                    "message": f"no correlation fixture for capability: {capability_id}",
                },
            }
            return self._emit(doc)

        scope_parts = _scope_parts_for_target(target)
        # For cluster/image scope, the fixture scope is fixed; the target is an
        # umbrella selector. We only return records whose scope_kind matches.
        source_records = [
            record
            for record in self._source.declared_entries()
            if (record["identity"] or {}).get("scope_kind") == scope_kind
        ]
        if scope_parts:
            source_records = [
                record
                for record in source_records
                if (record["identity"] or {}).get("scope_parts") == scope_parts
            ]

        runtime_records = [
            record
            for record in self._runtime.observed_entries()
            if (record["identity"] or {}).get("scope_kind") == scope_kind
        ]
        if scope_parts:
            runtime_records = [
                record
                for record in runtime_records
                if (record["identity"] or {}).get("scope_parts") == scope_parts
            ]

        if not source_records and not runtime_records:
            doc = {
                "tool": capability_id,
                "mode": SourceRuntimeMode.CONTROLLED.value,
                "target": target,
                "error": {
                    "kind": "no_fixture_records",
                    "message": f"no source/runtime fixture records for target: {target}",
                },
            }
            return self._emit(doc)

        return self._emit(
            {
                "tool": capability_id,
                "mode": SourceRuntimeMode.CONTROLLED.value,
                "target": target,
                "scope_kind": scope_kind,
                "source": source_records,
                "runtime": runtime_records,
            }
        )


__all__ = [
    "FAMILY_SCOPE_KIND",
    "MockSourceRuntimeTransport",
    "_scope_parts_for_target",
]
