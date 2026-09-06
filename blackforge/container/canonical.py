from __future__ import annotations

import re

_REFSEP = re.compile(r"[^a-z0-9]+")


def _slug(value: str) -> str:
    """Deterministic lowercase slug of a container label."""
    return _REFSEP.sub("-", value.strip().lower()).strip("-")


def container_namespace(cluster: str, namespace: str | None = None) -> str:
    """Canonical world model namespace for a cluster (and optional namespace).

    Cluster-scoped entities (nodes, namespaces) live under ``k8s/<cluster>``;
    namespace-scoped entities live under ``k8s/<cluster>/<namespace>`` so
    same-named workloads/services across namespaces stay distinct and never
    collide with Phase 10 directory or Phase 11 cloud identities.
    """
    cluster_slug = _slug(cluster)
    if not cluster_slug:
        raise ValueError("empty cluster name")
    if namespace is None:
        return f"k8s/{cluster_slug}"
    namespace_slug = _slug(namespace)
    if not namespace_slug:
        raise ValueError("empty namespace name")
    return f"k8s/{cluster_slug}/{namespace_slug}"


def container_resource_id(
    *,
    cluster: str,
    namespace: str | None,
    resource_type: str,
    name: str,
) -> str:
    """Deterministic, readable container resource identifier.

    Format: ``cluster:namespace:type:name`` (colon-joined slugs). Cluster-
    scoped resources use ``global`` in place of the namespace so the id is
    globally unique across the fleet without collisions.
    """
    return _REFSEP.sub(
        ":",
        ":".join(
            [
                _slug(cluster),
                _slug(namespace or "global"),
                _slug(resource_type),
                _slug(name),
            ]
        ),
    ).strip(":")


__all__ = [
    "container_namespace",
    "container_resource_id",
]
