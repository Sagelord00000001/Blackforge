from __future__ import annotations

import re

from pydantic import BaseModel

_CLUSTER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9-]*$")


class ContainerTargetParts(BaseModel):
    """Resolved parts of a container target string.

    ``cluster`` is always present; ``namespace`` is ``None`` for a bare
    cluster umbrella target and set for ``cluster/namespace`` targets.
    """

    cluster: str
    namespace: str | None = None


def parse_container_target(target: str) -> ContainerTargetParts:
    """Parse a ``cluster`` or ``cluster/namespace`` container target.

    Bare clusters are valid umbrella targets that resolve every namespace on
    the cluster. Only lowercase cluster/namespace names (Kubernetes naming
    rules) are accepted — any other shape raises ``ValueError`` so
    unauthorized or ambiguous targets fail closed.
    """
    value = str(target or "").strip()
    if not value:
        raise ValueError("empty container target")
    if "/" in value:
        cluster, _, namespace = value.partition("/")
        if not namespace or "/" in namespace:
            raise ValueError(f"invalid container target: {target}")
        if not _CLUSTER_RE.match(cluster) or not _NAMESPACE_RE.match(namespace):
            raise ValueError(f"invalid container target: {target}")
        return ContainerTargetParts(cluster=cluster, namespace=namespace)
    if not _CLUSTER_RE.match(value):
        raise ValueError(f"invalid container target: {target}")
    return ContainerTargetParts(cluster=value, namespace=None)


def cluster_for_target(target: str) -> str | None:
    """The cluster handle for a container target, or ``None`` if not one."""
    try:
        return parse_container_target(target).cluster
    except ValueError:
        return None


def target_looks_containers(target: str) -> bool:
    """True when a target uses the ``cluster[/namespace]`` container scheme."""
    return cluster_for_target(target) is not None


__all__ = [
    "ContainerTargetParts",
    "cluster_for_target",
    "parse_container_target",
    "target_looks_containers",
]
