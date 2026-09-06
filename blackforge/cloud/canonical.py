from __future__ import annotations

import re

_REFSEP = re.compile(r"[^a-z0-9]+")


def _slug(value: str) -> str:
    """Deterministic lowercase slug of a cloud label."""
    return _REFSEP.sub("-", value.strip().lower()).strip("-")


def cloud_namespace(provider: str, container: str) -> str:
    """Canonical world model namespace for a provider/container estate.

    All cloud entities of a service type live under this namespace so
    same-named resources across providers or containers stay distinct and
    never collide with Phase 10 directory identities.
    """
    return f"{_slug(provider)}/{_slug(container)}"


def cloud_resource_id(
    *,
    provider: str,
    container: str | None,
    region: str | None,
    resource_type: str,
    name: str,
) -> str:
    """Deterministic, readable cloud resource identifier.

    Format: ``provider:container:region:type:name``. The container is the
    account (AWS), subscription (Azure), or project (GCP) that owns the
    resource, so the id is globally unique across the estate without
    collisions.
    """
    return _REFSEP.sub(
        ":",
        ":".join(
            [
                _slug(provider),
                _slug(container or "root"),
                _slug(region or "global"),
                _slug(resource_type),
                _slug(name),
            ]
        ),
    ).strip(":")


def container_for_observation(
    *, account: str | None = None, project: str | None = None
) -> str | None:
    """The canonical container handle for an observation.

    Prefers the project (GCP) over the account/subscription so resource
    namespaces stay consistent with the target that produced them.
    """
    return project or account or None


__all__ = [
    "cloud_namespace",
    "cloud_resource_id",
    "container_for_observation",
]
