from __future__ import annotations

import re

from pydantic import BaseModel, Field

from blackforge.source_runtime.models import CorrelatedIdentity

_REFSEP = re.compile(r"[^a-z0-9]+")


def _slug(value: str) -> str:
    """Deterministic lowercase slug used inside canonical identities."""
    return _REFSEP.sub("-", str(value or "").strip().lower()).strip("-")


class CorrelationIdentitySpec(BaseModel):
    """Decomposed identity fields used to build a canonical key.

    Every correlation compares a *source* record and a *runtime* record. The
    two records are only comparable when they resolve to the same canonical
    identity. Loose names alone are never treated as equivalent.
    """

    scope_kind: str
    scope_parts: list[str] = Field(default_factory=list)
    name: str


def build_correlation_identity(
    scope_kind: str,
    scope_parts: list[str] | None,
    name: str,
) -> CorrelatedIdentity:
    """Deterministic canonical identity for a correlated resource.

    The identity is ``<scope_kind>:<scope_slug>:<name_slug>``. For Kubernetes
    resources the scope is ``cluster/namespace`` so the same workload name in a
    different namespace yields a different identity (never a false match). For
    cloud resources the scope is ``provider/account/region``; for image
    correlation the identity prefers the immutable digest over a mutable tag.
    """
    scope_slug = ":".join(_slug(part) for part in (scope_parts or []))
    name_slug = _slug(name)
    key = f"{_slug(scope_kind)}:{scope_slug}:{name_slug}".strip(":")

    keys: dict[str, str] = {"scope_kind": _slug(scope_kind), "name": name_slug}
    if scope_parts:
        keys["scope"] = scope_slug

    return CorrelatedIdentity(
        scope_kind=_slug(scope_kind),
        identity=key,
        keys=keys,
    )


def same_correlation_identity(
    source: CorrelatedIdentity, runtime: CorrelatedIdentity
) -> bool:
    """True only when both sides resolve to the identical canonical identity."""
    return source.identity == runtime.identity


__all__ = [
    "CorrelationIdentitySpec",
    "build_correlation_identity",
    "same_correlation_identity",
]
