from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.core.errors import IdentityNormalizationError
from blackforge.identity.models import (
    DirectoryObservation,
    GroupObservation,
    IdentityObservation,
    IdentityObservationKind,
    MembershipObservation,
    MetadataObservation,
    Observation,
    PermissionAssignmentObservation,
    PermissionObservation,
    RelationshipObservation,
    ResourceObservation,
    RoleAssignmentObservation,
    RoleObservation,
)
from blackforge.world_model.canonical import (
    normalize_directory,
    normalize_entity_name,
)
from blackforge.world_model.models import EntityType

_IDENTITY_PRINCIPAL_TYPES = frozenset(
    {"human", "service_account", "computer", "unknown"}
)
_PRIVILEGE_LEVELS = frozenset({"standard", "elevated", "administrator", "service"})
_RELATIONSHIP_TYPES = frozenset(
    {"member_of", "has_role", "has_permission", "applies_to"}
)


class IdentityNormalizedOutput(BaseModel):
    """Identity adapter result with optional transport error metadata.

    An ``error`` document is a *handled* negative outcome (timeout, rate
    limit, unauthorized, malformed response, unsupported directory, unknown
    identity, unresolved reference) — it becomes an identity status, never a
    crash.
    """

    observations: list[Observation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: dict | None = None


class IdentityToolAdapter(ABC):
    """Boundary between mock raw identity output and typed observations."""

    tool: str = "unknown"

    @abstractmethod
    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise IdentityNormalizationError(
                f"tool produced malformed JSON: {exc}"
            ) from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise IdentityNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise IdentityNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _optional_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _base_output(
    document: dict[str, Any],
    *,
    observations: list[Observation],
    warnings: list[str],
) -> IdentityNormalizedOutput:
    if document.get("error") is not None:
        error = document["error"]
        if not isinstance(error, dict):
            raise IdentityNormalizationError("tool error must be an object")
    return IdentityNormalizedOutput(observations=observations, warnings=warnings)


def _error_output(document: dict[str, Any]) -> IdentityNormalizedOutput:
    error = document.get("error")
    if not isinstance(error, dict):
        raise IdentityNormalizationError("tool error must be an object")
    return IdentityNormalizedOutput(observations=[], warnings=[], error=dict(error))


def _yield_observations(document: dict[str, Any]) -> list[dict[str, Any]]:
    observations = document.get("observations", [])
    if not isinstance(observations, list):
        raise IdentityNormalizationError("observations must be a list")
    return observations


def _directory_for(item: dict[str, Any]) -> str:
    value = item.get("directory") or item.get("target")
    if not isinstance(value, str) or not value.strip():
        raise IdentityNormalizationError("missing or empty string field: directory")
    return normalize_directory(value)


def _identity_kind(item: dict[str, Any]) -> IdentityObservationKind:
    kind = _optional_string(item.get("kind"))
    if kind is None:
        raise IdentityNormalizationError("missing observation kind")
    try:
        return IdentityObservationKind(kind)
    except ValueError as exc:
        raise IdentityNormalizationError(f"unknown observation kind: {kind}") from exc


def _require_identity(item: dict[str, Any]) -> str:
    value = _require_string(item, "identity")
    if value.lower() in {"", "."}:
        raise IdentityNormalizationError("identity must not be empty")
    return value.lower()


class DirectoryDiscoveryAdapter(IdentityToolAdapter):
    """Parses ``discover_directories`` output."""

    tool = "discover_directories"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError(
                "directory discovery output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded directory entry: not an object")
                continue
            try:
                directory = _directory_for(item)
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded directory entry: {exc}")
                continue
            observations.append(
                DirectoryObservation(
                    directory=directory,
                    dns_name=_optional_string(item.get("dns_name")),
                    directory_type=_optional_string(item.get("directory_type")),
                    forest=_optional_string(item.get("forest")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no directories discovered")
        return _base_output(document, observations=observations, warnings=warnings)


class IdentityInventoryAdapter(IdentityToolAdapter):
    """Parses ``inventory_identities`` output, discarding secret fields."""

    tool = "inventory_identities"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError(
                "identity inventory output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded identity entry: not an object")
                continue
            try:
                identity = _require_identity(item)
                directory = _directory_for(item)
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded identity entry: {exc}")
                continue
            principal_type = (
                _optional_string(item.get("principal_type")) or "unknown"
            )
            if principal_type not in _IDENTITY_PRINCIPAL_TYPES:
                warnings.append(
                    f"discarded identity entry: unsupported principal_type "
                    f"{principal_type!r}"
                )
                continue
            privilege_level = (
                _optional_string(item.get("privilege_level")) or "standard"
            )
            if privilege_level not in _PRIVILEGE_LEVELS:
                warnings.append(
                    f"discarded identity entry: unsupported privilege_level "
                    f"{privilege_level!r}"
                )
                continue
            observations.append(
                IdentityObservation(
                    kind=IdentityObservationKind.IDENTITY,
                    identity=identity,
                    directory=directory,
                    principal_type=principal_type,
                    display_name=_optional_string(item.get("display_name")),
                    email=_optional_string(item.get("email")),
                    enabled=bool(item.get("enabled", True)),
                    locked=bool(item.get("locked", False)),
                    privilege_level=privilege_level,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no identities inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class GroupInventoryAdapter(IdentityToolAdapter):
    """Parses ``inventory_groups`` output."""

    tool = "inventory_groups"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError("group inventory output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded group entry: not an object")
                continue
            try:
                directory = _directory_for(item)
                group = normalize_entity_name(EntityType.GROUP, _require_string(item, "group"))
            except (ValueError, IdentityNormalizationError) as exc:
                warnings.append(f"discarded group entry: {exc}")
                continue
            observations.append(
                GroupObservation(
                    group=group,
                    directory=directory,
                    scope_type=_optional_string(item.get("scope_type")),
                    membership_count=item.get("membership_count"),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no groups inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class RoleInventoryAdapter(IdentityToolAdapter):
    """Parses ``inventory_roles`` output."""

    tool = "inventory_roles"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError("role inventory output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded role entry: not an object")
                continue
            try:
                directory = _directory_for(item)
                role = _require_string(item, "role")
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded role entry: {exc}")
                continue
            privilege_level = _optional_string(item.get("privilege_level"))
            if privilege_level is not None and privilege_level not in _PRIVILEGE_LEVELS:
                warnings.append(
                    f"discarded role entry: unsupported privilege_level "
                    f"{privilege_level!r}"
                )
                continue
            observations.append(
                RoleObservation(
                    role=role,
                    directory=directory,
                    privilege_level=privilege_level,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no roles inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class PermissionInventoryAdapter(IdentityToolAdapter):
    """Parses ``inventory_permissions`` output."""

    tool = "inventory_permissions"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError(
                "permission inventory output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded permission entry: not an object")
                continue
            try:
                directory = _directory_for(item)
                permission = _require_string(item, "permission")
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded permission entry: {exc}")
                continue
            observations.append(
                PermissionObservation(
                    permission=permission,
                    directory=directory,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no permissions inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class ResourceInventoryAdapter(IdentityToolAdapter):
    """Parses ``inventory_resources`` output."""

    tool = "inventory_resources"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError(
                "resource inventory output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded resource entry: not an object")
                continue
            try:
                directory = _directory_for(item)
                resource = _require_string(item, "resource")
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded resource entry: {exc}")
                continue
            observations.append(
                ResourceObservation(
                    resource=resource,
                    directory=directory,
                    resource_type=_optional_string(item.get("resource_type")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no resources inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class MembershipObservationAdapter(IdentityToolAdapter):
    """Parses ``observe_membership`` output, collapsing duplicates."""

    tool = "observe_membership"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError("membership output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        seen: set[tuple[str, str, str]] = set()
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded membership entry: not an object")
                continue
            try:
                identity = _require_identity(item)
                directory = _directory_for(item)
                group = normalize_entity_name(EntityType.GROUP, _require_string(item, "group"))
                resolved = bool(item.get("resolved", True))
            except (ValueError, IdentityNormalizationError) as exc:
                warnings.append(f"discarded membership entry: {exc}")
                continue
            key = (identity, directory, group)
            if key in seen:
                warnings.append(
                    f"collapsed duplicate membership: {identity} -> {group}"
                )
                continue
            seen.add(key)
            observations.append(
                MembershipObservation(
                    identity=identity,
                    directory=directory,
                    group=group,
                    resolved=resolved,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no memberships observed")
        return _base_output(document, observations=observations, warnings=warnings)


class RoleAssignmentObservationAdapter(IdentityToolAdapter):
    """Parses ``observe_role_assignment`` output."""

    tool = "observe_role_assignment"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError("role assignment output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded role assignment entry: not an object")
                continue
            try:
                identity = _require_identity(item)
                directory = _directory_for(item)
                role = _require_string(item, "role")
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded role assignment entry: {exc}")
                continue
            observations.append(
                RoleAssignmentObservation(
                    identity=identity,
                    directory=directory,
                    role=role,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no role assignments observed")
        return _base_output(document, observations=observations, warnings=warnings)


class PermissionAssignmentObservationAdapter(IdentityToolAdapter):
    """Parses ``observe_permission_assignment`` output."""

    tool = "observe_permission_assignment"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError(
                "permission assignment output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded permission assignment entry: not an object")
                continue
            try:
                directory = _directory_for(item)
                role = _require_string(item, "role")
                permission = _require_string(item, "permission")
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded permission assignment entry: {exc}")
                continue
            observations.append(
                PermissionAssignmentObservation(
                    role=role,
                    permission=permission,
                    directory=directory,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no permission assignments observed")
        return _base_output(document, observations=observations, warnings=warnings)


class RelationshipAnalysisAdapter(IdentityToolAdapter):
    """Parses ``analyze_relationships`` output."""

    tool = "analyze_relationships"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError(
                "relationship analysis output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded relationship entry: not an object")
                continue
            try:
                directory = _directory_for(item)
                relationship_type = _require_string(item, "relationship_type")
                source = _require_string(item, "source")
                target = _require_string(item, "target")
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded relationship entry: {exc}")
                continue
            if relationship_type not in _RELATIONSHIP_TYPES:
                warnings.append(
                    f"discarded relationship entry: unsupported "
                    f"relationship_type {relationship_type!r}"
                )
                continue
            observations.append(
                RelationshipObservation(
                    relationship_type=relationship_type,
                    source=source,
                    target=target,
                    directory=directory,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no relationships analyzed")
        return _base_output(document, observations=observations, warnings=warnings)


class MetadataObservationAdapter(IdentityToolAdapter):
    """Parses ``observe_metadata`` output, skipping unresolved references."""

    tool = "observe_metadata"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> IdentityNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise IdentityNormalizationError("metadata output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[Observation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded metadata entry: not an object")
                continue
            try:
                identity = _require_identity(item)
                directory = _directory_for(item)
                attribute_key = _require_string(item, "attribute_key")
            except IdentityNormalizationError as exc:
                warnings.append(f"discarded metadata entry: {exc}")
                continue
            if not item.get("resolved", True):
                missing = _optional_string(item.get("missing_reference"))
                warnings.append(
                    f"skipped unresolved metadata: {attribute_key} missing "
                    f"reference {missing or 'unknown'}"
                )
                continue
            observations.append(
                MetadataObservation(
                    identity=identity,
                    directory=directory,
                    attribute_key=attribute_key,
                    attribute_value=_require_string(item, "attribute_value"),
                    source=_optional_string(item.get("source")) or "directory",
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no metadata observed")
        return _base_output(document, observations=observations, warnings=warnings)


def adapter_for_tool(tool: str) -> IdentityToolAdapter:
    """Return the adapter registered for an identity tool name."""
    mapping: dict[str, IdentityToolAdapter] = {
        "discover_directories": DirectoryDiscoveryAdapter(),
        "inventory_identities": IdentityInventoryAdapter(),
        "inventory_groups": GroupInventoryAdapter(),
        "inventory_roles": RoleInventoryAdapter(),
        "inventory_permissions": PermissionInventoryAdapter(),
        "inventory_resources": ResourceInventoryAdapter(),
        "observe_membership": MembershipObservationAdapter(),
        "observe_role_assignment": RoleAssignmentObservationAdapter(),
        "observe_permission_assignment": PermissionAssignmentObservationAdapter(),
        "analyze_relationships": RelationshipAnalysisAdapter(),
        "observe_metadata": MetadataObservationAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise IdentityNormalizationError(f"no adapter for tool: {tool}")
    return adapter


__all__ = [
    "IdentityNormalizedOutput",
    "IdentityToolAdapter",
    "adapter_for_tool",
]
