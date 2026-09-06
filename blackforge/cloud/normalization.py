from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.cloud.models import (
    AccountObservation,
    CloudObservation,
    CloudProvider,
    CloudResourceObservation,
    CloudResourceType,
    ClusterObservation,
    ComputeObservation,
    ContainerObservation,
    DatabaseObservation,
    EdgeArchitectureObservation,
    IamIdentityObservation,
    IamPermissionObservation,
    IamRoleObservation,
    NetworkObservation,
    OriginCandidateObservation,
    ProjectObservation,
    ProviderObservation,
    PublicExposureObservation,
    ResourceRelationshipObservation,
    SecretReferenceObservation,
    SecurityConfigurationObservation,
    StorageObservation,
    TransportSecurityObservation,
)
from blackforge.core.errors import CloudNormalizationError

_ALLOWED_RELATIONSHIP_TYPES = frozenset(
    {
        "contains",
        "uses",
        "depends_on",
        "connects_to",
        "applies_to",
        "hosts",
        "located_in",
        "belongs_to",
        "has_role",
        "has_permission",
        "associated_with",
    }
)


class CloudNormalizedOutput(BaseModel):
    """Cloud adapter result with optional transport error metadata.

    An ``error`` document is a *handled* negative outcome (timeout, rate
    limit, unauthorized, malformed response, unknown / unsupported provider,
    unknown account, unresolved reference) — it becomes a cloud status, never
    a crash.
    """

    observations: list[CloudObservation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: dict | None = None


class CloudToolAdapter(ABC):
    """Boundary between mock raw cloud output and typed observations."""

    tool: str = "unknown"

    @abstractmethod
    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise CloudNormalizationError(
                f"tool produced malformed JSON: {exc}"
            ) from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise CloudNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CloudNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _optional_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "yes", "1"}:
        return True
    if isinstance(value, str) and value.strip().lower() in {"false", "no", "0"}:
        return False
    return None


def _base_output(
    document: dict[str, Any],
    *,
    observations: list[CloudObservation],
    warnings: list[str],
) -> CloudNormalizedOutput:
    return CloudNormalizedOutput(observations=observations, warnings=warnings)


def _error_output(document: dict[str, Any]) -> CloudNormalizedOutput:
    error = document.get("error")
    if not isinstance(error, dict):
        raise CloudNormalizationError("tool error must be an object")
    return CloudNormalizedOutput(observations=[], warnings=[], error=dict(error))


def _yield_observations(document: dict[str, Any]) -> list[dict[str, Any]]:
    observations = document.get("observations", [])
    if not isinstance(observations, list):
        raise CloudNormalizationError("observations must be a list")
    return observations


def _provider(item: dict[str, Any]) -> CloudProvider:
    value = _require_string(item, "provider")
    try:
        return CloudProvider(value)
    except ValueError as exc:
        raise CloudNormalizationError(f"unknown cloud provider: {value}") from exc


def _document_context(item: dict[str, Any]) -> tuple[str, str | None, str | None, str | None]:
    """Extract (account, project, region) that transport stamps on every row."""
    account = _optional_string(item.get("account"))
    project = _optional_string(item.get("project"))
    region = _optional_string(item.get("region"))
    return account, project, region


class ProviderDiscoveryAdapter(CloudToolAdapter):
    """Parses ``discover_providers`` output."""

    tool = "discover_providers"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("provider discovery output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded provider entry: not an object")
                continue
            try:
                provider = _provider(item)
            except CloudNormalizationError as exc:
                warnings.append(f"discarded provider entry: {exc}")
                continue
            observations.append(
                ProviderObservation(
                    provider=provider,
                    container_type=_container_type(item.get("container_type")),
                    accounts=item.get("accounts"),
                    regions=_optional_list(item.get("regions")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no providers discovered")
        return _base_output(document, observations=observations, warnings=warnings)


class AccountInventoryAdapter(CloudToolAdapter):
    """Parses ``inventory_accounts`` output."""

    tool = "inventory_accounts"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("account inventory output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded account entry: not an object")
                continue
            try:
                provider = _provider(item)
                account = _require_string(item, "account")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded account entry: {exc}")
                continue
            observations.append(
                AccountObservation(
                    provider=provider,
                    account=account,
                    container_type=_container_type(item.get("container_type")),
                    account_id=_optional_string(item.get("account_id")),
                    regions=_optional_list(item.get("regions")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no accounts inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class ProjectInventoryAdapter(CloudToolAdapter):
    """Parses ``inventory_projects`` output."""

    tool = "inventory_projects"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("project inventory output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded project entry: not an object")
                continue
            try:
                provider = _provider(item)
                project = _require_string(item, "project")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded project entry: {exc}")
                continue
            account, _, _ = _document_context(item)
            observations.append(
                ProjectObservation(
                    provider=provider,
                    project=project,
                    account=account,
                    project_type=_optional_string(item.get("project_type")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no projects inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class ResourceInventoryAdapter(CloudToolAdapter):
    """Parses ``inventory_resources`` output (generic container-level pass)."""

    tool = "inventory_resources"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("resource inventory output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded resource entry: not an object")
                continue
            try:
                provider = _provider(item)
                resource = _require_string(item, "resource")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded resource entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                CloudResourceObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    resource_type=_resource_type(item.get("resource_type")),
                    name=resource,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no resources inventoried")
        return _base_output(document, observations=observations, warnings=warnings)


class ComputeObservationAdapter(CloudToolAdapter):
    """Parses ``observe_compute`` output."""

    tool = "observe_compute"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("compute output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded compute entry: not an object")
                continue
            try:
                provider = _provider(item)
                name = _require_string(item, "name")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded compute entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                ComputeObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    name=name,
                    instance_type=_optional_string(item.get("instance_type")),
                    state=_optional_string(item.get("state")),
                    public_endpoint=_optional_string(item.get("public_endpoint")),
                    private_endpoints=_optional_list(item.get("private_endpoints")),
                    tags=_tags(item.get("tags")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no compute observed")
        return _base_output(document, observations=observations, warnings=warnings)


class StorageObservationAdapter(CloudToolAdapter):
    """Parses ``observe_storage`` output."""

    tool = "observe_storage"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("storage output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded storage entry: not an object")
                continue
            try:
                provider = _provider(item)
                name = _require_string(item, "name")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded storage entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                StorageObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    name=name,
                    storage_type=_optional_string(item.get("storage_type")),
                    public_access=_optional_bool(item.get("public_access")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no storage observed")
        return _base_output(document, observations=observations, warnings=warnings)


class DatabaseObservationAdapter(CloudToolAdapter):
    """Parses ``observe_databases`` output."""

    tool = "observe_databases"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("database output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded database entry: not an object")
                continue
            try:
                provider = _provider(item)
                name = _require_string(item, "name")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded database entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                DatabaseObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    name=name,
                    engine=_optional_string(item.get("engine")),
                    public_access=_optional_bool(item.get("public_access")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no databases observed")
        return _base_output(document, observations=observations, warnings=warnings)


class NetworkObservationAdapter(CloudToolAdapter):
    """Parses ``observe_networks`` output."""

    tool = "observe_networks"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("network output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded network entry: not an object")
                continue
            try:
                provider = _provider(item)
                name = _require_string(item, "name")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded network entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                NetworkObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    name=name,
                    network_type=_optional_string(item.get("network_type")),
                    ingress_allowed=_optional_bool(item.get("ingress_allowed")),
                    attached_cidrs=_optional_list(item.get("attached_cidrs")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no networks observed")
        return _base_output(document, observations=observations, warnings=warnings)


class PublicExposureAdapter(CloudToolAdapter):
    """Parses ``analyze_public_exposure`` output."""

    tool = "analyze_public_exposure"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("public exposure output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded exposure entry: not an object")
                continue
            try:
                provider = _provider(item)
                resource = _require_string(item, "resource")
                exposed = bool(item.get("exposed", False))
            except CloudNormalizationError as exc:
                warnings.append(f"discarded exposure entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                PublicExposureObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    resource_type=_resource_type(item.get("resource_type")),
                    resource=resource,
                    exposed=exposed,
                    endpoint=_optional_string(item.get("endpoint")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no exposures analyzed")
        return _base_output(document, observations=observations, warnings=warnings)


class SecurityConfigurationAdapter(CloudToolAdapter):
    """Parses ``observe_security_configuration`` output.

    Unresolved references (``resolved`` False) are reported as warnings and
    never become findings.
    """

    tool = "observe_security_configuration"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError(
                "security configuration output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded security config entry: not an object")
                continue
            try:
                provider = _provider(item)
                entity = _require_string(item, "entity")
                attribute_item = _require_string(item, "item")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded security config entry: {exc}")
                continue
            if not item.get("resolved", True):
                missing = _optional_string(item.get("missing_reference"))
                warnings.append(
                    f"skipped unresolved security config: {attribute_item} "
                    f"missing reference {missing or 'unknown'}"
                )
                continue
            account, project, region = _document_context(item)
            observations.append(
                SecurityConfigurationObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    entity_type=_optional_string(item.get("entity_type")),
                    entity=entity,
                    item=attribute_item,
                    value=_optional_string(item.get("value")),
                    source=_optional_string(item.get("source")) or "provider",
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no security configuration observed")
        return _base_output(document, observations=observations, warnings=warnings)


class SecretReferenceAdapter(CloudToolAdapter):
    """Parses ``observe_secret_references`` output.

    Only name, kind, and the provider-reported reference are carried. Any
    secret value that leaked into the raw output is redacted at the artifact
    boundary and never attached here.
    """

    tool = "observe_secret_references"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError(
                "secret reference output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded secret reference entry: not an object")
                continue
            try:
                provider = _provider(item)
                name = _require_string(item, "name")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded secret reference entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                SecretReferenceObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    name=name,
                    secret_kind=_optional_string(item.get("secret_kind")),
                    reference=_optional_string(item.get("reference")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no secret references observed")
        return _base_output(document, observations=observations, warnings=warnings)


class IamIdentityAdapter(CloudToolAdapter):
    """Parses ``observe_iam_identities`` output."""

    tool = "observe_iam_identities"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("iam identity output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded iam identity entry: not an object")
                continue
            try:
                provider = _provider(item)
                account = _require_string(item, "account")
                identity = _require_string(item, "identity")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded iam identity entry: {exc}")
                continue
            observations.append(
                IamIdentityObservation(
                    provider=provider,
                    account=account,
                    identity=identity,
                    principal_type=_optional_string(item.get("principal_type")),
                    enabled=_optional_bool(item.get("enabled")),
                    mfa_enabled=_optional_bool(item.get("mfa_enabled")),
                    privileges=_optional_list(item.get("privileges")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no iam identities observed")
        return _base_output(document, observations=observations, warnings=warnings)


class IamRoleAdapter(CloudToolAdapter):
    """Parses ``observe_iam_roles`` output."""

    tool = "observe_iam_roles"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("iam role output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded iam role entry: not an object")
                continue
            try:
                provider = _provider(item)
                account = _require_string(item, "account")
                role = _require_string(item, "role")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded iam role entry: {exc}")
                continue
            observations.append(
                IamRoleObservation(
                    provider=provider,
                    account=account,
                    role=role,
                    description=_optional_string(item.get("description")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no iam roles observed")
        return _base_output(document, observations=observations, warnings=warnings)


class IamPermissionAdapter(CloudToolAdapter):
    """Parses ``observe_iam_permissions`` output."""

    tool = "observe_iam_permissions"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("iam permission output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded iam permission entry: not an object")
                continue
            try:
                provider = _provider(item)
                account = _require_string(item, "account")
                permission = _require_string(item, "permission")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded iam permission entry: {exc}")
                continue
            observations.append(
                IamPermissionObservation(
                    provider=provider,
                    account=account,
                    permission=permission,
                    effect=_optional_string(item.get("effect")),
                    action=_optional_string(item.get("action")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no iam permissions observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ResourceRelationshipAdapter(CloudToolAdapter):
    """Parses ``analyze_resource_relationships`` output."""

    tool = "analyze_resource_relationships"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError(
                "resource relationship output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded relationship entry: not an object")
                continue
            try:
                provider = _provider(item)
                relationship_type = _require_string(item, "relationship_type")
                source = _require_string(item, "source")
                target = _require_string(item, "target")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded relationship entry: {exc}")
                continue
            if relationship_type not in _ALLOWED_RELATIONSHIP_TYPES:
                warnings.append(
                    f"discarded relationship entry: unsupported "
                    f"relationship_type {relationship_type!r}"
                )
                continue
            account, project, region = _document_context(item)
            observations.append(
                ResourceRelationshipObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    relationship_type=relationship_type,
                    source_type=_resource_type(item.get("source_type")),
                    source=source,
                    target_type=_resource_type(item.get("target_type")),
                    target=target,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no resource relationships analyzed")
        return _base_output(document, observations=observations, warnings=warnings)


class ContainerObservationAdapter(CloudToolAdapter):
    """Parses ``observe_containers`` output."""

    tool = "observe_containers"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("container output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded container entry: not an object")
                continue
            try:
                provider = _provider(item)
                name = _require_string(item, "name")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded container entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                ContainerObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    name=name,
                    image=_optional_string(item.get("image")),
                    state=_optional_string(item.get("state")),
                    exposed_ports=_optional_list(item.get("exposed_ports")),
                    cluster=_optional_string(item.get("cluster")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no containers observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ClusterObservationAdapter(CloudToolAdapter):
    """Parses ``observe_clusters`` output."""

    tool = "observe_clusters"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("cluster output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded cluster entry: not an object")
                continue
            try:
                provider = _provider(item)
                name = _require_string(item, "name")
                node_count_value = item.get("node_count")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded cluster entry: {exc}")
                continue
            account, project, region = _document_context(item)
            node_count: int | None = None
            if isinstance(node_count_value, int):
                node_count = node_count_value
            observations.append(
                ClusterObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    name=name,
                    version=_optional_string(item.get("version")),
                    node_count=node_count,
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no clusters observed")
        return _base_output(document, observations=observations, warnings=warnings)


class EdgeArchitectureAdapter(CloudToolAdapter):
    """Parses ``observe_edge_architecture`` output."""

    tool = "observe_edge_architecture"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("edge architecture output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded edge architecture entry: not an object")
                continue
            try:
                provider = _provider(item)
                edge = _require_string(item, "edge")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded edge architecture entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                EdgeArchitectureObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    edge=edge,
                    edge_kind=_optional_string(item.get("edge_kind")),
                    domain=_optional_string(item.get("domain")),
                    origin_endpoints=_optional_list(item.get("origin_endpoints")),
                    protected_applications=_optional_list(
                        item.get("protected_applications")
                    ),
                    directly_reachable_origin=_optional_bool(
                        item.get("directly_reachable_origin")
                    ),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no edge architecture observed")
        return _base_output(document, observations=observations, warnings=warnings)


class OriginCandidateAdapter(CloudToolAdapter):
    """Parses ``analyze_origin_candidates`` output.

    Every candidate is a *correlation hypothesis*, never a claim: its
    ``evidence_status`` stage and ``validation_status`` are preserved
    verbatim and kept independent of confidence.
    """

    tool = "analyze_origin_candidates"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError("origin candidate output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded origin candidate entry: not an object")
                continue
            try:
                provider = _provider(item)
                domain = _require_string(item, "domain")
                candidate_address = _require_string(item, "candidate_address")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded origin candidate entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                OriginCandidateObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    domain=domain,
                    candidate_address=candidate_address,
                    candidate_endpoint=_optional_string(
                        item.get("candidate_endpoint")
                    ),
                    source_category=_optional_string(item.get("source_category")),
                    evidence_ids=_optional_list(item.get("evidence_ids")),
                    correlation_reasons=_optional_list(
                        item.get("correlation_reasons")
                    ),
                    confidence_label=_optional_string(item.get("confidence_label")),
                    evidence_status=_optional_string(item.get("evidence_status"))
                    or "hypothesized",
                    validation_status=_optional_string(item.get("validation_status"))
                    or "unvalidated",
                    authorization_requirements=_optional_list(
                        item.get("authorization_requirements")
                    ),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no origin candidates analyzed")
        return _base_output(document, observations=observations, warnings=warnings)


class TransportSecurityAdapter(CloudToolAdapter):
    """Parses ``observe_transport_security`` output."""

    tool = "observe_transport_security"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> CloudNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise CloudNormalizationError(
                "transport security output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[CloudObservation] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded transport security entry: not an object")
                continue
            try:
                provider = _provider(item)
                endpoint = _require_string(item, "endpoint")
            except CloudNormalizationError as exc:
                warnings.append(f"discarded transport security entry: {exc}")
                continue
            account, project, region = _document_context(item)
            observations.append(
                TransportSecurityObservation(
                    provider=provider,
                    account=account,
                    project=project,
                    region=region,
                    endpoint=endpoint,
                    tls_enforced=_optional_bool(item.get("tls_enforced")),
                    tls_version=_optional_string(item.get("tls_version")),
                    certificate_valid=_optional_bool(item.get("certificate_valid")),
                    source=_optional_string(item.get("source")) or "provider",
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no transport security observed")
        return _base_output(document, observations=observations, warnings=warnings)


def _container_type(value: object) -> str | None:
    text = _optional_string(value)
    if text is None:
        return None
    from blackforge.cloud.models import CloudContainerType

    try:
        return CloudContainerType(text).value
    except ValueError as exc:
        raise CloudNormalizationError(f"unknown container type: {text}") from exc


def _resource_type(value: object) -> CloudResourceType:
    if value is None:
        return CloudResourceType.UNKNOWN
    text = str(value).strip().lower()
    try:
        return CloudResourceType(text)
    except ValueError:
        return CloudResourceType.UNKNOWN


def _tags(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    return dict(value)


def adapter_for_tool(tool: str) -> CloudToolAdapter:
    """Return the adapter registered for a cloud tool name."""
    mapping: dict[str, CloudToolAdapter] = {
        "discover_providers": ProviderDiscoveryAdapter(),
        "inventory_accounts": AccountInventoryAdapter(),
        "inventory_projects": ProjectInventoryAdapter(),
        "inventory_resources": ResourceInventoryAdapter(),
        "observe_compute": ComputeObservationAdapter(),
        "observe_storage": StorageObservationAdapter(),
        "observe_databases": DatabaseObservationAdapter(),
        "observe_networks": NetworkObservationAdapter(),
        "analyze_public_exposure": PublicExposureAdapter(),
        "observe_security_configuration": SecurityConfigurationAdapter(),
        "observe_secret_references": SecretReferenceAdapter(),
        "observe_iam_identities": IamIdentityAdapter(),
        "observe_iam_roles": IamRoleAdapter(),
        "observe_iam_permissions": IamPermissionAdapter(),
        "analyze_resource_relationships": ResourceRelationshipAdapter(),
        "observe_containers": ContainerObservationAdapter(),
        "observe_clusters": ClusterObservationAdapter(),
        "observe_edge_architecture": EdgeArchitectureAdapter(),
        "analyze_origin_candidates": OriginCandidateAdapter(),
        "observe_transport_security": TransportSecurityAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise CloudNormalizationError(f"no adapter for tool: {tool}")
    return adapter


__all__ = [
    "CloudNormalizedOutput",
    "CloudToolAdapter",
    "adapter_for_tool",
]
