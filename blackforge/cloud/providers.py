from __future__ import annotations

from pydantic import BaseModel, Field

from blackforge.cloud.models import CloudContainerType, CloudProvider

MODELED_PROVIDERS: frozenset[CloudProvider] = frozenset(
    {CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP}
)


class CloudProviderProfile(BaseModel):
    """Typed provider metadata: container naming, regions, resource kinds.

    ``resource_types`` enumerates the deterministic resource kinds the mock
    can observe for that provider. The profile is purely descriptive — it is
    never used to guess anything about a live cloud account.
    """

    provider: CloudProvider
    container_type: CloudContainerType
    container_label: str
    default_regions: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)


PROVIDER_PROFILES: dict[CloudProvider, CloudProviderProfile] = {
    CloudProvider.AWS: CloudProviderProfile(
        provider=CloudProvider.AWS,
        container_type=CloudContainerType.ACCOUNT,
        container_label="account",
        default_regions=["us-test-1", "eu-test-1"],
        resource_types=[
            "compute_instance",
            "storage_bucket",
            "storage_disk",
            "database",
            "virtual_network",
            "subnet",
            "security_group",
            "firewall_rule",
            "load_balancer",
            "cluster",
            "container",
            "secret",
        ],
    ),
    CloudProvider.AZURE: CloudProviderProfile(
        provider=CloudProvider.AZURE,
        container_type=CloudContainerType.SUBSCRIPTION,
        container_label="subscription",
        default_regions=["us-test-central", "eu-test-west"],
        resource_types=[
            "compute_instance",
            "storage_bucket",
            "database",
            "virtual_network",
            "subnet",
            "security_group",
            "load_balancer",
            "cluster",
            "container",
            "secret",
        ],
    ),
    CloudProvider.GCP: CloudProviderProfile(
        provider=CloudProvider.GCP,
        container_type=CloudContainerType.PROJECT,
        container_label="project",
        default_regions=["us-test-central1", "eu-test-west1"],
        resource_types=[
            "compute_instance",
            "storage_bucket",
            "database",
            "virtual_network",
            "subnet",
            "cluster",
            "container",
            "secret",
        ],
    ),
}


def cloud_container_type(provider: CloudProvider) -> CloudContainerType | None:
    """The container type (account/subscription/project) for a provider."""
    profile = PROVIDER_PROFILES.get(provider)
    return profile.container_type if profile is not None else None


def cloud_container_label(provider: CloudProvider) -> str:
    """Human label for a provider's container (``account``, ``subscription``…)."""
    profile = PROVIDER_PROFILES.get(provider)
    return profile.container_label if profile is not None else "container"


class CloudTargetParts(BaseModel):
    """Parsed ``provider/container/region[/resource]`` cloud target.

    Only the leading provider token is required; container, region, and
    resource segments are optional (bare ``aws`` is a provider umbrella).
    """

    provider: CloudProvider
    container: str | None = None
    region: str | None = None
    resource: str | None = None


def parse_cloud_target(target: str) -> CloudTargetParts:
    """Parse a cloud target string into typed provider parts.

    The provider token is matched against the modeled provider set; anything
    else resolves to :attr:`CloudProvider.UNKNOWN` and the engine fails
    closed before any transport call. Extra path segments are retained so
    deeper estate paths can be addressed later.
    """
    segments = [segment for segment in target.strip().lower().split("/") if segment]
    provider: CloudProvider
    try:
        provider = CloudProvider(segments[0]) if segments else CloudProvider.UNKNOWN
    except ValueError:
        provider = CloudProvider.UNKNOWN
    if provider not in MODELED_PROVIDERS:
        provider = CloudProvider.UNKNOWN
    container = segments[1] if len(segments) > 1 else None
    region = segments[2] if len(segments) > 2 else None
    resource = segments[3] if len(segments) > 3 else None
    return CloudTargetParts(
        provider=provider,
        container=container,
        region=region,
        resource=resource,
    )


def provider_for_target(target: str) -> CloudProvider:
    """Resolve the typed provider of a target without an engine context."""
    return parse_cloud_target(target).provider


__all__ = [
    "MODELED_PROVIDERS",
    "CloudProviderProfile",
    "CloudTargetParts",
    "PROVIDER_PROFILES",
    "cloud_container_label",
    "cloud_container_type",
    "parse_cloud_target",
    "provider_for_target",
]
