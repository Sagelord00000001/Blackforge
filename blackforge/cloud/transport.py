from __future__ import annotations

import json
from typing import Any

from blackforge.cloud.mock import _ERROR_TABLE, CLOUD_ACCOUNTS, CLOUD_ESTATES
from blackforge.cloud.models import CloudMode, CloudProvider
from blackforge.cloud.providers import (
    PROVIDER_PROFILES,
    CloudTargetParts,
    parse_cloud_target,
)

_GCP_PROJECT_CONTAINER = "gcp"


class MockCloudTransport:
    """Deterministic mock cloud provider transport.

    Every method returns a JSON document just like a real provider adapter
    would: ``{"tool", "mode", "target", "provider", "observations": [...]}``
    for success or ``{"tool", "mode", "target", "provider", "error":
    {"kind", "message"}}`` for a handled negative outcome. Target strings are
    ``provider`` (bare umbrella), ``provider/container``
    (``aws/aelionix-aws-test``), or ``provider/container/region[/resource]``.

    The transport performs no authorization itself; the engine enforces scope
    before any call reaches it, and no real provider API is ever touched.
    """

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse(target: str) -> CloudTargetParts:
        return parse_cloud_target(target)

    @staticmethod
    def _profile(provider: CloudProvider):
        return PROVIDER_PROFILES.get(provider)

    @staticmethod
    def _emit(doc: dict[str, Any]) -> str:
        return json.dumps(doc, sort_keys=True, default=str)

    def _document(
        self,
        tool: str,
        target: str,
        mode: CloudMode,
        provider: CloudProvider,
        **fields: object,
    ) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "tool": tool,
            "mode": mode.value,
            "target": target,
            "provider": provider.value,
        }
        doc.update(fields)
        return doc

    def _error(
        self,
        tool: str,
        target: str,
        mode: CloudMode,
        provider: CloudProvider,
        kind: str,
        message: str,
    ) -> str:
        doc = self._document(tool, target, mode, provider)
        doc["error"] = {"kind": kind, "message": message}
        return self._emit(doc)

    def _unknown_provider(self, tool: str, target: str, mode: CloudMode) -> str:
        return self._error(
            tool,
            target,
            mode,
            CloudProvider.UNKNOWN,
            "unknown_provider",
            f"cloud provider not modeled: {target}",
        )

    def _resolve_estates(
        self,
        tool: str,
        target: str,
        mode: CloudMode,
        parts: CloudTargetParts,
    ) -> list[tuple[str, dict[str, Any]]] | str:
        """Resolve the container estates a tool should read (or an error doc)."""
        provider_value = parts.provider.value
        if parts.container is None:
            return [
                (name, estate)
                for name, estate in CLOUD_ESTATES.get(provider_value, {}).items()
            ]
        path = f"{provider_value}/{parts.container}"
        error = _ERROR_TABLE.get(path)
        if error is not None:
            return self._error(
                tool,
                target,
                mode,
                parts.provider,
                error["kind"],
                error["message"],
            )
        estate = CLOUD_ESTATES.get(provider_value, {}).get(parts.container)
        if estate is None:
            return self._error(
                tool,
                target,
                mode,
                parts.provider,
                "unsupported_provider",
                f"provider estate not modeled: {parts.container}",
            )
        return [(parts.container, estate)]

    def _stamp(
        self,
        record: dict[str, Any],
        parts: CloudTargetParts,
        container: str,
        *,
        region_default: str | None = None,
    ) -> dict[str, Any]:
        """Add provider/account/project(/region) context to a raw record."""
        stamped = dict(record)
        stamped["provider"] = parts.provider.value
        stamped["account"] = container
        if parts.provider.value == _GCP_PROJECT_CONTAINER:
            stamped["project"] = container
        region = record.get("region") or region_default
        if region is not None:
            stamped["region"] = region
        return stamped

    def _region_default(self, parts: CloudTargetParts) -> str | None:
        profile = self._profile(parts.provider)
        if profile is None or not profile.default_regions:
            return None
        return profile.default_regions[0]

    # ------------------------------------------------------------------
    # Provider-level tools
    # ------------------------------------------------------------------
    def discover_providers(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider("discover_providers", target, mode)
        provider_value = parts.provider.value
        profile = self._profile(parts.provider)
        row: dict[str, Any] = {
            "kind": "provider",
            "provider": provider_value,
            "container_type": profile.container_type.value,
            "accounts": len(CLOUD_ACCOUNTS.get(provider_value, {})),
            "regions": list(profile.default_regions),
        }
        return self._emit(
            self._document(
                "discover_providers",
                target,
                mode,
                parts.provider,
                observations=[row],
            )
        )

    def inventory_accounts(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider("inventory_accounts", target, mode)
        resolved = self._resolve_estates(
            "inventory_accounts", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        profile = self._profile(parts.provider)
        output = [
            {
                "kind": "account",
                "provider": parts.provider.value,
                "account": name,
                "container_type": profile.container_type.value,
                "account_id": estate["account"]["account_id"],
                "regions": list(estate["account"]["regions"]),
            }
            for name, estate in resolved
        ]
        return self._emit(
            self._document(
                "inventory_accounts",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    # ------------------------------------------------------------------
    # Container-level tools
    # ------------------------------------------------------------------
    def inventory_projects(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider("inventory_projects", target, mode)
        resolved = self._resolve_estates(
            "inventory_projects", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for project in estate["projects"]:
                row = dict(project)
                row["kind"] = "project"
                row["provider"] = parts.provider.value
                row["account"] = container
                output.append(row)
        return self._emit(
            self._document(
                "inventory_projects",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    def inventory_resources(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider("inventory_resources", target, mode)
        resolved = self._resolve_estates(
            "inventory_resources", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []

        def add(name: str, resource_type: str, container: str) -> None:
            output.append(
                self._stamp(
                    {
                        "kind": "cloud_resource",
                        "resource": name,
                        "resource_type": resource_type,
                    },
                    parts,
                    container,
                    region_default=region_default,
                )
            )

        for container, estate in resolved:
            for record in estate["resources"]["compute"]:
                add(record["name"], "compute_instance", container)
            for record in estate["resources"]["storage"]:
                storage_type = str(record.get("storage_type") or "")
                resource_type = (
                    "storage_bucket"
                    if storage_type == "object"
                    else "storage_disk"
                    if storage_type == "block"
                    else "storage"
                )
                add(record["name"], resource_type, container)
            for record in estate["resources"]["database"]:
                add(record["name"], "database", container)
            for record in estate["resources"]["network"]:
                network_type = record.get("network_type") or "virtual_network"
                add(record["name"], network_type, container)
            for record in estate["resources"]["cluster"]:
                add(record["name"], "cluster", container)
            for record in estate["resources"]["container"]:
                add(record["name"], "container", container)
            for record in estate["secret_references"]:
                add(record["name"], "secret", container)
        return self._emit(
            self._document(
                "inventory_resources",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    def _typed_resources(
        self,
        tool: str,
        target: str,
        mode: CloudMode,
        resource_key: str,
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(tool, target, mode)
        resolved = self._resolve_estates(tool, target, mode, parts)
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate["resources"][resource_key]:
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = resource_key
                output.append(row)
        return self._emit(
            self._document(tool, target, mode, parts.provider, observations=output)
        )

    def observe_compute(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._typed_resources("observe_compute", target, mode, "compute")

    def observe_storage(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._typed_resources("observe_storage", target, mode, "storage")

    def observe_databases(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._typed_resources("observe_databases", target, mode, "database")

    def observe_networks(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._typed_resources("observe_networks", target, mode, "network")

    def observe_containers(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._typed_resources("observe_containers", target, mode, "container")

    def observe_clusters(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._typed_resources("observe_clusters", target, mode, "cluster")

    def analyze_public_exposure(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(
                "analyze_public_exposure", target, mode
            )
        resolved = self._resolve_estates(
            "analyze_public_exposure", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate["exposures"]:
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = "public_exposure"
                output.append(row)
        return self._emit(
            self._document(
                "analyze_public_exposure",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    def observe_security_configuration(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(
                "observe_security_configuration", target, mode
            )
        resolved = self._resolve_estates(
            "observe_security_configuration", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate["security_configuration"]:
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = "security_configuration"
                output.append(row)
        return self._emit(
            self._document(
                "observe_security_configuration",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    def observe_secret_references(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(
                "observe_secret_references", target, mode
            )
        resolved = self._resolve_estates(
            "observe_secret_references", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate["secret_references"]:
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = "secret_reference"
                output.append(row)
        return self._emit(
            self._document(
                "observe_secret_references",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    def observe_iam_identities(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._iam_rows(
            "observe_iam_identities", target, mode, "iam_identities"
        )

    def observe_iam_roles(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._iam_rows("observe_iam_roles", target, mode, "iam_roles")

    def observe_iam_permissions(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        return self._iam_rows(
            "observe_iam_permissions", target, mode, "iam_permissions"
        )

    def _iam_rows(
        self,
        tool: str,
        target: str,
        mode: CloudMode,
        record_key: str,
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(tool, target, mode)
        resolved = self._resolve_estates(tool, target, mode, parts)
        if isinstance(resolved, str):
            return resolved
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate[record_key]:
                row = self._stamp(record, parts, container)
                row["kind"] = record_key
                output.append(row)
        return self._emit(
            self._document(tool, target, mode, parts.provider, observations=output)
        )

    def analyze_resource_relationships(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(
                "analyze_resource_relationships", target, mode
            )
        resolved = self._resolve_estates(
            "analyze_resource_relationships", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate["relationships"]:
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = "resource_relationship"
                output.append(row)
        return self._emit(
            self._document(
                "analyze_resource_relationships",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    # ------------------------------------------------------------------
    # Edge / origin-boundary tools
    # ------------------------------------------------------------------
    def observe_edge_architecture(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(
                "observe_edge_architecture", target, mode
            )
        resolved = self._resolve_estates(
            "observe_edge_architecture", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate.get("edges", []):
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = "edge_architecture"
                output.append(row)
        return self._emit(
            self._document(
                "observe_edge_architecture",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    def analyze_origin_candidates(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(
                "analyze_origin_candidates", target, mode
            )
        resolved = self._resolve_estates(
            "analyze_origin_candidates", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate.get("origin_candidates", []):
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = "origin_candidate"
                output.append(row)
        return self._emit(
            self._document(
                "analyze_origin_candidates",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )

    def observe_transport_security(
        self, target: str, mode: CloudMode = CloudMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        if parts.provider is CloudProvider.UNKNOWN:
            return self._unknown_provider(
                "observe_transport_security", target, mode
            )
        resolved = self._resolve_estates(
            "observe_transport_security", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        region_default = self._region_default(parts)
        output: list[dict[str, Any]] = []
        for container, estate in resolved:
            for record in estate.get("transport_security", []):
                row = self._stamp(
                    record,
                    parts,
                    container,
                    region_default=region_default,
                )
                row["kind"] = "transport_security"
                output.append(row)
        return self._emit(
            self._document(
                "observe_transport_security",
                target,
                mode,
                parts.provider,
                observations=output,
            )
        )


__all__ = ["MockCloudTransport"]
