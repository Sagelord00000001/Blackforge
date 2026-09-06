from __future__ import annotations

import json
from typing import Any

from blackforge.container.addressing import (
    ContainerTargetParts,
    parse_container_target,
)
from blackforge.container.mock import (
    _ERROR_TABLE,
    _FABRICATED_CLUSTER,
    CLUSTER_CREDENTIAL_SYNTHETICS,
    CLUSTERS,
)
from blackforge.container.models import ContainerMode


class MockContainerTransport:
    """Deterministic mock Kubernetes / container platform transport.

    Every method returns a JSON document just like a real cluster adapter
    would: ``{"tool", "mode", "target", "cluster", "observations": [...]}``
    for success or ``{"tool", "mode", "target", "cluster", "error":
    {"kind", "message"}}`` for a handled negative outcome. Target strings are
    ``cluster`` (bare umbrella) or ``cluster/namespace``.

    The transport performs no authorization itself; the engine enforces scope
    before any call reaches it, and no real cluster API is ever touched.
    """

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse(target: str) -> ContainerTargetParts:
        return parse_container_target(target)

    @staticmethod
    def _emit(doc: dict[str, Any]) -> str:
        return json.dumps(doc, sort_keys=True, default=str)

    def _document(
        self,
        tool: str,
        target: str,
        mode: ContainerMode,
        cluster: str,
        **fields: object,
    ) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "tool": tool,
            "mode": mode.value,
            "target": target,
            "cluster": cluster,
        }
        doc.update(fields)
        return doc

    def _error(
        self,
        tool: str,
        target: str,
        mode: ContainerMode,
        cluster: str,
        kind: str,
        message: str,
    ) -> str:
        doc = self._document(tool, target, mode, cluster)
        doc["error"] = {"kind": kind, "message": message}
        return self._emit(doc)

    def _table_error(
        self, tool: str, target: str, mode: ContainerMode, cluster: str
    ) -> str | None:
        """Return a handled error doc for a known synthetic cluster, else None."""
        error = _ERROR_TABLE.get(cluster)
        if error is None:
            return None
        return self._error(
            tool, target, mode, cluster, error["kind"], error["message"]
        )

    def _resolve(
        self,
        tool: str,
        target: str,
        mode: ContainerMode,
        parts: ContainerTargetParts,
    ) -> tuple[str, dict[str, Any]] | str:
        """Resolve ``(cluster, estate)`` or return an error doc."""
        if parts.cluster == _FABRICATED_CLUSTER:
            return self._error(
                tool,
                target,
                mode,
                parts.cluster,
                "unsupported_cluster",
                "cluster not modeled by this platform",
            )
        table_error = self._table_error(tool, target, mode, parts.cluster)
        if table_error is not None:
            return table_error
        estate = CLUSTERS.get(parts.cluster)
        if estate is None:
            return self._error(
                tool,
                target,
                mode,
                parts.cluster,
                "unknown_cluster",
                f"cluster not modeled: {parts.cluster}",
            )
        if parts.namespace is not None and not self._namespace_exists(
            estate, parts.namespace
        ):
            return self._error(
                tool,
                target,
                mode,
                parts.cluster,
                "unknown_namespace",
                f"namespace not modeled on {parts.cluster}: {parts.namespace}",
            )
        return parts.cluster, estate

    @staticmethod
    def _namespace_exists(estate: dict[str, Any], namespace: str) -> bool:
        return any(
            row.get("namespace") == namespace
            for row in estate.get("namespaces", [])
        )

    def _rows(
        self,
        tool: str,
        target: str,
        mode: ContainerMode,
        collection_key: str,
        *,
        namespaced: bool,
        stamp_kind: str,
    ) -> str:
        parts = self._parse(target)
        resolved = self._resolve(tool, target, mode, parts)
        if isinstance(resolved, str):
            return resolved
        cluster, estate = resolved
        output: list[dict[str, Any]] = []
        for row in estate.get(collection_key, []):
            if (
                namespaced
                and parts.namespace is not None
                and row.get("namespace") != parts.namespace
            ):
                continue
            item = dict(row)
            item.setdefault("cluster", cluster)
            if namespaced:
                item.setdefault("namespace", parts.namespace or row.get("namespace"))
            item["kind"] = stamp_kind
            output.append(item)
        return self._emit(
            self._document(tool, target, mode, cluster, observations=output)
        )

    # ------------------------------------------------------------------
    # Fleet / cluster tools
    # ------------------------------------------------------------------
    def observe_clusters(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        resolved = self._resolve("observe_clusters", target, mode, parts)
        if isinstance(resolved, str):
            return resolved
        cluster, estate = resolved
        row = dict(estate["cluster"])
        row["kind"] = "cluster"
        return self._emit(
            self._document(
                "observe_clusters",
                target,
                mode,
                cluster,
                observations=[row],
            )
        )

    def observe_nodes(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_nodes", target, mode, "nodes", namespaced=False, stamp_kind="node"
        )

    def enumerate_namespaces(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        resolved = self._resolve("enumerate_namespaces", target, mode, parts)
        if isinstance(resolved, str):
            return resolved
        cluster, estate = resolved
        output = []
        for row in estate.get("namespaces", []):
            item = dict(row)
            item["kind"] = "namespace"
            output.append(item)
        return self._emit(
            self._document(
                "enumerate_namespaces",
                target,
                mode,
                cluster,
                observations=output,
            )
        )

    # ------------------------------------------------------------------
    # Namespace-scoped tools
    # ------------------------------------------------------------------
    def observe_workloads(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        resolved = self._resolve("observe_workloads", target, mode, parts)
        if isinstance(resolved, str):
            return resolved
        cluster, estate = resolved
        output: list[dict[str, Any]] = []
        for key, stamp in (("workloads", "workload"), ("deployments", "deployment")):
            for row in estate.get(key, []):
                if parts.namespace is not None and row.get("namespace") != parts.namespace:
                    continue
                item = dict(row)
                item.setdefault("cluster", cluster)
                item.setdefault("namespace", parts.namespace or row.get("namespace"))
                item["kind"] = stamp
                output.append(item)
        return self._emit(
            self._document(
                "observe_workloads",
                target,
                mode,
                cluster,
                observations=output,
            )
        )

    def observe_pods(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_pods", target, mode, "pods", namespaced=True, stamp_kind="pod"
        )

    def observe_containers(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_containers",
            target,
            mode,
            "containers",
            namespaced=True,
            stamp_kind="container",
        )

    def observe_image_metadata(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        resolved = self._resolve("observe_image_metadata", target, mode, parts)
        if isinstance(resolved, str):
            return resolved
        cluster, estate = resolved
        output: list[dict[str, Any]] = []
        for key, stamp in (("registries", "registry"), ("images", "image")):
            for row in estate.get(key, []):
                if parts.namespace is not None and row.get("namespace") != parts.namespace:
                    continue
                item = dict(row)
                item.setdefault("cluster", cluster)
                item.setdefault("namespace", parts.namespace or row.get("namespace"))
                item["kind"] = stamp
                output.append(item)
        return self._emit(
            self._document(
                "observe_image_metadata",
                target,
                mode,
                cluster,
                observations=output,
            )
        )

    def observe_services(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_services",
            target,
            mode,
            "services",
            namespaced=True,
            stamp_kind="service",
        )

    def observe_ingress(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_ingress",
            target,
            mode,
            "ingress",
            namespaced=True,
            stamp_kind="ingress",
        )

    def observe_rbac(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_rbac", target, mode, "rbac", namespaced=True, stamp_kind="rbac"
        )

    def observe_service_accounts(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_service_accounts",
            target,
            mode,
            "service_accounts",
            namespaced=True,
            stamp_kind="service_account",
        )

    def observe_network_policies(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_network_policies",
            target,
            mode,
            "network_policies",
            namespaced=True,
            stamp_kind="network_policy",
        )

    def observe_security_contexts(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        return self._rows(
            "observe_security_contexts",
            target,
            mode,
            "security_contexts",
            namespaced=True,
            stamp_kind="security_context",
        )

    def observe_resource_configuration(
        self, target: str, mode: ContainerMode = ContainerMode.CONTROLLED
    ) -> str:
        parts = self._parse(target)
        resolved = self._resolve(
            "observe_resource_configuration", target, mode, parts
        )
        if isinstance(resolved, str):
            return resolved
        cluster, estate = resolved
        output: list[dict[str, Any]] = []
        for key in ("resource_configuration", "configuration_discrepancies"):
            for row in estate.get(key, []):
                if parts.namespace is not None and row.get("namespace") != parts.namespace:
                    continue
                item = dict(row)
                item.setdefault("cluster", cluster)
                item.setdefault(
                    "namespace", parts.namespace or row.get("namespace")
                )
                output.append(item)
        return self._emit(
            self._document(
                "observe_resource_configuration",
                target,
                mode,
                cluster,
                observations=output,
            )
        )


def synthetic_cluster_credential(cluster: str, key: str) -> str | None:
    """Return a synthetic secret value for redaction tests, if present."""
    return CLUSTER_CREDENTIAL_SYNTHETICS.get(cluster, {}).get(key)


__all__ = ["MockContainerTransport", "synthetic_cluster_credential"]
