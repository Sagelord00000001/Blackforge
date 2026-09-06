from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.container.models import (
    ClusterObservation,
    ConfigurationDiscrepancyObservation,
    ContainerInstanceObservation,
    ContainerObservationKind,
    DeploymentObservation,
    ImageObservation,
    IngressObservation,
    NamespaceObservation,
    NetworkPolicyObservation,
    NodeObservation,
    PodObservation,
    RbacObservation,
    RegistryObservation,
    ResourceConfigurationObservation,
    SecurityContextObservation,
    ServiceAccountObservation,
    ServiceObservation,
    WorkloadObservation,
)
from blackforge.core.errors import ContainerNormalizationError

ContainerObservationUnion = (
    ClusterObservation
    | NodeObservation
    | NamespaceObservation
    | WorkloadObservation
    | DeploymentObservation
    | PodObservation
    | ContainerInstanceObservation
    | ImageObservation
    | RegistryObservation
    | ServiceObservation
    | IngressObservation
    | RbacObservation
    | ServiceAccountObservation
    | NetworkPolicyObservation
    | SecurityContextObservation
    | ResourceConfigurationObservation
    | ConfigurationDiscrepancyObservation
)


class ContainerNormalizedOutput(BaseModel):
    """Container adapter result with optional transport error metadata.

    An ``error`` document is a *handled* negative outcome (timeout, rate
    limit, unauthorized, malformed response, unknown / unsupported cluster,
    unknown namespace) — it becomes a container status, never a crash.
    """

    observations: list[ContainerObservationUnion] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: dict | None = None


class ContainerToolAdapter(ABC):
    """Boundary between mock raw container output and typed observations."""

    tool: str = "unknown"

    @abstractmethod
    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        ...


def _load_document(raw_output: object) -> Any:
    if isinstance(raw_output, str):
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise ContainerNormalizationError(
                f"tool produced malformed JSON: {exc}"
            ) from exc
    if isinstance(raw_output, (dict, list)):
        return raw_output
    raise ContainerNormalizationError("tool output is not a parseable document")


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ContainerNormalizationError(f"missing or empty string field: {field}")
    return value.strip()


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _optional_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _optional_list_dict(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


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
    observations: list[ContainerObservationUnion],
    warnings: list[str],
) -> ContainerNormalizedOutput:
    return ContainerNormalizedOutput(observations=observations, warnings=warnings)


def _error_output(document: dict[str, Any]) -> ContainerNormalizedOutput:
    error = document.get("error")
    if not isinstance(error, dict):
        raise ContainerNormalizationError("tool error must be an object")
    return ContainerNormalizedOutput(observations=[], warnings=[], error=dict(error))


def _yield_observations(document: dict[str, Any]) -> list[dict[str, Any]]:
    observations = document.get("observations", [])
    if not isinstance(observations, list):
        raise ContainerNormalizationError("observations must be a list")
    return observations


def _cluster(item: dict[str, Any]) -> str:
    return _require_string(item, "cluster")


def _namespace(item: dict[str, Any]) -> str:
    return _require_string(item, "namespace")


def _tags(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    return dict(value)


class ClusterObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_clusters`` output."""

    tool = "observe_clusters"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("cluster output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded cluster entry: not an object")
                continue
            try:
                cluster = _cluster(item)
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded cluster entry: {exc}")
                continue
            observations.append(
                ClusterObservation(
                    cluster=cluster,
                    platform=_optional_string(item.get("platform")),
                    version=_optional_string(item.get("version")),
                    node_count=_optional_int(item.get("node_count")),
                    namespace_count=_optional_int(item.get("namespace_count")),
                    workload_count=_optional_int(item.get("workload_count")),
                    api_accessible=_optional_bool(item.get("api_accessible")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no clusters observed")
        return _base_output(document, observations=observations, warnings=warnings)


class NodeObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_nodes`` output."""

    tool = "observe_nodes"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("node output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded node entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                node = _require_string(item, "node")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded node entry: {exc}")
                continue
            observations.append(
                NodeObservation(
                    cluster=cluster,
                    node=node,
                    role=_optional_string(item.get("role")),
                    ip_address=_optional_string(item.get("ip_address")),
                    os_image=_optional_string(item.get("os_image")),
                    container_runtime=_optional_string(item.get("container_runtime")),
                    kubelet_version=_optional_string(item.get("kubelet_version")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no nodes observed")
        return _base_output(document, observations=observations, warnings=warnings)


class NamespaceEnumerationAdapter(ContainerToolAdapter):
    """Parses ``enumerate_namespaces`` output."""

    tool = "enumerate_namespaces"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("namespace output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded namespace entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _require_string(item, "namespace")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded namespace entry: {exc}")
                continue
            observations.append(
                NamespaceObservation(
                    cluster=cluster,
                    namespace=namespace,
                    labels=_tags(item.get("labels")),
                    pod_count=_optional_int(item.get("pod_count")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no namespaces enumerated")
        return _base_output(document, observations=observations, warnings=warnings)


class WorkloadObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_workloads`` output (workload + deployment rows)."""

    tool = "observe_workloads"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("workload output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded workload entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                workload = _require_string(item, "workload")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded workload entry: {exc}")
                continue
            kind = _optional_string(item.get("kind")) or "workload"
            if kind == "deployment":
                observations.append(
                    DeploymentObservation(
                        cluster=cluster,
                        namespace=namespace,
                        deployment=workload,
                        workload=workload,
                        replicas=_optional_int(item.get("replicas")),
                        ready_replicas=_optional_int(item.get("ready_replicas")),
                        available_replicas=_optional_int(
                            item.get("available_replicas")
                        ),
                        strategy=_optional_string(item.get("strategy")),
                        image=_optional_string(item.get("image")),
                        note=_optional_string(item.get("note")),
                    )
                )
            else:
                observations.append(
                    WorkloadObservation(
                        cluster=cluster,
                        namespace=namespace,
                        workload=workload,
                        workload_kind=_optional_string(item.get("workload_kind")),
                        replicas=_optional_int(item.get("replicas")),
                        image=_optional_string(item.get("image")),
                        strategy=_optional_string(item.get("strategy")),
                        update_status=_optional_string(item.get("update_status")),
                        note=_optional_string(item.get("note")),
                    )
                )
        if not observations:
            warnings.append("no workloads observed")
        return _base_output(document, observations=observations, warnings=warnings)


class PodObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_pods`` output."""

    tool = "observe_pods"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("pod output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded pod entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                pod = _require_string(item, "pod")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded pod entry: {exc}")
                continue
            observations.append(
                PodObservation(
                    cluster=cluster,
                    namespace=namespace,
                    pod=pod,
                    workload=_optional_string(item.get("workload")),
                    node=_optional_string(item.get("node")),
                    phase=_optional_string(item.get("phase")),
                    pod_ip=_optional_string(item.get("pod_ip")),
                    restarts=_optional_int(item.get("restarts")),
                    service_account=_optional_string(item.get("service_account")),
                    containers=_optional_list(item.get("containers")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no pods observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ContainerObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_containers`` output."""

    tool = "observe_containers"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("container output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded container entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                container = _require_string(item, "container")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded container entry: {exc}")
                continue
            observations.append(
                ContainerInstanceObservation(
                    cluster=cluster,
                    namespace=namespace,
                    pod=_optional_string(item.get("pod")),
                    container=container,
                    image=_optional_string(item.get("image")),
                    image_pull_policy=_optional_string(item.get("image_pull_policy")),
                    command=_optional_list(item.get("command")),
                    args=_optional_list(item.get("args")),
                    ports=_optional_list(item.get("ports")),
                    volume_mounts=_optional_list(item.get("volume_mounts")),
                    privileged=_optional_bool(item.get("privileged")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no containers observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ImageMetadataAdapter(ContainerToolAdapter):
    """Parses ``observe_image_metadata`` output (image + registry rows)."""

    tool = "observe_image_metadata"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("image metadata output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded image entry: not an object")
                continue
            try:
                cluster = _cluster(item)
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded image entry: {exc}")
                continue
            kind = _optional_string(item.get("kind")) or "image"
            image = _optional_string(item.get("image"))
            if kind == "registry":
                observations.append(
                    RegistryObservation(
                        cluster=cluster,
                        registry=_require_string(item, "registry"),
                        host=_optional_string(item.get("host")),
                        image_count=_optional_int(item.get("image_count")),
                        secure=_optional_bool(item.get("secure")),
                        note=_optional_string(item.get("note")),
                    )
                )
            elif image is not None:
                observations.append(
                    ImageObservation(
                        cluster=cluster,
                        namespace=_optional_string(item.get("namespace")),
                        image=image,
                        registry=_optional_string(item.get("registry")),
                        tag=_optional_string(item.get("tag")),
                        digest=_optional_string(item.get("digest")),
                        pull_policy=_optional_string(item.get("pull_policy")),
                        note=_optional_string(item.get("note")),
                    )
                )
            else:
                warnings.append("discarded image entry: missing image/registry")
        if not observations:
            warnings.append("no image metadata observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ServiceObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_services`` output."""

    tool = "observe_services"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("service output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded service entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                service = _require_string(item, "service")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded service entry: {exc}")
                continue
            observations.append(
                ServiceObservation(
                    cluster=cluster,
                    namespace=namespace,
                    service=service,
                    service_type=_optional_string(item.get("service_type")),
                    cluster_ip=_optional_string(item.get("cluster_ip")),
                    ports=_optional_list(item.get("ports")),
                    selector=_tags(item.get("selector")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no services observed")
        return _base_output(document, observations=observations, warnings=warnings)


class IngressObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_ingress`` output."""

    tool = "observe_ingress"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("ingress output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded ingress entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                ingress = _require_string(item, "ingress")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded ingress entry: {exc}")
                continue
            observations.append(
                IngressObservation(
                    cluster=cluster,
                    namespace=namespace,
                    ingress=ingress,
                    host=_optional_string(item.get("host")),
                    paths=_optional_list(item.get("paths")),
                    backend=_optional_string(item.get("backend")),
                    tls_enabled=_optional_bool(item.get("tls_enabled")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no ingress observed")
        return _base_output(document, observations=observations, warnings=warnings)


class RbacObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_rbac`` output."""

    tool = "observe_rbac"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("rbac output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded rbac entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                subject = _require_string(item, "subject")
                role = _require_string(item, "role")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded rbac entry: {exc}")
                continue
            observations.append(
                RbacObservation(
                    cluster=cluster,
                    namespace=namespace,
                    subject=subject,
                    subject_kind=_optional_string(item.get("subject_kind")),
                    role=role,
                    role_kind=_optional_string(item.get("role_kind")),
                    permission=_optional_string(item.get("permission")),
                    verbs=_optional_list(item.get("verbs")),
                    resources=_optional_list(item.get("resources")),
                    api_group=_optional_string(item.get("api_group")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no rbac observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ServiceAccountObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_service_accounts`` output."""

    tool = "observe_service_accounts"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError(
                "service account output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded service account entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                service_account = _require_string(item, "service_account")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded service account entry: {exc}")
                continue
            observations.append(
                ServiceAccountObservation(
                    cluster=cluster,
                    namespace=namespace,
                    service_account=service_account,
                    automount_token=_optional_bool(item.get("automount_token")),
                    secrets=_optional_list(item.get("secrets")),
                    image_pull_secrets=_optional_list(item.get("image_pull_secrets")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no service accounts observed")
        return _base_output(document, observations=observations, warnings=warnings)


class NetworkPolicyObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_network_policies`` output."""

    tool = "observe_network_policies"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError("network policy output must be a dict")
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded network policy entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                network_policy = _require_string(item, "network_policy")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded network policy entry: {exc}")
                continue
            observations.append(
                NetworkPolicyObservation(
                    cluster=cluster,
                    namespace=namespace,
                    network_policy=network_policy,
                    policy_types=_optional_list(item.get("policy_types")),
                    pod_selector=_tags(item.get("pod_selector")),
                    ingress_rules=_optional_list_dict(item.get("ingress_rules")),
                    egress_rules=_optional_list_dict(item.get("egress_rules")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no network policies observed")
        return _base_output(document, observations=observations, warnings=warnings)


class SecurityContextObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_security_contexts`` output."""

    tool = "observe_security_contexts"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError(
                "security context output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append("discarded security context entry: not an object")
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded security context entry: {exc}")
                continue
            source = _optional_string(item.get("source")) or "cluster"
            observations.append(
                SecurityContextObservation(
                    cluster=cluster,
                    namespace=namespace,
                    pod=_optional_string(item.get("pod")),
                    container=_optional_string(item.get("container")),
                    allow_privilege_escalation=_optional_bool(
                        item.get("allow_privilege_escalation")
                    ),
                    privileged=_optional_bool(item.get("privileged")),
                    run_as_non_root=_optional_bool(item.get("run_as_non_root")),
                    run_as_user=_optional_int(item.get("run_as_user")),
                    read_only_root_filesystem=_optional_bool(
                        item.get("read_only_root_filesystem")
                    ),
                    seccomp_profile=_optional_string(item.get("seccomp_profile")),
                    capabilities=_optional_list(item.get("capabilities")),
                    source=source,
                    resolved=item.get("resolved", True) is not False,
                    missing_reference=_optional_string(item.get("missing_reference")),
                    note=_optional_string(item.get("note")),
                )
            )
        if not observations:
            warnings.append("no security contexts observed")
        return _base_output(document, observations=observations, warnings=warnings)


class ResourceConfigurationObservationAdapter(ContainerToolAdapter):
    """Parses ``observe_resource_configuration`` output."""

    tool = "observe_resource_configuration"

    def adapt(
        self, raw_output: object, *, context: dict | None = None
    ) -> ContainerNormalizedOutput:
        document = _load_document(raw_output)
        if not isinstance(document, dict):
            raise ContainerNormalizationError(
                "resource configuration output must be a dict"
            )
        if document.get("error") is not None:
            return _error_output(document)
        observations: list[ContainerObservationUnion] = []
        warnings: list[str] = []
        for item in _yield_observations(document):
            if not isinstance(item, dict):
                warnings.append(
                    "discarded resource configuration entry: not an object"
                )
                continue
            try:
                cluster = _cluster(item)
                namespace = _namespace(item)
                workload = _require_string(item, "workload")
            except ContainerNormalizationError as exc:
                warnings.append(f"discarded resource configuration entry: {exc}")
                continue
            observations.append(
                ResourceConfigurationObservation(
                    cluster=cluster,
                    namespace=namespace,
                    workload=workload,
                    container=_optional_string(item.get("container")),
                    cpu_request=_optional_string(item.get("cpu_request")),
                    memory_request=_optional_string(item.get("memory_request")),
                    cpu_limit=_optional_string(item.get("cpu_limit")),
                    memory_limit=_optional_string(item.get("memory_limit")),
                    recommendation_source=_optional_string(
                        item.get("recommendation_source")
                    ),
                    source=_optional_string(item.get("source")) or "cluster",
                    resolved=item.get("resolved", True) is not False,
                    missing_reference=_optional_string(item.get("missing_reference")),
                    note=_optional_string(item.get("note")),
                )
            )
            declared = _optional_string(item.get("declared_value"))
            reported = _optional_string(item.get("cluster_reported_value"))
            discrepancy_item = _optional_string(item.get("item"))
            if declared is not None and reported is not None:
                observations.append(
                    ConfigurationDiscrepancyObservation(
                        cluster=cluster,
                        namespace=namespace,
                        workload=workload,
                        container=_optional_string(item.get("container")),
                        item=discrepancy_item or "resource_configuration",
                        declared_value=declared,
                        cluster_reported_value=reported,
                        severity=_optional_string(item.get("severity")),
                        note=_optional_string(item.get("note")),
                    )
                )
        if not observations:
            warnings.append("no resource configuration observed")
        return _base_output(document, observations=observations, warnings=warnings)


def adapter_for_tool(tool: str) -> ContainerToolAdapter:
    """Return the adapter registered for a container tool name."""
    mapping: dict[str, ContainerToolAdapter] = {
        "observe_clusters": ClusterObservationAdapter(),
        "observe_nodes": NodeObservationAdapter(),
        "enumerate_namespaces": NamespaceEnumerationAdapter(),
        "observe_workloads": WorkloadObservationAdapter(),
        "observe_pods": PodObservationAdapter(),
        "observe_containers": ContainerObservationAdapter(),
        "observe_image_metadata": ImageMetadataAdapter(),
        "observe_services": ServiceObservationAdapter(),
        "observe_ingress": IngressObservationAdapter(),
        "observe_rbac": RbacObservationAdapter(),
        "observe_service_accounts": ServiceAccountObservationAdapter(),
        "observe_network_policies": NetworkPolicyObservationAdapter(),
        "observe_security_contexts": SecurityContextObservationAdapter(),
        "observe_resource_configuration": ResourceConfigurationObservationAdapter(),
    }
    adapter = mapping.get(tool)
    if adapter is None:
        raise ContainerNormalizationError(f"no adapter for tool: {tool}")
    return adapter


# Kind -> observation class map used by capabilities' ``produces`` declarations.
KIND_TO_OBSERVATION: dict[str, type] = {
    "cluster": ClusterObservation,
    "node": NodeObservation,
    "namespace": NamespaceObservation,
    "workload": WorkloadObservation,
    "deployment": DeploymentObservation,
    "pod": PodObservation,
    "container": ContainerInstanceObservation,
    "image": ImageObservation,
    "registry": RegistryObservation,
    "service": ServiceObservation,
    "ingress": IngressObservation,
    "rbac": RbacObservation,
    "service_account": ServiceAccountObservation,
    "network_policy": NetworkPolicyObservation,
    "security_context": SecurityContextObservation,
    "resource_configuration": ResourceConfigurationObservation,
    "configuration_discrepancy": ConfigurationDiscrepancyObservation,
}


def observation_kind_for(value: str | ContainerObservationKind):
    """Return a ContainerObservationKind from a string, if recognized."""
    try:
        return ContainerObservationKind(value)
    except ValueError:
        return None


__all__ = [
    "ContainerNormalizedOutput",
    "ContainerObservationUnion",
    "ContainerToolAdapter",
    "ImageMetadataAdapter",
    "IngressObservationAdapter",
    "NamespaceEnumerationAdapter",
    "NetworkPolicyObservationAdapter",
    "NodeObservationAdapter",
    "PodObservationAdapter",
    "RbacObservationAdapter",
    "ResourceConfigurationObservationAdapter",
    "SecurityContextObservationAdapter",
    "ServiceAccountObservationAdapter",
    "ServiceObservationAdapter",
    "WorkloadObservationAdapter",
    "adapter_for_tool",
    "observation_kind_for",
]
