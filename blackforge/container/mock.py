from __future__ import annotations

import hashlib
import json
from typing import Any

# ---------------------------------------------------------------------------
# Deterministic mock Kubernetes / container platform fleet (all fixture data).
#
# The mock models two fictional AELIONIX test clusters — aelionix-platform
# (rich: nodes, namespaces, workloads/deployments, pods, containers, images,
# services, ingress, RBAC, service accounts, network policies, security and
# resource configuration) and aelionix-staging (small). Every value is
# synthetic: ``*.test`` image names, ``10.x.x.x`` pod/node addresses, and
# ``*.aelionix.test`` host rules. Nothing here requires a real cluster and
# nothing here is ever queried or mutated at runtime.
#
# Credential-like fields below (``registry_token``, ``service_account_token``,
# ``kubeconfig_password``, ``tls_private_key``) exist ONLY to prove the
# redaction boundary: they are stripped at the artifact boundary and never
# reach observations, evidence, or the world model.
# ---------------------------------------------------------------------------

CONTAINER_PLATFORM = "kubernetes"

# Deterministic, non-invertible redaction marker used by the artifact
# boundary; identical to the identity/network convention.
_REDACTED = "REDACTED"


def _redacted() -> str:
    return _REDACTED


def _digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _image(name: str, tag: str = "1.0.0") -> str:
    digest = _digest(f"{name}:{tag}")
    return f"{name}.test:{tag}@{digest}"


_IMAGES = {
    "web-api": _image("registry.test/aelionix/web-api"),
    "worker": _image("registry.test/aelionix/worker"),
    "metrics": _image("registry.test/aelionix/metrics"),
    "staging-api": _image("registry.test/aelionix/staging-api"),
}

CLUSTERS: dict[str, dict[str, Any]] = {
    "aelionix-platform": {
        "cluster": {
            "cluster": "aelionix-platform",
            "platform": CONTAINER_PLATFORM,
            "version": "v1.29.test",
            "node_count": 2,
            "namespace_count": 3,
            "workload_count": 3,
            "api_accessible": True,
        },
        "nodes": [
            {
                "cluster": "aelionix-platform",
                "node": "worker-01",
                "role": "worker",
                "ip_address": "10.0.0.11",
                "os_image": "aelionix-os-v1",
                "container_runtime": "containerd.test",
                "kubelet_version": "v1.29.test",
            },
            {
                "cluster": "aelionix-platform",
                "node": "worker-02",
                "role": "worker",
                "ip_address": "10.0.0.12",
                "os_image": "aelionix-os-v1",
                "container_runtime": "containerd.test",
                "kubelet_version": "v1.29.test",
            },
        ],
        # namespace -> collections keyed for the transport tools
        "namespaces": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "labels": {"tier": "frontend", "managed": "true"},
                "pod_count": 2,
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "labels": {"tier": "backend", "managed": "true"},
                "pod_count": 1,
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "labels": {"tier": "observability", "managed": "true"},
                "pod_count": 1,
            },
        ],
        "workloads": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "workload": "web-api",
                "workload_kind": "Deployment",
                "replicas": 2,
                "image": _IMAGES["web-api"],
                "strategy": "RollingUpdate",
                "update_status": "Ready",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "workload": "worker",
                "workload_kind": "Deployment",
                "replicas": 1,
                "image": _IMAGES["worker"],
                "strategy": "RollingUpdate",
                "update_status": "Ready",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "workload": "metrics",
                "workload_kind": "Deployment",
                "replicas": 1,
                "image": _IMAGES["metrics"],
                "strategy": "Recreate",
                "update_status": "Ready",
            },
        ],
        "deployments": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "deployment": "web-api",
                "workload": "web-api",
                "replicas": 2,
                "ready_replicas": 2,
                "available_replicas": 2,
                "strategy": "RollingUpdate",
                "image": _IMAGES["web-api"],
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "deployment": "worker",
                "workload": "worker",
                "replicas": 1,
                "ready_replicas": 1,
                "available_replicas": 1,
                "strategy": "RollingUpdate",
                "image": _IMAGES["worker"],
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "deployment": "metrics",
                "workload": "metrics",
                "replicas": 1,
                "ready_replicas": 1,
                "available_replicas": 1,
                "strategy": "Recreate",
                "image": _IMAGES["metrics"],
            },
        ],
        "pods": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "pod": "web-api-7d9c8f",
                "workload": "web-api",
                "node": "worker-01",
                "phase": "Running",
                "pod_ip": "10.1.0.5",
                "restarts": 0,
                "service_account": "web-api-sa",
                "containers": ["web-api"],
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "pod": "web-api-7d9c8f-6a2b",
                "workload": "web-api",
                "node": "worker-02",
                "phase": "Running",
                "pod_ip": "10.1.0.6",
                "restarts": 0,
                "service_account": "web-api-sa",
                "containers": ["web-api"],
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "pod": "worker-5f8a1e",
                "workload": "worker",
                "node": "worker-02",
                "phase": "Running",
                "pod_ip": "10.1.1.4",
                "restarts": 1,
                "service_account": "default",
                "containers": ["worker"],
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "pod": "metrics-3b2c9d",
                "workload": "metrics",
                "node": "worker-01",
                "phase": "Running",
                "pod_ip": "10.1.2.3",
                "restarts": 0,
                "service_account": "metrics-sa",
                "containers": ["metrics"],
            },
        ],
        "containers": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "pod": "web-api-7d9c8f",
                "container": "web-api",
                "image": _IMAGES["web-api"],
                "image_pull_policy": "IfNotPresent",
                "command": ["/app/web-api"],
                "args": ["--listen=:8080"],
                "ports": ["8080/tcp"],
                "volume_mounts": ["/etc/config"],
                "privileged": False,
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "pod": "web-api-7d9c8f-6a2b",
                "container": "web-api",
                "image": _IMAGES["web-api"],
                "image_pull_policy": "IfNotPresent",
                "command": ["/app/web-api"],
                "args": ["--listen=:8080"],
                "ports": ["8080/tcp"],
                "volume_mounts": ["/etc/config"],
                "privileged": False,
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "pod": "worker-5f8a1e",
                "container": "worker",
                "image": _IMAGES["worker"],
                "image_pull_policy": "Always",
                "command": ["/app/worker"],
                "args": ["--queue=orders"],
                "ports": [],
                "volume_mounts": [],
                "privileged": False,
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "pod": "metrics-3b2c9d",
                "container": "metrics",
                "image": _IMAGES["metrics"],
                "image_pull_policy": "IfNotPresent",
                "command": ["/app/metrics"],
                "args": ["--exporter"],
                "ports": ["9090/tcp"],
                "volume_mounts": [],
                "privileged": True,
            },
        ],
        "images": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "image": _IMAGES["web-api"],
                "registry": "registry.test",
                "tag": "1.0.0",
                "digest": _IMAGES["web-api"].split("@", 1)[1],
                "pull_policy": "IfNotPresent",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "image": _IMAGES["worker"],
                "registry": "registry.test",
                "tag": "1.0.0",
                "digest": _IMAGES["worker"].split("@", 1)[1],
                "pull_policy": "Always",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "image": _IMAGES["metrics"],
                "registry": "registry.test",
                "tag": "1.0.0",
                "digest": _IMAGES["metrics"].split("@", 1)[1],
                "pull_policy": "IfNotPresent",
            },
        ],
        "registries": [
            {
                "cluster": "aelionix-platform",
                "registry": "registry.test",
                "host": "registry.test",
                "image_count": 3,
                "secure": True,
                # present ONLY to prove redaction at the artifact boundary
                "registry_token": "demo-registry-token-0000",
            },
        ],
        "services": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "service": "web-api-service",
                "service_type": "ClusterIP",
                "cluster_ip": "10.3.0.10",
                "ports": ["8080:80"],
                "selector": {"app": "web-api"},
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "service": "internal-worker-service",
                "service_type": "ClusterIP",
                "cluster_ip": "10.3.0.20",
                "ports": ["9090:9090"],
                "selector": {"app": "worker"},
            },
        ],
        "ingress": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "ingress": "public-api",
                "host": "api.aelionix.test",
                "paths": ["/"],
                "backend": "web-api-service:80",
                "tls_enabled": True,
            },
        ],
        "rbac": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "subject": "web-api-sa",
                "subject_kind": "ServiceAccount",
                "role": "web-api-reader",
                "role_kind": "Role",
                "permission": "web-api-reader",
                "verbs": ["get", "list", "watch"],
                "resources": ["pods", "configmaps"],
                "api_group": "",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "subject": "metrics-sa",
                "subject_kind": "ServiceAccount",
                "role": "metrics-viewer",
                "role_kind": "ClusterRole",
                "permission": "metrics-viewer",
                "verbs": ["get", "list"],
                "resources": ["pods", "nodes"],
                "api_group": "metrics.k8s.test",
            },
        ],
        "service_accounts": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "service_account": "web-api-sa",
                "automount_token": True,
                "secrets": ["web-api-token"],
                "image_pull_secrets": ["registry-pull"],
                # present ONLY to prove redaction
                "service_account_token": "demo-sa-token-0000",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "service_account": "metrics-sa",
                "automount_token": False,
                "secrets": ["metrics-token"],
                "image_pull_secrets": [],
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "service_account": "default",
                "automount_token": True,
                "secrets": [],
                "image_pull_secrets": ["registry-pull"],
            },
        ],
        "network_policies": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "network_policy": "web-api-ingress",
                "policy_types": ["Ingress"],
                "pod_selector": {"app": "web-api"},
                "ingress_rules": [
                    {"from": [{"namespaceSelector": {"tier": "frontend"}}]}
                ],
                "egress_rules": [],
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "network_policy": "worker-egress",
                "policy_types": ["Egress"],
                "pod_selector": {"app": "worker"},
                "ingress_rules": [],
                "egress_rules": [{"to": [{"podSelector": {"app": "worker"}}]}],
            },
        ],
        "security_contexts": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "pod": "web-api-7d9c8f",
                "container": "web-api",
                "allow_privilege_escalation": False,
                "privileged": False,
                "run_as_non_root": True,
                "run_as_user": 1000,
                "read_only_root_filesystem": False,
                "seccomp_profile": "RuntimeDefault",
                "capabilities": ["NET_BIND_SERVICE"],
                "source": "cluster",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "monitoring",
                "pod": "metrics-3b2c9d",
                "container": "metrics",
                "allow_privilege_escalation": True,
                "privileged": True,
                "run_as_non_root": False,
                "run_as_user": 0,
                "read_only_root_filesystem": False,
                "seccomp_profile": "Unconfined",
                "capabilities": ["ALL"],
                "source": "cluster",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "pod": "worker-5f8a1e",
                "container": "worker",
                "allow_privilege_escalation": False,
                "privileged": False,
                "run_as_non_root": True,
                "run_as_user": 1001,
                "read_only_root_filesystem": True,
                "seccomp_profile": "RuntimeDefault",
                "capabilities": [],
                "source": "cluster",
            },
        ],
        "resource_configuration": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "workload": "web-api",
                "container": "web-api",
                "cpu_request": "250m",
                "memory_request": "256Mi",
                "cpu_limit": "500m",
                "memory_limit": "512Mi",
                "recommendation_source": "cluster",
                "source": "cluster",
            },
            {
                "cluster": "aelionix-platform",
                "namespace": "backend",
                "workload": "worker",
                "container": "worker",
                "cpu_request": "100m",
                "memory_request": "128Mi",
                "cpu_limit": "250m",
                "memory_limit": "256Mi",
                "recommendation_source": "cluster",
                "source": "cluster",
            },
        ],
        "configuration_discrepancies": [
            {
                "cluster": "aelionix-platform",
                "namespace": "frontend",
                "workload": "web-api",
                "container": "web-api",
                "item": "cpu_limit",
                "declared_value": "500m",
                "cluster_reported_value": "750m",
                "severity": "low",
            },
        ],
    },
    "aelionix-staging": {
        "cluster": {
            "cluster": "aelionix-staging",
            "platform": CONTAINER_PLATFORM,
            "version": "v1.28.test",
            "node_count": 1,
            "namespace_count": 1,
            "workload_count": 1,
            "api_accessible": False,
        },
        "nodes": [
            {
                "cluster": "aelionix-staging",
                "node": "staging-node-01",
                "role": "worker",
                "ip_address": "10.20.0.11",
                "os_image": "aelionix-os-v1",
                "container_runtime": "containerd.test",
                "kubelet_version": "v1.28.test",
            },
        ],
        "namespaces": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "labels": {"tier": "staging"},
                "pod_count": 1,
            },
        ],
        "workloads": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "workload": "staging-api",
                "workload_kind": "Deployment",
                "replicas": 1,
                "image": _IMAGES["staging-api"],
                "strategy": "RollingUpdate",
                "update_status": "Ready",
            },
        ],
        "deployments": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "deployment": "staging-api",
                "workload": "staging-api",
                "replicas": 1,
                "ready_replicas": 1,
                "available_replicas": 1,
                "strategy": "RollingUpdate",
                "image": _IMAGES["staging-api"],
            },
        ],
        "pods": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "pod": "staging-api-c1d2e3",
                "workload": "staging-api",
                "node": "staging-node-01",
                "phase": "Running",
                "pod_ip": "10.21.0.5",
                "restarts": 0,
                "service_account": "default",
                "containers": ["staging-api"],
            },
        ],
        "containers": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "pod": "staging-api-c1d2e3",
                "container": "staging-api",
                "image": _IMAGES["staging-api"],
                "image_pull_policy": "IfNotPresent",
                "command": ["/app/staging-api"],
                "args": ["--listen=:8080"],
                "ports": ["8080/tcp"],
                "volume_mounts": [],
                "privileged": False,
            },
        ],
        "images": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "image": _IMAGES["staging-api"],
                "registry": "registry.test",
                "tag": "1.0.0",
                "digest": _IMAGES["staging-api"].split("@", 1)[1],
                "pull_policy": "IfNotPresent",
            },
        ],
        "registries": [
            {
                "cluster": "aelionix-staging",
                "registry": "registry.test",
                "host": "registry.test",
                "image_count": 1,
                "secure": True,
                # present ONLY to prove redaction
                "registry_token": "demo-staging-registry-token-0000",
            },
        ],
        "services": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "service": "staging-api-service",
                "service_type": "ClusterIP",
                "cluster_ip": "10.23.0.10",
                "ports": ["8080:80"],
                "selector": {"app": "staging-api"},
            },
        ],
        "ingress": [],
        "rbac": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "subject": "default",
                "subject_kind": "ServiceAccount",
                "role": "default-viewer",
                "role_kind": "Role",
                "permission": "default-viewer",
                "verbs": ["get"],
                "resources": ["pods"],
                "api_group": "",
            },
        ],
        "service_accounts": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "service_account": "default",
                "automount_token": True,
                "secrets": [],
                "image_pull_secrets": [],
            },
        ],
        "network_policies": [],
        "security_contexts": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "pod": "staging-api-c1d2e3",
                "container": "staging-api",
                "allow_privilege_escalation": False,
                "privileged": False,
                "run_as_non_root": True,
                "run_as_user": 1000,
                "read_only_root_filesystem": False,
                "seccomp_profile": "RuntimeDefault",
                "capabilities": [],
                "source": "cluster",
            },
        ],
        "resource_configuration": [
            {
                "cluster": "aelionix-staging",
                "namespace": "default",
                "workload": "staging-api",
                "container": "staging-api",
                "cpu_request": "250m",
                "memory_request": "256Mi",
                "cpu_limit": "500m",
                "memory_limit": "512Mi",
                "recommendation_source": "cluster",
                "source": "cluster",
            },
        ],
        "configuration_discrepancies": [],
    },
}

# Optional synthetic secret-like values present on cluster records to prove
# the redaction boundary for the kubeconfig/password/TLS material when a tool
# emits them. Kept out of the primary estate rows so they only appear when a
# dedicated redaction fixture needs them.
CLUSTER_CREDENTIAL_SYNTHETICS: dict[str, dict[str, str]] = {
    "aelionix-platform": {
        "kubeconfig_password": "demo-kubeconfig-password-0000",
        "tls_private_key": "demo-tls-private-key-0000",
    },
    "aelionix-staging": {
        "kubeconfig_password": "demo-staging-kubeconfig-password-0000",
        "tls_private_key": "demo-staging-tls-private-key-0000",
    },
}

_ERROR_TABLE: dict[str, dict[str, str]] = {
    "snail-cluster": {
        "kind": "timeout",
        "message": "cluster observation timed out",
    },
    "bursty-cluster": {
        "kind": "rate_limited",
        "message": "cluster observation rate limit exceeded",
    },
    "locked-cluster": {
        "kind": "unauthorized",
        "message": "cluster observation not authorized",
    },
    "garbled-cluster": {
        "kind": "malformed",
        "message": "cluster returned a malformed response",
    },
}

# A cluster prefix reserved for the "unknown kind" and "unsupported cluster"
# negative outcomes handled by the transport.
_FABRICATED_CLUSTER = "fabricated-cluster"


def modeled_cluster_names() -> list[str]:
    """Deterministic cluster names for the modeled fleet."""
    return [name for name in CLUSTERS]


def _as_json(document: Any) -> str:
    return json.dumps(document, sort_keys=True, default=str)


def plugin_notebook_payload() -> dict[str, Any]:
    """Synthetic full-fleet bundle used by the notebook demo, pre-redacted."""
    import copy

    from blackforge.container.redaction import redact_container_document

    bundle: dict[str, Any] = {"kind": "container_fleet", "clusters": {}}
    for name, estate in CLUSTERS.items():
        redacted = copy.deepcopy(estate)
        for collection_key, collection in redacted.items():
            if isinstance(collection, list):
                redacted[collection_key] = [
                    redact_container_document(row) if isinstance(row, dict) else row
                    for row in collection
                ]
            elif isinstance(collection, dict):
                redacted[collection_key] = redact_container_document(collection)
        bundle["clusters"][name] = {
            "cluster": redacted["cluster"],
            "namespaces": redacted["namespaces"],
            "workloads": redacted["workloads"],
            "images": redacted["images"],
            "services": redacted["services"],
            "ingress": redacted["ingress"],
        }
    return bundle


__all__ = [
    "CLUSTERS",
    "CLUSTER_CREDENTIAL_SYNTHETICS",
    "CONTAINER_PLATFORM",
    "_ERROR_TABLE",
    "_FABRICATED_CLUSTER",
    "modeled_cluster_names",
    "plugin_notebook_payload",
]
