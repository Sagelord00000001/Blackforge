# Container & Kubernetes Security

## Architecture

The Container & Kubernetes Security Capability Foundation mirrors the
`cloud/` architecture: a typed engine, typed capabilities, a deterministic
mock-only transport, normalization adapters, evidence persistence, and World
Model materialization — with **no real cluster access, no credential use, no
mutation, and no offensive semantics**. Every observation is read-only against
a fixed internal fixture on a mock Kubernetes estate.

- **`blackforge/container/engine.py`** (`ContainerEngine`) — guards and
  orchestrates the full pipeline: request validation → Scope → Authorization →
  target resolution → capability validation → mock transport → normalization →
  evidence persistence (artifact + typed observations) → World Model
  materialization → best-effort memory link. It carries 14 tools,
  `capability_ids()` builds the expected ID set, `CLOUD_REF` qualifies a
  cloud-scoped target, `_error_scope()` maps synthetic bare cluster names onto
  error fixtures, and the same guarded path runs every capability. `run()`
  exposes no generic executor — unknown capability IDs are rejected before
  anything runs.
- **`blackforge/container/capabilities.py`** — fourteen typed
  `ContainerCapability` instances, each bound to a transport method, a
  normalization adapter, and capability metadata. `build_container_capabilities()`
  builds all fourteen; `build_container_meta()` builds their metadata;
  `ContainerCapabilityMeta` adds `category="container"`, PASSIVE default mode,
  `produces`, and `world_model=True`. `CONTAINER_CAPABILITY_IDS` is the
  ordered 14-ID surface.
- **`blackforge/container/transport.py`** (`MockContainerTransport`) —
  deterministic, mock-only transport over a fixed synthetic estate. Never
  touches a real cluster; every method returns a JSON document. Credential-like
  demo fields exist **only** to prove the redaction boundary and are stripped
  before any evidence row or world record.
- **`blackforge/container/normalization.py`** — typed normalization adapters
  that parse mock raw output into typed observation models;
  `is_header_status_line()` and `normalize_response_text()` fold a stray status
  line so a malformed raw feed cannot fabricate rows.
- **`blackforge/container/evidence.py`** — `artifact_evidence()` and
  `observation_evidence()` construct evidence records; `observation_confidence()`
  implements the confidence policy; the container mode is embedded in each
  stored raw payload so a PASSIVE observation never dedups onto (and silently
  inherits the confidence of) a CONTROLLED record while repeated same-mode runs
  still coalesce; `observation_kind_for()` maps a tool + kind onto the
  vocabulary; `evidence_dedup_key_for()` / `existing_evidence_id()` enable
  idempotent reruns.
- **`blackforge/container/materializer.py`** (`ContainerWorldMaterializer`) —
  maps typed observations into World Model records with a fixed, deterministic
  mapping. **No offensive edge types (EXPLOITS / CAN_COMPROMISE / LEADS_TO /
  ENABLES) are ever emitted.** Containers link to images with `USES_IMAGE`
  (feature flags feature off), `DEPLOYMENT --DEPLOYS--> WORKLOAD` from a single
  `workload` source row; registries are emitted before the images that belong
  to them so `BELONGS_TO` resolves; service accounts are emitted before pods
  and RBAC.
- **`blackforge/container/redaction.py`** — credential-like keys
  (`registry_token`, `service_account_token`, `docker_config_auth`,
  `basic_auth_password`, `oauth2_token`, `oidc_id_token`, `kubeconfig_password`,
  `tls_private_key`, `client_key_data`, plus token-level matches) are
  force-redacted to the literal `REDACTED` marker. Re-exports
  `credential_value_redacted` from the network redaction layer.
- **`blackforge/container/models.py`** — `ContainerMode` (PASSIVE/CONTROLLED),
  `ContainerStatus`, `ContainerObservationKind`, typed observation models
  discriminated by `"kind"`, `ContainerRequest`, `ContainerResult`.
- **`blackforge/container/addressing.py`** — cluster / namespace /
  cluster/namespace target parsing; only `CLOUD` (unqualified cluster or
  `cluster/namespace`) and bare-cluster ASSET error targets are accepted —
  a domain or IP target is rejected with `ContainerExecutionError` before
  transport.
- **`blackforge/container/canonical.py`** — container-world canonical keys and
  helpers used by the materializer.
- **`blackforge/core/errors.py`** — `ContainerNormalizationError`,
  `ContainerExecutionError`; out-of-scope targets surface an
  `AuthorizationError` before any transport work; unsupported target types and
  unknown capabilities surface `ContainerExecutionError`.
- **`blackforge/core/types.py`** — `TargetType.SECURITY` and
  `ContainerScopeQualifier` additions for the container capability registry;
  `blackforge/world_model/models.py` gained `CONTAINER` / `CONTAINER_IMAGE` /
  `REGISTRY` / `INGRESS` / `NETWORK_POLICY` entity types and `NETWORK_POLICY`
  assertion kinds; scope matching gained `SECURITY` + container-qualifier rules.

## Capabilities

| ID | Name | Mode | Risk | Produces |
|---|---|---|---|---|
| `container.cluster_observation` | Cluster Observation | PASSIVE | LOW | CLUSTER |
| `container.node_observation` | Node Observation | PASSIVE | LOW | NODE |
| `container.namespace_enumeration` | Namespace Enumeration | PASSIVE | LOW | NAMESPACE |
| `container.workload_observation` | Workload Observation | PASSIVE | LOW | WORKLOAD, DEPLOYMENT |
| `container.pod_observation` | Pod Observation | PASSIVE | LOW | POD |
| `container.container_observation` | Container Observation | PASSIVE | LOW | CONTAINER |
| `container.image_metadata_observation` | Image Metadata Observation | PASSIVE | LOW | IMAGE, REGISTRY |
| `container.service_observation` | Service Observation | PASSIVE | LOW | SERVICE |
| `container.ingress_exposure_observation` | Ingress Exposure Observation | PASSIVE | LOW | INGRESS |
| `container.rbac_observation` | RBAC Observation | PASSIVE | LOW | ROLE |
| `container.service_account_observation` | Service Account Observation | PASSIVE | LOW | SERVICE_ACCOUNT |
| `container.network_policy_observation` | Network Policy Observation | PASSIVE | LOW | NETWORK_POLICY |
| `container.security_context_observation` | Security Context Observation | PASSIVE | LOW | SECURITY_CONTEXT |
| `container.resource_configuration_observation` | Resource Configuration | PASSIVE | LOW | RESOURCE_CONFIGURATION, CONFIGURATION_DISCREPANCY |

All fourteen capabilities support `AssetTarget` / `CloudTarget` (`SECURITY`
target type plus the `CLOUD`-qualified container surface); the metadata
`supported_target_types` advertises both `asset` and `cloud`. Registry counts:
defaults-only → 1, recon → 7, + webapi → 17, + auth → 28, + business logic →
39, + network → 50, + identity → 61, + cloud → 81, + container → **95**
(`container_ready`, fourteen typed capabilities).

## Safety Model

Every capability runs the identical guarded pipeline:

1. **Request → Scope → Authorization** — the target must be inside
   `TargetScope.allowed_targets`; otherwise an `AuthorizationError` is raised
   **before** any transport work. A qualified umbrella like
   `aelionix-platform/frontend` is authorized only when the qualifier is
   allowed.
2. **Typed surface, fail-closed** — only the fourteen typed contracts exist. An
   unknown capability ID is rejected with `ContainerExecutionError` before
   anything runs (no generic executor). Unsupported target types (e.g. a domain
   like `apps.aelionix.test:8080` or an IP) and invalid modes are rejected
   before transport. A cluster that is explicitly out of scope, unknown, or
   unmapped fails closed with `UNKNOWN_CLUSTER` and zero observations — never a
   crash, never an empty "clean" result.
3. **Deterministic mock transport** — the only transport iterates a fixed mock
   estate. No real cluster is ever queried or mutated. Credential-like demo
   fields are stripped at the boundary.
4. **Evidence integrity** — every observation persists with `OBSERVED`
   provenance (container evidence is never elevated) and DERIVED_FROM links to
   its run's artifact; a PASSIVE run produces LOW confidence records independent
   of any earlier CONTROLLED run on the same target.
5. **World Model** — descriptive/structural edges only; no offensive
   relationship types are materialized. Contradictions surface instead of
   silently overwriting: a declared resource limit that differs from the
   cluster-reported value is recorded as an INFERRED `discrepancy.<item>`
   assertion rather than overwriting the reported value.
6. **Failure-aware statuses** — negative outcomes (timeout, rate limited,
   unauthorized, malformed, unsupported cluster, no evidence, limited
   truncation) are recorded as structured `ContainerStatus` results, never
   silent failures, and never become findings.
7. **No autonomous action** — observed misconfigurations never trigger
   automatic remediation or exploitation. Analysis is observational and
   read-only.

## Transport Abstraction

`MockContainerTransport` is the only transport. The demo fixture defines three
estates plus synthetic error targets:

- **Platform** — `aelionix-platform`: 1 cluster, 2 nodes, 3 namespaces, 6
  workloads, 4 pods, 4 containers, 4 image-metadata rows, 2 services, 1
  ingress, 2 RBAC rows, 3 service accounts, 2 network policies, 3 security
  contexts, 4 resource-configuration rows.
- **Staging** — `aelionix-staging`: 1 cluster, 1 node, 1 namespace, 2
  workloads, 1 pod, 1 container, 2 image rows, 1 service, 1 RBAC row, 1
  service account, 1 security context, 1 resource-configuration row; the
  estate has **no ingress and no network policies**, so `observe_ingress` /
  `observe_network_policies` return `status == NO_EVIDENCE` with zero
  observations (never a fabricated "clean" result).
- **Frontend namespace** — `aelionix-platform/frontend`: the qualified target
  narrows every capability to the `frontend` namespace only.

Deterministic fixture behavior (verified by tests and the validation notebook)
for the typed counts per estate:

- **Platform** — observe_clusters 1, observe_nodes 2, enumerate_namespaces 3,
  observe_workloads 6, observe_pods 4, observe_containers 4,
  observe_image_metadata 4, observe_services 2, observe_ingress 1, observe_rbac
  2, observe_service_accounts 3, observe_network_policies 2,
  observe_security_contexts 3, observe_resource_configuration 4. Total 41
  observations, 55 evidence rows.
- **Staging** — 1, 1, 1, 2, 1, 1, 2, 1, 0 (`no_evidence`), 1, 1, 0
  (`no_evidence`), 1, 1. Total 14 observations.
- **Frontend** — 1, 2, 3, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 3. Total 22.

Five synthetic error clusters (`snail-cluster`, `bursty-cluster`,
`locked-cluster`, `garbled-cluster`, `fabricated-cluster`) and any unmodeled
cluster produce handled error documents:

| Error fixture | `error.kind` | Status |
|---|---|---|
| `snail-cluster` | `timeout` | TIMEOUT |
| `bursty-cluster` | `rate_limited` | RATE_LIMITED |
| `locked-cluster` | `unauthorized` | UNAUTHORIZED |
| `garbled-cluster` | `malformed_response` | MALFORMED_RESPONSE |
| `fabricated-cluster` / unmodeled | `unsupported_cluster` | UNSUPPORTED_CLUSTER |

## Observation Models

All observations are discriminated unions keyed on `"kind"`:

- `ClusterObservation` (kind=cluster) — cluster, node_count, state
- `NodeObservation` (kind=node) — node, cluster, capacity, state
- `NamespaceObservation` (kind=namespace) — namespace, cluster, labels
- `WorkloadObservation` (kind=workload) — workload, namespace, kind,
  replicas, labels (also surfaces as a `deployment`)
- `DeploymentObservation` (kind=deployment) — same source row re-typed as a
  deployment
- `PodObservation` (kind=pod) — pod, node, namespace, phase, labels
- `ContainerInstanceObservation` (kind=container) — container, pod, image,
  image_id, state, restart_count (no class collision: the typed row is
  `ContainerInstanceObservation`, the world entity is `CONTAINER`)
- `ImageMetadataObservation` (kind=device_image / `image_metadata`) — image,
  registry, tag, digest, pulled_since
- `RegistryObservation` (kind=registry) — registry, image, tag, digest
  (same source row re-typed)
- `ServiceObservation` (kind=service) — service, namespace, type, cluster_ip,
  selector
- `IngressObservation` (kind=ingress) — ingress, namespace, host, path,
  service, replicas (structural exposure only, no attack language)
- `RbacObservation` (kind=rbac) — role, namespace, kind, rules
  (verb/username mappings stay observational)
- `ServiceAccountObservation` (kind=service_account) — service_account,
  namespace, token, labels (token values are redacted)
- `NetworkPolicyObservation` (kind=network_policy) — network_policy, namespace,
  pod_selector, ingress_allowed, egress_allowed
- `SecurityContextObservation` (kind=security_context) — container, pod,
  workload, namespace, privileged, allow_privilege_escalation,
  run_as_non_root, run_as_user, read_only_root_filesystem, seccomp_profile,
  capabilities
- `ResourceConfigurationObservation` (kind=resource_configuration) —
  workload, namespace, cpu_request, cpu_limit, memory_request, memory_limit,
  items (declared + cluster-reported values)

## World Model Semantics

Container resources are namespaced per cluster/namespace (`canonical_key` e.g.
`container_cluster|aelionix-platform`). The mapping is fixed and deterministic,
and **no attack-graph relationship types are ever materialized**:

- CLUSTER --CONTAINS--> NODE; CLUSTER --CONTAINS--> NAMESPACE.
- NAMESPACE --CONTAINS--> WORKLOAD / SERVICE / INGRESS / NETWORK_POLICY /
  ROLE / SERVICE_ACCOUNT.
- WORKLOAD --RUNS--> POD --RUNS--> CONTAINER.
- DEPLOYMENT --DEPLOYS--> WORKLOAD (from the same `workload` source row).
- CONTAINER --USES_IMAGE--> CONTAINER_IMAGE; CONTAINER_IMAGE --BELONGS_TO-->
  REGISTRY (registries are emitted before their images so the edge resolves).
- SERVICE --SELECTS--> WORKLOAD; INGRESS --ROUTES_TO--> SERVICE.
- NETWORK_POLICY --APPLIES_TO--> WORKLOAD.
- SERVICE_ACCOUNT --USES_SERVICE_ACCOUNT--> POD; ROLE --HAS_ROLE--> SERVICE
  ACCOUNT or pod; PERMISSION --HAS_PERMISSION--> RBAC role (RBAC structure maps
  `verb`/`username` observationally, never as an attack path).

Security context qualifications surface as container assertions:
`privileged`, `allow_privilege_escalation`, `run_as_non_root`, `run_as_user`,
`read_only_root_filesystem`, `seccomp_profile`, `capabilities`. Resource limits
surface on the workload: `cpu_request`, `cpu_limit`, `memory_request`,
`memory_limit`, plus `discrepancy.<item>` assertions at INFERRED confidence
when the declared limit disagrees with the cluster-reported value — a
contradiction is surfaced, not silently overwritten.

Headline totals on the mission (deterministic, asserted in tests and the
notebook): platform+staging+frontend mission produces 119 evidence rows, 48
active entities (2 cluster / 3 node / 4 namespace / 4 workload / 4 deployment /
5 pod / 4 container / 4 image / 2 registry / 3 service / 1 ingress / 3 role / 3
permission / 4 service account / 2 network policy) and 61 relationships (contains
35 / runs 5 / uses_service_account 2 / belongs_to 4 / deploys 4 / uses_image 1 /
applies_to 2 / has_permission 3 / has_role 1 / routes_to 1 / selects 3). Provenance
is preserved: entities, relationships, and assertions carry their evidence links;
every evidence row links to its run's artifact via DERIVED_FROM.

## Confidence Policy

- PASSIVE mode → LOW confidence (applied unconditionally).
- CONTROLLED direct authoritative container records (cluster/node/namespace
  discovery, workload/pod/container/image/registry/service/service-account
  observation) → HIGH.
- Derived kinds (ingress exposure, RBAC, network policy, security context,
  resource configuration, configuration discrepancy) → MEDIUM in CONTROLLED.
- Mode is embedded in each stored evidence payload, so dedup can never cross
  modes: a PASSIVE run yields its own LOW records independent of an earlier
  CONTROLLED run, while repeated same-mode runs coalesce idempotently.

## Redaction

Credential-like keys (`registry_token`, `service_account_token`,
`docker_config_auth`, `basic_auth_password`, `oauth2_token`, `oidc_id_token`,
`kubeconfig_password`, `tls_private_key`, `client_key_data`, `token`,
`password`, `secret`, `credentials`, plus token-level matches) are
force-replaced with the literal `REDACTED` marker — never a hash, so redaction
is unambiguous. Non-secret sibling keys are preserved so the observation keeps
its structure. `redact_container_document()` (recursive) and
`redact_container_raw()` (JSON re-serialization) run at the redaction boundary;
`credential_value_redacted()` is re-exported from the network layer. The demo
dataset carries credential-like fields (`demo-registry-token-0000`,
`demo-sa-token-0000`, `demo-staging-registry-token-0000`,
`demo-kubeconfig-password-0000`, `demo-tls-private-key-0000`) **only** to prove
the boundary. Tests assert no plaintext credential-like value ever appears in
raw output, artifact payloads, observation rows, or world-model assertions, and
that an artifacts keeps its structure while credential fields become
`REDACTED`.