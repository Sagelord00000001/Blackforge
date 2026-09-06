# Cloud Security

## Architecture

The Cloud Security Capability Foundation mirrors the
`recon/` / `webapi/` / `auth/` / `business_logic/` / `network/` /
`identity/` architecture: a typed engine, typed capabilities, a deterministic
mock-only transport, normalization adapters, evidence persistence, and World
Model materialization — with **no real cloud queries, no credential use, no
mutation, and no offensive semantics**. Every observation is read-only against
a fixed internal fixture on a mock estate.

- **`blackforge/cloud/engine.py`** (`CloudEngine`) — guards and orchestrates
  the full pipeline: request validation → LLM Suggestion (never trusted
  directly) → Deterministic Policy → Capability Allowlist → Scope → Authorization
  → resolution → mock transport → normalization → evidence persistence
  (artifact + typed observations) → World Model materialization → best-effort
  memory link. It carries 20 tools, `capability_ids()` builds the expected ID
  set, `_ERROR_KIND_TO_STATUS` maps transport error kinds to `CloudStatus`, and
  the same guarded path runs every capability. `run()` exposes no generic
  executor — unknown capability IDs are rejected before anything runs.
- **`blackforge/cloud/capabilities.py`** — twenty typed `CloudCapability`
  instances, each bound to a transport method, a normalization adapter, and
  capability metadata. `build_cloud_capabilities()` builds all twenty;
  `build_cloud_meta()` builds their metadata; `CloudCapabilityMeta` adds
  `category="cloud"`, PASSIVE default mode, `produces`, and `world_model=True`.
  `CLOUD_CAPABILITY_IDS` is the ordered 20-ID surface.
- **`blackforge/cloud/transport.py`** (`MockCloudTransport`) — deterministic,
  mock-only transport over three fixed estates (AWS / Azure / GCP). Never
  touches a real cloud; every method returns a JSON document. Credential-like
  demo fields exist **only** to prove the redaction boundary and are stripped
  before any evidence row or world record.
- **`blackforge/cloud/normalization.py`** — typed normalization adapters that
  parse mock raw output into typed observation models; `is_header_status_line()`
  and `normalize_response_text()` fold a stray status line so a malformed raw
  feed cannot fabricate rows.
- **`blackforge/cloud/evidence.py`** — `artifact_evidence()` and
  `observation_evidence()` construct evidence records; `observation_confidence()`
  implements the confidence policy; the cloud mode is embedded in each stored
  raw payload so a PASSIVE observation never dedups onto (and silently inherits
  the confidence of) a CONTROLLED record while repeated same-mode runs still
  coalesce; `evidence_dedup_key_for()` / `existing_evidence_id()` enable
  idempotent reruns.
- **`blackforge/cloud/materializer.py`** (`CloudWorldMaterializer`) — maps typed
  observations into World Model records with a fixed, deterministic mapping.
  **No offensive edge types (EXPLOITS / CAN_COMPROMISE / LEADS_TO / ENABLES) are
  ever emitted.** A HIGH-confidence origin candidate is materialized as an
  `ORIGIN_CANDIDATE` at INFERRED / unvalidated and is **never** auto-promoted to
  a confirmed origin — an origin is only an origin when an origin endpoint
  actually exists.
- **`blackforge/cloud/redaction.py`** — credential-like keys (`access_key`,
  `access_key_id`, `secret_key`, `secret_value`, `connection_string`,
  `private_key`, `public_key_material`, `client_secret`,
  `service_account_secret`, `iam_credential`, `managed_identity_secret`,
  `token`, `password`, `secret`, `credentials`, plus token-level matches)
  are force-redacted to the literal `REDACTED` marker. Re-exports
  `credential_value_redacted` from the network redaction layer.
- **`blackforge/cloud/models.py`** — `CloudMode` (PASSIVE/CONTROLLED),
  `CloudStatus`, `CloudObservationKind`, typed observation models discriminated
  by `"kind"`, `CloudRequest`, `CloudResult`. Added `AddressType` /
  `classify_address()` (public vs private addressing) for origin-candidate
  correlation.
- **`blackforge/cloud/addressing.py`** — provider / account / project /
  asset addressing helpers; `provider_and_target()` parses `provider/...`
  targets and supports provider-level umbrellas (`aws` covers `aws/...`).
- **`blackforge/cloud/providers.py`** — provider registry and identity
  resolution over the three supported providers.
- **`blackforge/core/errors.py`** — `CloudError`, `CloudNormalizationError`,
  `CloudExecutionError`, `CloudTimeoutError`; out-of-scope targets surface an
  `AuthorizationError` before any transport work.
- **`blackforge/core/types.py`** — `TargetType` gained `CLOUD`;
  `blackforge/world_model/models.py` gained `EdgeType.SECURITY` (in addition to
  `ORGANIZATIONAL`/`INFRASTRUCTURE`) and `RelationshipType` gained `PROTECTS`,
  `PROXIES`, `FRONTED_BY`; `blackforge/world_model/canonical.py` gained
  `normalize_cloud_*` / host addressing; scope matching gained provider-aware
  umbrella rules (`aws` / `azure` / `gcp`).

## Capabilities

| ID | Name | Mode | Risk | Produces |
|---|---|---|---|---|
| `cloud.provider_discovery` | Provider Discovery | PASSIVE | LOW | CLOUD_PROVIDER |
| `cloud.account_inventory` | Account Inventory | PASSIVE | LOW | CLOUD_ACCOUNT |
| `cloud.project_inventory` | Project Inventory | PASSIVE | LOW | CLOUD_PROJECT |
| `cloud.resource_inventory` | Resource Inventory | PASSIVE | LOW | CLOUD_REGION |
| `cloud.compute_observation` | Compute Observation | PASSIVE | LOW | CLOUD_COMPUTE |
| `cloud.storage_observation` | Storage Observation | PASSIVE | LOW | CLOUD_STORAGE |
| `cloud.database_observation` | Database Observation | PASSIVE | LOW | CLOUD_DATABASE |
| `cloud.network_observation` | Network Observation | PASSIVE | LOW | CLOUD_NETWORK |
| `cloud.public_exposure_analysis` | Public Exposure | PASSIVE | LOW | PUBLIC_ADDRESS |
| `cloud.security_configuration_observation` | Security Configuration | PASSIVE | LOW | CLOUD_ACCOUNT |
| `cloud.secret_reference_observation` | Secret References | PASSIVE | LOW | CLOUD_SECRET |
| `cloud.iam_identity_observation` | IAM Identity Observation | PASSIVE | LOW | IDENTITY |
| `cloud.iam_role_observation` | IAM Role Observation | PASSIVE | LOW | ROLE |
| `cloud.iam_permission_observation` | IAM Permission Observation | PASSIVE | LOW | PERMISSION |
| `cloud.resource_relationship_analysis` | Resource Relationships | PASSIVE | LOW | RELATIONSHIP |
| `cloud.container_observation` | Container Observation | PASSIVE | LOW | CLOUD_CONTAINER |
| `cloud.cluster_observation` | Cluster Observation | PASSIVE | LOW | CLOUD_CLUSTER |
| `cloud.edge_architecture_observation` | Edge Architecture | PASSIVE | LOW | EDGE_ENDPOINT |
| `cloud.origin_candidate_analysis` | Origin Candidate Analysis | PASSIVE | LOW | ORIGIN_CANDIDATE |
| `cloud.transport_security_observation` | Transport Security | PASSIVE | LOW | ENDPOINT |

All twenty capabilities support `TargetType.CLOUD`. Registry counts:
defaults-only → 1, recon → 7, + webapi → 17, + auth → 28, + business logic →
39, + network → 50, + identity → 61, + cloud → **81** (`cloud_ready`, twenty
typed capabilities).

## Safety Model

Every capability runs the identical guarded pipeline:

1. **LLM Suggestion → Deterministic Policy → Capability Allowlist → Scope →
   Authorization** — a model suggestion can only select a capability that
   exists on the deterministic allowlist. The target must be inside
   `TargetScope.allowed_targets`; otherwise an `AuthorizationError` is raised
   **before** any transport work. Provider references act as umbrellas: `aws`
   covers `aws/...`, `aws/<account>`, `aws/<account>/<asset>` — normalization
   based scope membership only, never a data access.
2. **Typed surface, fail-closed** — only the twenty typed contracts exist. An
   unknown capability ID is rejected with `CloudExecutionError` before anything
   runs (no generic executor). Unsupported target types (e.g. a domain or IP
   address) are rejected before transport.
3. **Deterministic mock transport** — the only transport iterates three fixed
   mock estates. No real cloud is ever queried or mutated. Credential-like demo
   fields are stripped at the boundary.
4. **Evidence integrity** — every observation persists with `OBSERVED`
   provenance (cloud evidence is never elevated) and DERIVED_FROM links to its
   run's artifact; a PASSIVE run produces LOW confidence records independent of
   any earlier CONTROLLED run on the same target.
5. **World Model** — descriptive/structural edges only; no offensive
   relationship types are materialized. Contradictions surface instead of
   silently overwriting; candidates are never confirmed until validated.
6. **Failure-aware statuses** — negative outcomes (timeout, rate limited,
   unauthorized, malformed, unsupported provider, limited truncation) are
   recorded as structured `CloudStatus` results, never silent failures, and
   never become findings.
7. **No autonomous action** — a HIGH-confidence origin candidate, a suspected
   vuln, or a transport-security mismatch never triggers automatic remediation
   or exploitation. Analysis is observational and read-only.

## Transport Abstraction

`MockCloudTransport` is the only transport. The demo fixture defines three
estates plus synthetic error targets:

- **AWS** — `aws/aelionix-aws-test`: 2 projects, 17 resources, 3 providers;
  edge fronting + origin-candidate + transport-security scenarios (see below).
- **Azure** — `azure/aelionix-azure-test`: 2 projects, 9 resources.
- **GCP** — `gcp/aelionix-gcp-test`: 1 project, 8 resources.
- Five synthetic error accounts (`snail-account`, `bursty-account`,
  `locked-account`, `garbled-account`, `fabricated-estate`) and any unmodeled
  provider/account produce handled error documents:

| Error fixture | `error.kind` | Status |
|---|---|---|
| `aws/snail-account` | `timeout` | TIMEOUT |
| `aws/bursty-account` | `rate_limited` | RATE_LIMITED |
| `aws/locked-account` | `unauthorized` | UNAUTHORIZED |
| `aws/garbled-account` | `malformed_response` | MALFORMED_RESPONSE |
| `aws/fabricated-estate` / unmodeled | `unsupported_provider` | UNSUPPORTED_PROVIDER |

Any in-scope but unsupported provider (`oci/foo`) fails closed with
`UNKNOWN_PROVIDER` and zero observations — never a crash, never an empty
"clean" result. `observe_security_configuration(AWS)` returns `status ==
PARTIAL` with 6 observations: the `cloudtrail_logging` contradiction pair
(`enabled` + `disabled`) is collapsed into one status while **both** assertion
values remain visible on the account.

Deterministic fixture behavior (verified by tests and the validation notebook)
for the typed counts per estate:

- **AWS** — discover_providers 1, inventory_accounts 1, inventory_projects 2,
  inventory_resources 17, observe_compute 2, observe_storage 3,
  observe_databases 1, observe_networks 5, analyze_public_exposure 5,
  observe_security_configuration 6 (PARTIAL), observe_secret_references 3,
  observe_iam_identities 3, observe_iam_roles 3, observe_iam_permissions 5,
  analyze_resource_relationships 7, observe_containers 2, observe_clusters 1,
  observe_edge_architecture 2, analyze_origin_candidates 4,
  observe_transport_security 4.
- **Azure** — 1, 1, 2, 9, 2, 1, 1, 2, 2, 2, 1, 2, 2, 2, 2, 1, 1, 1, 2, 2.
- **GCP** — 1, 1, 1, 8, 2, 1, 1, 1, 2, 2, 1, 2, 2, 2, 2, 1, 1, 1, 2, 2.

An `observation_count` of 1 on `discover_providers` holds even though three
providers exist: the estate's resolved provider identity is a single typed
observation.

## Observation Models

All observations are discriminated unions keyed on `"kind"`:

- `ProviderObservation` (kind=provider) — provider, estate
- `AccountObservation` (kind=account) — account, provider
- `ProjectObservation` (kind=project) — project, account, provider
- `ResourceObservation` (kind=resource) — resource, resource_type, account, project
- `ComputeObservation` (kind=compute) — instance, state, account, region
- `StorageObservation` (kind=storage) — bucket, account, region
- `DatabaseObservation` (kind=database) — database, engine, account
- `NetworkObservation` (kind=network) — network, cidr, account, region
- `PublicExposureObservation` (kind=public_exposure) — asset, address, port, exposure
- `SecurityConfigurationObservation` (kind=security_configuration) —
  account, property_key, property_value, source
- `SecretReferenceObservation` (kind=secret_reference) — secret, referenced_by, key
- `IamIdentityObservation` / `IamRoleObservation` / `IamPermissionObservation`
  (kind=iam_identity / iam_role / iam_permission) — identity / role / permission
- `ResourceRelationshipObservation` (kind=resource_relationship) —
  relationship_type, source, target (structural vocabulary only)
- `ContainerObservation` (kind=container) — container, image, state
- `ClusterObservation` (kind=cluster) — cluster, nodegroup, state
- `EdgeArchitectureObservation` (kind=edge_architecture) — edge, origin,
  **directly_reachable_origin**, provider
- `OriginCandidateObservation` (kind=origin_candidate) — candidate, address,
  address_type, confidence, validation
- `TransportSecurityObservation` (kind=transport_security) — endpoint_name,
  tls_enforced, tls_version, provider

## World Model Semantics

Cloud resources are namespaced per provider/account (`canonical_key` e.g.
`cloud_compute|aws/aelionix-aws-test|web-01`). The mapping is fixed and
deterministic, and **no attack-graph relationship types are ever materialized**:

- CLOUD_PROVIDER --CONTAINS--> CLOUD_ACCOUNT --CONTAINS--> CLOUD_PROJECT
  --CONTAINS--> CLOUD_REGION --CONTAINS--> compute / storage / database /
  network / container / cluster.
- Cloud compute / storage / database / network / container / cluster
  --LOCATED_IN--> CLOUD_REGION.
- IAM IDENTITY --HAS_ROLE--> ROLE --HAS_PERMISSION--> PERMISSION;
  PERMISSION --APPLIES_TO--> resource (from IAM observation + relationship
  analysis); relationships remain structural (`contains`, `located_in`,
  `connects_to`, `depends_on`, `routes_to`, `uses`).
- **Edge / origin / transport (Phase 11 amendment):**
  - EDGE_ENDPOINT --PROTECTS--> CLOUD_COMPUTE (the fronted app) and
    EDGE_ENDPOINT --PROXIES--> ORIGIN_ENDPOINT. `directly_reachable_origin` is
    asserted INFERRED `false` on every edge.
  - ORIGIN_ENDPOINT --FRONTED_BY--> EDGE_ENDPOINT (the origin is reachable only
    through the edge).
  - ORIGIN_CANDIDATE --ROUTES_TO--> PRIVATE/PUBLIC_ADDRESS and, for a
    HIGH-confidence `edge_config` candidate, an ORIGINATES_FROM edge to an
    existing ORIGIN_ENDPOINT. **A candidate is never promoted to a confirmed
    origin.** The HIGH candidate `app.aelionix.test:10.0.0.10` keeps
    `confidence_label=high` / `evidence_status=inferred` /
    `validation_status=unvalidated`; the exposure-feed candidate
    `app.aelionix.test:203.0.113.10` stays LOW / `hypothesized` with **no**
    ORIGINATES_FROM edge.
  - Transport security asserts `tls_enforced` / `tls_version`; contradictory
    TLS rows (`True` + `False`, `TLS1.0` + `TLS1.3`) both surface on the
    transport endpoint. Endpoint canonical names drop any trailing slash
    (`https://app.aelionix.test`, `https://api.aelionix.test`).

Cross-provider headline totals (deterministic, asserted in tests and the
notebook): 4 active EDGE_ENDPOINT, 3 ORIGIN_ENDPOINT, 8 ORIGIN_CANDIDATE, 7
ENDPOINT, 3 PUBLIC_ADDRESS, 4 PRIVATE_ADDRESS, 101 active entities. Provenance
is preserved: entities, relationships, and assertions carry their evidence
links; every evidence row links to its run's artifact via DERIVED_FROM.

## Confidence Policy

- PASSIVE mode → LOW confidence (applied unconditionally).
- CONTROLLED direct authoritative provider records (provider/account/project/
  resource inventories, IAM records, secret references) → HIGH.
- Security configuration sourced from the authoritative `provider` feed →
  HIGH; correlated feeds → MEDIUM.
- Derived kinds (public exposure, resource relationships, edge architecture,
  origin-candidate correlation, transport security) → MEDIUM in CONTROLLED.
- Mode is embedded in each stored evidence payload, so dedup can never cross
  modes: a PASSIVE run yields its own LOW records independent of an earlier
  CONTROLLED run, while repeated same-mode runs coalesce idempotently.

## Redaction

Credential-like keys (`access_key`, `access_key_id`, `secret_key`,
`secret_value`, `connection_string`, `private_key`, `public_key_material`,
`client_secret`, `service_account_secret`, `iam_credential`,
`managed_identity_secret`, `token`, `password`, `secret`, `credentials`, plus
token-level matches for access/secret/connection/credential/key) are
force-replaced with the literal `REDACTED` marker — never a hash, so redaction
is unambiguous. Non-secret sibling keys are preserved so the observation keeps
its structure. `redact_cloud_document()` (recursive) and `redact_cloud_raw()`
(JSON re-serialization) run at the redaction boundary;
`credential_value_redacted()` is re-exported from the network layer. The demo
dataset carries credential-like fields **only** to prove the boundary. Tests
assert no plaintext credential-like value ever appears in raw output, artifact
payloads, observation rows, or world-model assertions, and that a secret
reference artifact keeps its structure (`bucket` preserved) while
`connection_string`/`access_key_id`/`secret_value` become `REDACTED`.
