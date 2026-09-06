# Identity & Directory Security

## Architecture

The Identity & Directory Security Capability Foundation mirrors the
`recon/` / `webapi/` / `auth/` / `business_logic/` / `network/` architecture: a
typed engine, typed capabilities, a deterministic mock-only transport,
normalization adapters, evidence persistence, and World Model materialization —
with **no real directory queries, no credential use, no mutation, and no
offensive semantics**. Every observation is read-only against a fixed internal
fixture.

- **`blackforge/identity/engine.py`** (`IdentityEngine`) — guards and
  orchestrates the full pipeline: request validation → scope/authorization →
  identity resolution → mock transport → normalization → evidence persistence
  (artifact + typed observations) → World Model materialization → best-effort
  memory link. `capability_ids()` builds the expected ID set; the 11 tool
  methods are bound to capability IDs; `_ERROR_KIND_TO_STATUS` maps transport
  error kinds to `IdentityStatus`; identity-level tools resolve the explicit
  identity from capability params → request → target string.
- **`blackforge/identity/capabilities.py`** — eleven typed `IdentityCapability`
  instances, each bound to a transport method, a normalization adapter, and
  capability metadata. `build_identity_capabilities()` builds all eleven;
  `build_identity_meta()` builds their metadata; `IdentityCapabilityMeta` adds
  `category="identity"`, PASSIVE default mode, `produces`, and
  `world_model=True`.
- **`blackforge/identity/transport.py`** (`MockIdentityTransport`) —
  deterministic, mock-only transport over the `AELIONIX-CORP` fixture
  (`AELIONIX-CORP.LOCAL`). Never touches a real directory; every method returns
  a JSON document. Credential-like demo fields exist **only** to prove the
  redaction boundary and are stripped before any evidence row or world record.
- **`blackforge/identity/normalization.py`** — eleven `IdentityToolAdapter`
  subclasses that parse mock raw output into typed observation models.
  `adapter_for_tool()` routes each transport method to its adapter.
- **`blackforge/identity/evidence.py`** — `artifact_evidence()` and
  `observation_evidence()` construct evidence records; `observation_confidence()`
  implements the confidence policy; the identity mode is embedded in each stored
  raw payload so a PASSIVE observation never dedups onto (and silently inherits
  the confidence of) a CONTROLLED record while repeated same-mode runs still
  coalesce; `evidence_dedup_key_for()` / `existing_evidence_id()` enable
  idempotent reruns.
- **`blackforge/identity/materializer.py`** (`IdentityWorldMaterializer`) —
  maps typed observations into World Model records with a fixed, deterministic
  mapping. **No offensive edge types (EXPLOITS / CAN_COMPROMISE / LEADS_TO /
  ENABLES) are ever emitted.**
- **`blackforge/identity/redaction.py`** — credential-like keys are
  force-redacted to the literal `REDACTED` marker (recursive field sweep +
  token-level key matching + JSON document/raw re-serialization). Re-exports
  `credential_value_redacted` from the network redaction layer.
- **`blackforge/identity/models.py`** — `IdentityMode` (PASSIVE/CONTROLLED),
  `IdentityStatus` (thirteen failure-aware outcomes), `IdentityObservationKind`,
  eleven typed observation models discriminated by `"kind"`, `IdentityRequest`,
  `IdentityResult`.
- **`blackforge/core/errors.py`** — `IdentityError`,
  `IdentityNormalizationError`, `IdentityExecutionError`, `IdentityTimeoutError`.
- **`blackforge/core/types.py`** — `TargetType` gained `DIRECTORY` and
  `IDENTITY`; `blackforge/world_model/models.py` gained `EntityType.DIRECTORY`
  and `EntityType.GROUP`; `blackforge/world_model/canonical.py` gained
  `normalize_directory()` (short corporate name, identity forms rejected) and
  directory/group name normalizers; scope matching gained directory-aware
  spelling rules (`AELIONIX-CORP` / `AELIONIX-CORP.LOCAL` / UPN identities /
  down-level identities / DNS sub-objects).

## Capabilities

| ID | Name | Mode | Risk | Produces |
|---|---|---|---|---|
| `identity.directory_discovery` | Directory Discovery | PASSIVE | LOW | DIRECTORY |
| `identity.identity_inventory` | Identity Inventory | PASSIVE | LOW | IDENTITY |
| `identity.group_inventory` | Group Inventory | PASSIVE | LOW | GROUP |
| `identity.role_inventory` | Role Inventory | PASSIVE | LOW | ROLE |
| `identity.permission_inventory` | Permission Inventory | PASSIVE | LOW | PERMISSION |
| `identity.resource_inventory` | Resource Inventory | PASSIVE | LOW | RESOURCE |
| `identity.membership_observation` | Membership Observation | PASSIVE | LOW | MEMBERSHIP |
| `identity.role_assignment_observation` | Role Assignment Observation | PASSIVE | LOW | ROLE_ASSIGNMENT |
| `identity.permission_assignment_observation` | Permission Assignment Observation | PASSIVE | LOW | PERMISSION_ASSIGNMENT |
| `identity.relationship_analysis` | Relationship Analysis | PASSIVE | LOW | RELATIONSHIP |
| `identity.metadata_observation` | Metadata Observation | PASSIVE | LOW | METADATA |

Directory-level tools (the six inventory capabilities) accept DIRECTORY /
ASSET / DOMAIN targets; identity-level tools (the five observation
capabilities) additionally accept IDENTITY targets. Registry counts:
defaults-only → 1, recon → 7, + webapi → 17, + auth → 28, + business logic →
39, + network → 50, + identity → **61** (`identity_ready`, eleven typed
capabilities).

## Safety Model

Every capability runs the identical guarded pipeline:

1. **Scope** — the target must be inside `TargetScope.allowed_targets`;
   otherwise an `AuthorizationError` is raised **before** any transport work.
   Directory references act as umbrellas: `AELIONIX-CORP` covers
   `AELIONIX-CORP.LOCAL`, UPN identities, down-level identities, and DNS
   sub-objects of the domain — normalization-based scope membership only, never
   a data access.
2. **Typed surface, fail-closed** — only the eleven typed contracts exist. An
   unknown capability ID is rejected with `IdentityExecutionError` before
   anything runs (no generic executor). Unsupported target types (e.g. an IP
   address) are rejected before transport.
3. **Deterministic mock transport** — the only transport iterates the
   `AELIONIX-CORP` fixture. No real directory is ever queried or mutated.
   Credential-like demo fields are stripped at the boundary.
4. **Evidence integrity** — every observation persists with `OBSERVED`
   provenance (identity evidence is never elevated) and DERIVED_FROM links to
   its run's artifact; a PASSIVE run produces LOW confidence records
   independent of any earlier CONTROLLED run on the same target.
5. **World Model** — descriptive/structural edges only; no offensive
   relationship types are materialized.
6. **Failure-aware statuses** — negative outcomes (timeout, rate limited,
   unauthorized, malformed, unsupported directory, no evidence) are recorded as
   structured `IdentityStatus` results, never silent failures, and never become
   findings.

## Transport Abstraction

`MockIdentityTransport` is the only transport. The demo fixture:

- One active-domain-style directory, `AELIONIX-CORP` (DNS
  `AELIONIX-CORP.LOCAL`).
- Five identities: `alice` (human, standard), `bob` (human, elevated),
  `build-service` / `api-service` (service accounts), `web-server-01$`
  (computer).
- Four groups (`engineering`, `operations`, `administrators`, `read-only`),
  four roles (`application-admin`, `deployment-operator`, `viewer`,
  `service-operator`), four permissions (`deploy`, `manage`, `read`,
  `view_logs`), four resources (`production-api`, `internal-dashboard`,
  `deployment-system`, `database-cluster`).
- Memberships: `alice → engineering`; `bob → operations, administrators`;
  `build-service → operations`; `api-service → read-only`;
  `web-server-01$ → administrators`. `observe_membership` emits a duplicate row
  per group to prove **deterministic collapse** (2 rows in, 1 observation out,
  status PARTIAL with a `collapsed duplicate membership` warning).
- Role assignments: `alice → viewer`; `bob → deployment-operator`;
  `build-service / api-service → service-operator`; `web-server-01$ → viewer`.
- Permission assignments flow from roles:
  `deployment-operator → deploy, view_logs`; `viewer → read`;
  `service-operator → manage`; `application-admin → deploy`.
- Permission-to-resource edges: `deploy → production-api, deployment-system`;
  `manage → internal-dashboard, database-cluster`; `read →
  internal-dashboard`; `view_logs → deployment-system`.
- Metadata: `alice` has a **contradiction** — `department=engineering`
  (source `directory`, authoritative) vs `department=sales` (source
  `secondary_hr_feed`); `api-service` has a **missing reference**
  (`manager=ghost-manager`, source `identity_api`, unresolved → PARTIAL with a
  warning).
- Five synthetic error directories (`snail-dir`, `bursty-dir`, `locked-dir`,
  `garbled-dir`, `fabricated-dir`) and any unmodeled directory produce handled
  error documents:

| Error fixture | `error.kind` | Status |
|---|---|---|
| `SNAIL-DIR` | `timeout` | TIMEOUT |
| `BURSTY-DIR` | `rate_limited` | RATE_LIMITED |
| `LOCKED-DIR` | `unauthorized` | UNAUTHORIZED |
| `GARBLED-DIR` | `malformed` | MALFORMED_RESPONSE |
| `FABRICATED-DIR` / any unmodeled dir | `unsupported_directory` | UNSUPPORTED_DIRECTORY |

- Identity-level tools on a directory target without an identity spellings
  (`name@corp.local`, `CORP\name`, or the `identity=` param) also produce
  `unsupported_directory`; an unknown identity name inside a resolved directory
  produces `unknown_identity` → NO_EVIDENCE (never a crash).

Deterministic fixture behavior (verified by tests and the validation notebook):

- `discover_directories("AELIONIX-CORP")` → 1 directory observation.
- `inventory_identities` → 5; `inventory_groups` → 4; `inventory_roles` → 4;
  `inventory_permissions` → 4; `inventory_resources` → 4.
- `observe_membership(alice)` → 1 observation (collapsed, PARTIAL);
  `observe_role_assignment(bob)` → 1; `observe_permission_assignment(bob)` → 2;
  `analyze_relationships(alice)` → 4 (member_of, has_role, has_permission,
  applies_to); `observe_metadata(alice)` → 2.

## Observation Models

All observations are discriminated unions keyed on `"kind"`:

- `DirectoryObservation` (kind=directory) — directory, dns_name, directory_type, forest
- `IdentityObservation` (kind=identity) — identity, principal_type, display_name, email, enabled, locked, privilege_level
- `GroupObservation` (kind=group) — group, scope_type, membership_count
- `RoleObservation` (kind=role) — role, privilege_level
- `PermissionObservation` (kind=permission) — permission
- `ResourceObservation` (kind=resource) — resource, resource_type
- `MembershipObservation` (kind=membership) — identity, group, **resolved**
- `RoleAssignmentObservation` (kind=role_assignment) — identity, role
- `PermissionAssignmentObservation` (kind=permission_assignment) — role, permission
- `RelationshipObservation` (kind=relationship) — relationship_type, source, target (bounded vocabulary: member_of / has_role / has_permission / applies_to)
- `MetadataObservation` (kind=metadata) — identity, attribute_key, attribute_value, source, **resolved** (+ `missing_reference`)

## World Model Semantics

Identity-bearing entities are namespaced by directory so same-named principals
across directories stay distinct (`canonical_key` e.g.
`identity|aelionix-corp|alice`). The mapping is fixed and deterministic:

- DIRECTORY --CONTAINS--> GROUP / IDENTITY / ROLE / PERMISSION / RESOURCE
  (from the six inventory capabilities).
- IDENTITY --MEMBER_OF--> GROUP (membership, only when `resolved`).
- IDENTITY --HAS_ROLE--> ROLE (role assignment).
- ROLE --HAS_PERMISSION--> PERMISSION (permission assignment).
- PERMISSION --APPLIES_TO--> RESOURCE (relationship analysis).
- Metadata becomes an **assertion** on the identity entity; a correlated-feed
  claim (e.g. `secondary_hr_feed` with a different value) is recorded at
  INFERRED status and the materializer report counts an
  **assertions_contradicted** — a weak claim never silently overwrites an
  authoritative record. `IdentityMaterializeReport` exposes `entries`,
  `relationships_created/corroborated`, and `assertions_created/corroborated/
  contradicted`.

Provenance is preserved: entities, relationships, and assertions carry their
evidence links; every evidence row is linked to its run's artifact via
DERIVED_FROM. No attack-graph relationship types are ever materialized.

## Confidence Policy

- PASSIVE mode → LOW confidence (applied unconditionally).
- CONTROLLED direct inventory observations (directory/identity/group/role/
  permission/resource) → HIGH.
- Derived kinds (relationship analysis) and non-authoritative metadata feeds →
  MEDIUM (`observation_confidence` lowers PASSIVE to LOW before any kind rule).
- Mode is embedded in each stored evidence payload, so dedup can never
  cross modes: a PASSIVE run yields its own LOW records independent of an
  earlier CONTROLLED run, while repeated same-mode runs coalesce idempotently.

## Redaction

Credential-like keys (`password_hash`, `nt_hash`, `lm_hash`,
`kerberos_ticket`, `session_token`, `mfa_secret`, `recovery_code`,
`service_account_secret`, `sso_token`, `password`, `token`, `secret`,
`credentials`, plus token-level matches for hash/credential/ticket) are
force-replaced with the literal `REDACTED` marker — never a hash, so redaction
is unambiguous. Non-secret sibling keys are preserved so the observation keeps
its structure. `redact_identity_document()` (recursive) and
`redact_identity_raw()` (JSON re-serialization) run at the redaction boundary;
`credential_value_redacted()` is re-exported from the network layer. The demo
dataset carries `build-service.password_hash`/`session_token` and
`api-service.credentials.api_key` **only** to prove the boundary. Tests assert
no plaintext credential-like value ever appears in raw output, artifact
payloads, observation rows, or world-model assertions.