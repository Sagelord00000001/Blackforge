# Source & Runtime Correlation

## Architecture

The Source & Runtime Correlation Capability Foundation is the first
**two-independent-sources** capability layer in Blackforge: it joins a
**declared** (source) view of a workload estate with an **observed** (runtime)
view and reports whether the two agree — without inventing either side and
without ever querying or mutating a real cluster, registry, or cloud.

Unlike the earlier `recon/` / `webapi/` / `auth/` / `business_logic/` /
`network/` / `identity/` / `cloud/` / `container/` engines, the Phase 13
pipeline does **not** collect facts into the World Model on its own. It reads
from **independent fixture sources** (`blackforge/source_runtime/source.py` and
`blackforge/source_runtime/runtime.py`) that share a fixture format but are
separate modules — the runtime side is never derived from the declared side, so
a mismatch between them is a real signal, not an artifact.

- **`blackforge/source_runtime/engine.py`** (`SourceRuntimeEngine`) — guards
  and orchestrates the full pipeline: request validation → Scope → Authorization
  → target resolution → capability validation (fail-closed, no generic
  executor) → mock transport → identity pairing → deterministic rule
  comparison → evidence persistence (correlation evidence **derived** from the
  independent source and runtime evidence, never in place of them) → World
  Model materialization → best-effort memory link. `run()` returns a
  `SourceRuntimeResult` with typed outcomes; `_parse_document()` raises
  `SourceRuntimeExecutionError` on transport error documents, so a missing
  fixture is a structured failure, never a fabricated `MATCH`.
- **`blackforge/source_runtime/models.py`** — `SourceRuntimeMode`
  (PASSIVE/CONTROLLED), `SourceRuntimeStatus` (SUCCESS, PARTIAL, NO_EVIDENCE,
  INSUFFICIENT_EVIDENCE, NOT_COMPARABLE, OUT_OF_SCOPE, UNSUPPORTED_TARGET,
  UNKNOWN_CAPABILITY, REQUEST_FAILED, FAILED), `SourceRuntimeRequest`,
  `SourceRuntimeResult`, `SourceRuntimeOutcome`.
- **`blackforge/source_runtime/capabilities.py`** — ten typed correlation
  capabilities bound to transport methods, property maps, and metadata;
  `SOURCE_RUNTIME_CAPABILITY_IDS` is the ordered 10-ID surface. Every capability
  is risk **LOW**, mode **CONTROLLED**, and supported on `ASSET`/`CLOUD`/
  `APPLICATION` targets.
- **`blackforge/source_runtime/source.py`** — the independent **declared**
  fixture side. Relative topology does **not** exist: runtime records are
  loaded/stored as a source of truth and the transport only ever reads several
  **independent** fixture modules (declared size: **5 entry-level identity
  records**).
- **`blackforge/source_runtime/runtime.py`** — the independent **observed**
  fixture side (observed size: **6 entry-level identity records**, one more
  runtime-only service than declared). It carries a version stamp so a missing
  fixture cannot silently pass as "no difference".
- **`blackforge/source_runtime/identity.py`** — canonical identity
  construction and matching. `build_correlation_identity(scope_kind,
  scope_parts, name)` produces an opaque canonical string
  (`cluster:aelionix-prod:payments:payment-gateway`); `same_correlation_identity`
  is true only when both sides resolve to the identical canonical identity, so a
  service with the same name in a different scope (e.g. prod vs staging) is
  **never** silently paired.
- **`blackforge/source_runtime/rules.py`** — the deterministic rule vocabulary
  (`sr_exact` exact equality, `sr_set` order-independent set equality,
  `sr_digest` immutable digest for images, `sr_presence` presence-only,
  `sr_contradiction` mutually-exclusive contradiction set) plus
  `default_rule_registry()` and `register_rule()`. No freeform interpretation:
  every comparison is a registered, versioned, deterministic rule.
- **`blackforge/source_runtime/correlation.py`** — `CorrelationEvaluator`
  compares paired source/runtime records into typed `CorrelationComparison`
  rows (`property`, `rule`, `result`, `source_value`, `runtime_value`, `note`)
  and aggregates outcomes. A `CONTRADICTION` outranks `DISCREPANCY`, which
  outranks `MATCH`/`UNKNOWN`; the aggregate drives the outcome's result.
- **`blackforge/source_runtime/redaction.py`** — credential-like keys
  (see Redaction) force-redacted to the literal `REDACTED` marker before
  anything is stored. `redact_source_runtime_raw()` re-serializes JSON;
  `redact_source_runtime_document()` is recursive.
- **`blackforge/source_runtime/transport.py`** (`MockSourceRuntimeTransport`) —
  deterministic, mock-only transport. Never touches a real cluster, registry, or
  cloud; every method returns a JSON document. Unmodeled targets produce a
  handled error document (`error.kind == "no_fixture_records"`) that propagates
  as a structured `SourceRuntimeExecutionError`.
- **`blackforge/source_runtime/evidence.py`** — `source_evidence()`
  (`SOURCE_ANALYSIS`, OBSERVED), `runtime_evidence()` (`OBSERVATION`,
  OBSERVED), and `correlation_outcome_evidence()` (`VALIDATION_RESULT`,
  INFERRED). `correlation_confidence()` is **the weaker of the two independent
  sides** (LOW+HIGH → LOW); dedup never inflates confidence.
- **`blackforge/source_runtime/materializer.py`**
  (`SourceRuntimeWorldMaterializer`) — maps paired outcomes into World Model
  records: a `SOURCE_COMPONENT` entity per correlated service plus `:source` /
  `:runtime` sibling entities and `DECLARED_AS` / `OBSERVED_AS` /
  `CORRESPONDS_TO` / `DIFFERS_FROM` edges. **No offensive edge types
  (EXPLOITS / CAN_COMPROMISE / LEADS_TO / ENABLES) are ever emitted.**
- **`blackforge/core/errors.py`** — `SourceRuntimeError` family including
  `SourceRuntimeExecutionError`; out-of-scope targets surface an
  `AuthorizationError` **before** any transport work.
- **`blackforge/world_model/models.py`** — `RelationshipType` gained
  `DECLARED_AS`, `OBSERVED_AS`, `CORRESPONDS_TO`, `DIFFERS_FROM`; `EntityType`
  gained `SOURCE_COMPONENT`.

## Capabilities

| ID | Name | Mode | Risk | Compares |
|---|---|---|---|---|
| `source_runtime.container_configuration_correlation` | Container Configuration | CONTROLLED | LOW | declared vs observed |
| `source_runtime.image_runtime_correlation` | Image / Runtime | CONTROLLED | LOW | digest / tag |
| `source_runtime.workload_manifest_correlation` | Workload Manifest | CONTROLLED | LOW | replicas / resources |
| `source_runtime.service_exposure_correlation` | Service Exposure | CONTROLLED | LOW | port / type |
| `source_runtime.ingress_runtime_correlation` | Ingress / Runtime | CONTROLLED | LOW | host / path |
| `source_runtime.network_policy_correlation` | Network Policy | CONTROLLED | LOW | selector / policy |
| `source_runtime.cloud_resource_correlation` | Cloud Resource | CONTROLLED | LOW | backup / version / exposure |
| `source_runtime.api_surface_correlation` | API Surface | CONTROLLED | LOW | endpoint / method |
| `source_runtime.application_configuration_correlation` | Application Config | CONTROLLED | LOW | config keys |
| `source_runtime.rbac_manifest_correlation` | RBAC Manifest | CONTROLLED | LOW | role / binding |

All ten capabilities support `ASSET` / `CLOUD` / `APPLICATION` targets and
compare against the full result vocabulary (`MATCH`, `DISCREPANCY`,
`CONTRADICTION`, `UNKNOWN`, `INSUFFICIENT_EVIDENCE`, `NOT_COMPARABLE`).
Registry counts: defaults-only → 1, recon → 7, + webapi → 17, + auth → 28,
+ business logic → 39, + network → 50, + identity → 61, + cloud → 81, +
container → 95, + source runtime → **105** (`source_runtime_ready`, ten typed
correlation capabilities).

## Safety Model

Every capability runs the identical guarded pipeline:

1. **Request → Scope → Authorization** — the target must be inside
   `TargetScope.allowed_targets`; otherwise an `AuthorizationError` is raised
   **before** any transport work. Umbrella targets (`cloud`, `cluster`,
   `image`) are resolved against the whole family; scoped targets
   (`aelionix-prod/payments`, `registry.aelionix.io`) narrow to a single
   identity.
2. **Typed surface, fail-closed** — only the ten typed contracts exist. An
   unknown capability ID is rejected with a structured
   `UNKNOWN_CAPABILITY` result before anything runs (no generic executor).
   Unsupported targets are rejected before transport.
3. **Independent deterministic transport** — the only transport iterates
   independent source/runtime fixture modules. No real cluster, registry, or
   cloud is ever queried or mutated.
4. **Correlation never authors facts** — correlation evidence is
   `VALIDATION_RESULT` / INFERRED **derived** from (never in place of) the
   `SOURCE_ANALYSIS` / `OBSERVATION` evidence of the two independent sides.
   Confidence is the weaker of the two sides and is never inflated by dedup.
   A runtime-only service is reported as `UNKNOWN` with a
   `missing source evidence` note — never fabricated into a `MATCH`.
5. **World Model** — descriptive/structural edges only
   (`DECLARED_AS` / `OBSERVED_AS` / `CORRESPONDS_TO` / `DIFFERS_FROM`); no
   attack-graph relationship types are materialized. Contradictions surface
   instead of silently overwriting.
6. **Failure-aware statuses** — negative outcomes (out of scope, unsupported
   target, unknown capability, no fixture, request failure) are recorded as
   structured `SourceRuntimeStatus` results, never silent failures, and never
   become findings.
7. **No autonomous action** — a `CONTRADICTION` or `DISCREPANCY` never
   triggers automatic remediation or exploitation. Correlation is
   observational and read-only; it is **not** vulnerability detection.

## Transport Abstraction

`MockSourceRuntimeTransport` is the only transport. The independent fixture
sides declare (5 records) and observe (6 records) the same mock estate:

| Identity | Declared | Observed | Outcome |
|---|---|---|---|
| `cluster:aelionix-prod:payments:payment-gateway` | ✓ | ✓ | MATCH |
| `cluster:aelionix-staging:payments:payment-gateway` | ✓ | ✓ | MATCH |
| `cluster:aelionix-prod:marketing:marketing-site` | ✓ | ✓ | DISCREPANCY (replicas 3 vs 5) |
| `cluster:aelionix-prod:payments-prod:payment-gateway` | — | ✓ | UNKNOWN (runtime-only) |
| `cloud:aws:acct-112233445566:us-east-1:payments-database` | ✓ | ✓ | CONTRADICTION |
| `image:registry-aelionix-io:payments-payment-gateway` | ✓ | ✓ | MATCH |

Any unmodeled target (`missing-ns/missing-app`) produces a handled error
document — `error.kind == "no_fixture_records"` — which the engine surfaces as
a `SourceRuntimeExecutionError` (never an empty "clean" result).

## Correlation Semantics

- **Canonical identity pairing** — `scope_kind:scope:name`, an opaque string,
  so the same service name in a different scope (prod vs staging) never
  matches. Records that differ only in scope surface `NOT_COMPARABLE`.
- **Deterministic rule vocabulary** — `sr_exact` (normalized value equality),
  `sr_set` (order-independent set equality), `sr_digest` (immutable image
  digest), `sr_presence` (presence-only declared-vs-observed), and
  `sr_contradiction` (both sides present and mutually exclusive). Property maps
  per capability choose which rule applies to which property.
- **Contradiction-sensitive properties** — `backup_enabled`,
  `publicly_accessible`, `tls_enabled`, `readiness`, `service_type` route to
  `sr_contradiction`; e.g. the cloud database declares `backup_enabled=true`
  while runtime observes `false` → `CONTRADICTION` (both sides preserved). A
  plain value mismatch (`version` 16 vs 15) is a `DISCREPANCY`. A
  `CONTRADICTION` outranks any `DISCREPANCY` in the outcome aggregate.
- **Confidence policy** — `correlation_confidence()` returns the weaker of the
  source and runtime confidence scores (LOW+HIGH → LOW, HIGH+HIGH → HIGH).
  Dedup reuses the identical evidence rows on a re-run and can never inflate a
  confidence.

## Evidence Integrity

Every correlated outcome writes **three** evidence rows (idempotently on
re-run):

1. `SOURCE_ANALYSIS` (OBSERVED) — the declared side.
2. `OBSERVATION` (OBSERVED) — the runtime side.
3. `VALIDATION_RESULT` (INFERRED) — the correlation outcome, with
   `DERIVED_FROM` links to both the source and runtime rows.

Source/runtime evidence is **never mutated** by correlation; the derived row is
append-only. A repeated run of the same scenario produces the byte-identical
evidence ids (dedup by content), and a second mission is fully isolated (its
own evidence and World Model rows, counted independently).

## World Model Semantics

Correlated services materialize as `SOURCE_COMPONENT` entities with a fixed,
deterministic mapping:

- Main entity (canonical key `source_component||<identity>`) with a
  `correlation_result` assertion (`match` / `discrepancy` / `contradiction` /
  `unknown`).
- `:source` and `:runtime` sibling entities on the same canonical key.
- Edges: main `--DECLARED_AS--> :source`, main `--OBSERVED_AS--> :runtime`,
  and between the siblings `--CORRESPONDS_TO-->` (agreement) or
  `--DIFFERS_FROM-->` (disagreement).

**No attack-graph relationship types are ever materialized.** Provenance is
preserved: entities, relationships, and assertions carry their evidence links
and every evidence row links to its run's source and runtime evidence via
`DERIVED_FROM`. Re-running corroborates the same entities/edges
(`world_entity_corroborated`) instead of duplicating them.

## Redaction

Credential-like keys (`access_key`, `access_key_id`, `api_key`, `api_secret`,
`authorization`, `basic_auth_password`, `bearer_token`, `client_secret`,
`connection_string`, `credentials`, `oauth2_token`, `oidc_id_token`, `passwd`,
`password`, `private_key`, `public_key_material`, `secret`, `secret_access_key`,
`secret_key`, `token`, plus token-level matches) are force-replaced with the
literal `REDACTED` marker — never a hash, so redaction is unambiguous.
Non-secret sibling keys are preserved so the comparison keeps its structure.
`redact_source_runtime_raw()` (JSON re-serialization) and
`redact_source_runtime_document()` (recursive) run at the redaction boundary;
`credential_value_redacted()` is re-exported from the network layer. Tests
assert no plaintext credential-like value ever appears in raw output, evidence
rows, or world-model assertions.