# Business Logic

## Architecture

The Business Logic & Attack-Path Capability Foundation mirrors the `auth/`
architecture: a typed engine, typed capabilities, a deterministic mock-only
transport, normalization adapters, evidence persistence, and World Model
materialization — with **no free-form code execution, no credential use, and
no autonomous identity discovery.**

- **`blackforge/business_logic/engine.py`** (`BusinessLogicEngine`) — guards
  and orchestrates the full pipeline: request validation → scope/authorization
  → test-identity enforcement → fail-closed replay pre-check → mock transport →
  normalization → evidence persistence → World Model materialization →
  best-effort memory link. `METHOD_TO_CAPABILITY` maps tool methods to
  capability IDs; `_ERROR_KIND_TO_STATUS` maps transport error kinds to
  `BusinessLogicStatus`.
- **`blackforge/business_logic/capabilities.py`** — eleven typed
  `BusinessLogicCapability` instances, each bound to a transport method,
  a normalization adapter, and capability metadata. `build_business_logic_capabilities()`
  builds all eleven; `build_business_logic_meta()` builds their metadata.
- **`blackforge/business_logic/transport.py`** (`MockBusinessLogicTransport`) —
  deterministic, mock-only workflow/rule/role transport. Known demo hosts use a
  fixed dataset; unknown hosts yield a stable hash-derived dataset. Never
  touches the network, never executes code, never guesses identities.
- **`blackforge/business_logic/normalization.py`** — eleven
  `BusinessToolAdapter` subclasses that parse mock raw output into typed
  observation models. `adapter_for_tool()` routes each transport method to its
  adapter.
- **`blackforge/business_logic/evidence.py`** — `artifact_evidence()` and
  `observation_evidence()` construct evidence records; `observation_confidence()`
  implements the confidence policy; `evidence_dedup_key_for()` and
  `existing_evidence_id()` enable idempotent reruns.
- **`blackforge/business_logic/materializer.py`** (`BusinessWorldMaterializer`) —
  maps typed observations into World Model records: WORKFLOW + APPLICATION,
  BUSINESS_STATE, BUSINESS_ACTION with **OPERATES_ON**, **TRANSITIONS_TO** edges,
  RESOURCE --BELONGS_TO--> IDENTITY ownership, and the ROLE --HAS_PERMISSION-->
  PERMISSION --APPLIES_TO--> RESOURCE boundary. **No attack-graph relationship
  types (e.g. EXPLOITS / CAN_COMPROMISE) are ever materialized.**
- **`blackforge/business_logic/redaction.py`** — credential-like keys are
  force-redacted to the literal `REDACTED` marker. Re-exports
  `blackforge.webapi.redaction` helpers (`redact_secret`, `redact_document`,
  `redact_headers`).
- **`blackforge/business_logic/models.py`** — `BusinessLogicMode`,
  `BusinessLogicStatus`, ten typed observation models discriminated by `"kind"`,
  `BusinessLogicRequest`, `BusinessLogicResult`, replay/classification enums
  (`TransitionResult`, `ReplaySafetyClass`, `HypothesisOutcome`,
  `ValidationResult`).
- **`blackforge/core/errors.py`** — `BusinessLogicError`,
  `BusinessLogicExecutionError`, `BusinessLogicTimeoutError`.

## Capabilities

| ID | Name | Mode | Risk | Produces |
|---|---|---|---|---|
| `business_logic.workflow_discovery` | Workflow Discovery | PASSIVE | LOW | WORKFLOW |
| `business_logic.workflow_modeling` | Workflow Modeling | PASSIVE | LOW | STATE |
| `business_logic.state_transition_analysis` | State-Transition Analysis | PASSIVE | LOW | STATE_TRANSITION |
| `business_logic.business_rule_analysis` | Business-Rule Analysis | PASSIVE | LOW | BUSINESS_RULE |
| `business_logic.ownership_analysis` | Ownership Analysis | PASSIVE | LOW | OWNERSHIP |
| `business_logic.role_boundary_analysis` | Role-Boundary Analysis | PASSIVE | LOW | ROLE_BOUNDARY |
| `business_logic.workflow_consistency_analysis` | Workflow-Consistency Analysis | PASSIVE | LOW | WORKFLOW_CONSISTENCY |
| `business_logic.controlled_workflow_replay` | Controlled Workflow Replay | ACTIVE | MEDIUM | WORKFLOW_REPLAY |
| `business_logic.business_logic_hypothesis` | Business-Logic Hypothesis | PASSIVE | MEDIUM | BUSINESS_LOGIC_HYPOTHESIS |
| `business_logic.business_logic_validation` | Business-Logic Validation | ACTIVE | MEDIUM | BUSINESS_LOGIC_VALIDATION |
| `business_logic.workflow_evidence_collection` | Workflow Evidence Collection | PASSIVE | MEDIUM | WORKFLOW (event evidence) |

Registry counts: defaults-only → 1, recon → 7, + webapi → 17, + auth → **28**,
+ business logic → **39**.

## Safety Model

Every capability runs the identical guarded pipeline:

1. **Scope** — the target must be inside `TargetScope.allowed_targets`;
   otherwise an `AuthorizationError` is raised **before** any transport work.
2. **Explicit-identity enforcement** — `ownership_analysis` /
   `role_boundary_analysis` and the controlled-replay/validation capabilities
   require `test_identities` from the request. The engine never guesses
   identities: no identities → `BusinessLogicExecutionError`; an identity
   outside the request's authorized test identities → denied ("not authorized").
3. **Fail-closed replay pre-check** — every action is classified by
   `ReplaySafetyClass`. Unknown actions and actions with an unknown or
   non-password/token-side-effect safety profile stop replay **before**
   transport (`fail_closed=False` rejects replay). The explicit action
   allow-list (`SUBMIT_ORDER`, `PROCESS_PAYMENT`, `SHIP_ORDER`, `CANCEL_ORDER`,
   `PUT_ORDER_ON_HOLD`) keeps every replayable step bounded.
4. **Deterministic mock transport** — paper-model replay only.
5. **Evidence elevation** — hypothesis observations persist as HYPOTHESIZED;
   only `business_logic_validation` elevates consensus evidence to VALIDATED.
   INVALIDATED / UNVERIFIABLE outcomes never produce VALIDATED evidence.
6. **World Model** — typed observations only; no attack-graph relationship
   types are materialized.

## Transport Abstraction

`MockBusinessLogicTransport` is the only transport. Known demo hosts use fixed
datasets (`shop.example.com` order workflow, `checkout.example.com`,
`web.example.com`, plus the error hosts `throttled`, `unreachable`, `slow`,
`malformed`, and `elsewhere.example.com`). Error records carry an `error` dict
with a `kind` field mapped by the engine to statuses:

- `rate_limited` → RATE_LIMITED
- `malformed`, `malformed_response` → MALFORMED_RESPONSE
- `connection_refused` → REQUEST_FAILED
- `timeout` → TIMEOUT
- anything else → REQUEST_FAILED

## Observation Models

All observations are discriminated unions keyed on `"kind"`:

- `WorkflowObservation` (kind=workflow) — url, host, workflow, application, state_names, action_names
- `StateObservation` (kind=state) — url, host, workflow, state, initial, terminal, allowed_roles
- `StateTransitionObservation` (kind=state_transition) — url, host, workflow, action, source_state, target_state, direct, prerequisite, resource, **anomalous**
- `BusinessRuleObservation` (kind=business_rule) — url, host, workflow, rule, description, enforcement (`enforced`/`broken`/`not_applicable`), observed
- `OwnershipObservation` (kind=ownership) — url, host, workflow, resource, owner, owner_type, **controlled**
- `RoleBoundaryObservation` (kind=role_boundary) — url, host, workflow, role, action, resource, allowed, expected, consistent
- `WorkflowConsistencyObservation` (kind=workflow_consistency) — url, host, workflow, invariant, status
- `WorkflowReplayObservation` (kind=workflow_replay) — url, host, workflow, action, source_state, target_state, result (`success`/`unexpected_transition`/`missing_prerequisite`/`terminal`/`repeated`/`unknown_action`/`malformed`), safety_class, sequence_length
- `BusinessLogicHypothesisObservation` (kind=business_logic_hypothesis) — url, host, workflow, hypothesis, outcome (`supported`/`refuted`/`inconclusive`)
- `BusinessLogicValidationObservation` (kind=business_logic_validation) — url, host, workflow, hypothesis, result (`validated`/`invalidated`/`unverifiable`), evidence_reference, replay_observations

The mock dataset demonstrates the whole flow end to end:

- `state_transition_analysis` observes the anomalous `created -> shipped` edge
  for `ship_order` (marked `anomalous`, never auto-classified).
- `business_rule_analysis` observes `only_paid_orders_ship` as **broken**.
- `workflow_consistency_analysis` records the same invariant as **violated**.
- `controlled_workflow_replay` replays `process_payment -> ship_order` with all
  steps SUCCESS and `bounded` safety.
- `business_logic_hypothesis` marks `cancel_after_payment` **supported** while
  `cancel_ambiguous_order` stays **inconclusive**; `business_logic_validation`
  elevates `cancel_after_payment` to **validated** (VALIDATED evidence).

## World Model Semantics

- WORKFLOW entities are named by workflow id and namespaced by host. Each new
  workflow REPORT supersedes the previous revision (canonical entity
  revisioning); the assertion ledger (rule / invariant / replay / hypothesis /
  validation prefixes) stays attached to the revision that produced it. Queries
  that need the full ledger aggregate across the active + superseded revisions.
- BUSINESS_STATE (initial/terminal flags), BUSINESS_ACTION (with OPERATES_ON
  edges to RESOURCE), and TRANSITIONS_TO edges capture the modeled lifecycle.
- RESOURCE --BELONGS_TO--> IDENTITY captures controlled ownership; ROLE
  --HAS_PERMISSION--> PERMISSION --APPLIES_TO--> RESOURCE captures the observed
  role boundary.
- Relation assertions carry statuses: HYPOTHESIZED, INFERRED, CORROBORATED, and
  VALIDATED (validation only). Evidence rows for every observation are linked
  to their run's artifact via DERIVED_FROM.

## Redaction

Credential-like keys (`credential_value`, `password`, `token`, `authorization`,
`cookie`, `secret`, `api_key`, `access_token`, `refresh_token`,
`client_secret`, `otp`, `credential`, ...) are force-replaced with the literal
`REDACTED` marker — never a hash, so redaction is unambiguous.
`redact_credential_fields()` (recursive) and `redact_nested_credential_values()`
(recursive value sweep) are available at the redaction boundary, and the auth/
webapi `redact_secret`/`redact_document`/`redact_headers` helpers are
re-exported. Tests assert no plaintext credential-like value ever appears in
raw output or persisted evidence.