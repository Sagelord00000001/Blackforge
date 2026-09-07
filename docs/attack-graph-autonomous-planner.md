# Attack Graph & Autonomous Planner

## Architecture

The Attack Graph & Autonomous Planner Foundation is the first layer of
Blackforge that *reasoning* — rather than evidence collection — stands on. It
derives a **descriptive attack graph** from the World Model and existing
evidence, classifies paths, computes evidence gaps, adds per-path hypotheses,
and plans an **authorized, budget-bounded assessment sequence** that closes the
highest-priority gaps. Everything the planner emits is a suggestion for a
future, separately-authorized assessment step — never an instruction to attack.

The Phase 14 module group (`blackforge/attack_graph/`) is a **self-contained
model + planner layer**. It introduces zero new capability IDs and performs no
transport; it consumes capabilities that already exist in the registry.

- **`blackforge/attack_graph/models.py`** — the graph vocabulary. `Graph
  state` (INFERRED / HYPOTHESIZED / VALIDATED / BLOCKED / CONTRADICTED /
  INSUFFICIENT_EVIDENCE) and `path state`
  (INFERRED_PATH / HYPOTHESIZED_PATH / VALIDATED_PATH /
  INSUFFICIENT_EVIDENCE) are **strictly weaker than the evidence they rest on**:
  a validated edge maps back to `INFERRED` evidence, never the reverse, so the
  graph can never overclaim. `GraphRelationship` enumerates six descriptors
  (`SERVES`, `EXPOSES`, `REQUIRES`, `POTENTIALLY_LEADS_TO`,
  `REQUIRES_VALIDATION`, `CORRELATED_WITH`) and **deliberately carries no
  offensive semantics** — `POTENTIALLY_LEADS_TO` and `REQUIRES_VALIDATION` are
  hypotheses a future assessment step may or may not confirm.
- **`blackforge/attack_graph/builder.py`** (`AttackGraphBuilder`) — derives the
  graph from World Model entities, relationships, and evidence artifacts.
  `build_derived_graph()` mirrors world entities into `ag_entity_mirror` nodes
  with provenance back to the canonical world entity, converts world `SERVES`
  edges into `EXPOSES` edges with state no stronger than the source evidence,
  lifts correlation `DIFFERS_FROM` relationships into `REQUIRES_VALIDATION`
  edges with a declared-vs-runtime prerequisite, and adds a count-bounded
  `POTENTIALLY_LEADS_TO` hypothesis edge per correlated pair. Derivation is
  **append-only and immutable**: an edge hypothesis can never be upgraded by a
  later derivation, and no `VALIDATED` graph record and no offensive predicate
  is ever produced.
- **`blackforge/attack_graph/query.py`** (`AttackGraphQuery`) — read side of
  the repository: `nodes_by_entity`, `edges_for_path`, `open_paths(max_depth,
  max_paths)`, `gaps_for_paths` (typed as `REQUIRES_VALIDATION` /
  `EXPOSURE_UNCONFIRMED` / `AUTH_MISSING_OR_WEAK`), `missing_prerequisites`
  (declared-vs-runtime, deduplicated), `evaluate(path)` (classify + missing
  prerequisites) and `classify_path(path)` which uses path state priority to
  ensure a hypothesis stays `HYPOTHESIZED_PATH` and is never upgraded.
- **`blackforge/attack_graph/planner.py`** (`AssessmentPlanner`) — consumes
  graph paths and the capability registry to emit a ranked, ordered plan:
  `_paths()` starts from the requested focus node and falls back to
  `open_paths()`; each gap selects registered capabilities (preferring the gap's
  evidence kind, else coverage capabilities), all in-scope against the mission
  `TargetScope`; a deterministic score sorts candidates; steps are
  budget-bounded by `ide_budget_hours` and `max_steps`. Plan statuses are
  first-class (`NO_ACTION_AVAILABLE` and `INSUFFICIENT_SCOPE` are legitimate,
  fail-closed outcomes, never empty "success").
- **`blackforge/attack_graph/actions.py`** — `CapabilityMeta` binds a
  registered capability's surface (target kind, evidence types produced,
  risk). `CandidateAction` turns a meta + a graph gap into an actionable,
  explainable plan step with `target`, `expected_evidence`, and `rationale`.
- **`blackforge/attack_graph/scoring.py`** — `assess(...)` produces a
  **deterministic, explainable priority score**, never a probability. Fixed
  weights over path depth, exposure ratio, IDE-saturation, focus alignment,
  contradiction pressure, corroboration, and derived confidence map to a
  LOW / MODERATE / ELEVATED / HIGH ladder; every factor is attributable.
- **`blackforge/attack_graph/repository.py`** +
  **`blackforge/attack_graph/sqlite_store.py`** — in-memory repository plus a
  SQLite store for graph and plan payloads. Node/edge/path structural state
  (ids, edges, states) survives round trips; the SQLite layer **cannot
  round-trip rich Python fields** (sets, enums, nested pydantic models) — those
  are reconstructed from `JSON`/normalized projection columns on load, so
  "save after derive, reopen, and you get structural state back" is the
  supported contract, not byte-for-byte equality.
- **`blackforge/attack_graph/validation.py`** — `validate_plan` is
  order-sensitive, rejects unordered or out-of-bounds steps, and enforces scope
  integrity on every stored plan.
- **`blackforge/attack_graph/priority.py`** — the 4-ID coverage-capability
  allowlist (`ag_custom_greeting`, `ag_backend_probe`, `ag_http_probe`,
  `ag_app_probe`) that the planner may match to a gap. It is a **deterministic
  mapping**, not a free-text interpreter: a capability can only fill a gap it
  declares it produces evidence for.

## Safety Model

The Attack Graph is a **descriptive, derived view**. It never executes anything,
calls no network, and invokes no capability on its own. Every path a planner
step is gated by the same authorization boundary that guards every other
Blackforge capability: Scope → Authorization → capability allowlist → mission
context. The planner fails closed: an empty registry returns
`NO_ACTION_AVAILABLE`; an out-of-scope target returns `INSUFFICIENT_SCOPE`;
an exhausted IDE budget returns `PLAN_CAPPED`. There is no generic command
execution, no `eval`, no subprocess, and no raw network socket surface anywhere
in `blackforge/attack_graph`.

Two invariants are enforced at the model level:

> **POTENTIAL PATH ≠ SUCCESSFUL ATTACK.** A graph path represents an
> evidence-supported or hypothesized security relationship. It does not by
> itself prove exploitability, successful exploitation, compromise, or
> unauthorized access.

> **GRAPH CONNECTIVITY ≠ EXPLOITABILITY.** Derived edges only reflect what the
> World Model and evidence support. A connected path through the graph is an
> ordering of *hypotheses to verify*, not a chain of demonstrated effects.

The required reading is therefore:

> "A graph path represents an evidence-supported or hypothesized security
> relationship. It does not by itself prove exploitability, successful
> exploitation, compromise, or unauthorized access."

## Graph Vocabulary & Semantics

The graph deliberately has **no offensive predicates** (no `LEADS_TO`,
`ENABLES`, `EXPLOITS`, or `CAN_COMPROMISE` in the derived graph — those remain
rejected at the World Model enum layer). The six `GraphRelationship` values are:

| Value | Meaning | Max state |
|---|---|---|
| `SERVES` | architectural relationship (source of exposure edges) | world |
| `EXPOSES` | an entity exposes another, derived from `SERVES` | `INFERRED` |
| `REQUIRES` | an edge lists a prerequisite whose status is not yet resolved | `INFERRED` |
| `POTENTIALLY_LEADS_TO` | a bounded hypothesis edge per correlated pair | `HYPOTHESIZED` |
| `REQUIRES_VALIDATION` | a declared-vs-runtime discrepancy flagged for validation | `HYPOTHESIZED` |
| `CORRELATED_WITH` | supporting relationship surfaced by correlation evidence | `INFERRED` |

## Path Classification & Gap Semantics

`classify_path` uses **path-state priority** so downstream reasoning never
inflates confidence: a hypothesis stays `HYPOTHESIZED_PATH`, a
`VALIDATED_PATH` requires validated supporting evidence, and the worst state
wins. `compute_gaps` produces one typed evidence gap per derived edge
(`REQUIRES_VALIDATION`, `EXPOSURE_UNCONFIRMED`, `AUTH_MISSING_OR_WEAK`);
`missing_prerequisites` surfaces declared-vs-runtime prerequisites deduplicated
across all edges of a path. `evaluate(path)` returns `PathOutcome` with the
classification and the surfaced missing prerequisites — the single call the
planner uses to decide what an authorized assessment should verify next.

## Assessment Scoring

`assess()` is a pure function of seven normalized factors; all inputs are
explicit so the output is fully explainable:

```
score = 0.15·depth  + 0.35·exposure  + 0.15·saturation
      + 0.15·focus  + 0.05·contradiction + 0.05·corroboration
      + 0.10·confidence
```

Levels: `LOW` < 0.25, `MODERATE` < 0.5, `ELEVATED` < 0.75, else `HIGH`. A
near-saturation environment zeroes the exposure contribution; a blocked path
can only produce derived, evidence-collection-agnostic edges.

## Planner & Bounds

Every planning request is schema-bounded and fails closed on bad input:
`ide_budget_hours` ∈ [0, 48], `max_steps` ∈ [1, 30], `max_candidates` ∈ [1, 20],
`max_graph_depth` ∈ [1, 6], `max_replans` ∈ [0, 10]. A request with an empty
capability allowlist ('none') yields `NO_ACTION_AVAILABLE`; a request with a
single step budget yields a one-step plan; and a saturated idle-IDE budget
returns `PLAN_CAPPED` with an explicit "idle IDE budget saturated" warning.
Replanning produces a new annotated plan against the same graph — evidence
gathering is never approximated by re-running the planner.

## Persistence

`sqlite_store` persists: graph nodes, edges, graph paths, prerequisites and
their states in normalized columns; and full plan payloads (steps → candidate
actions → expected evidence) as structured JSON. Re-saving the same graph uses
`INSERT OR IGNORE` (no growth), superseded nodes keep history (1 active + 1
archived), and loading from a fresh connection on the same SQLite file restores
the structural state. Rich Python fields (sets, enums, nested models) are
reconstructed from projections on load — the round-trip contract is
"structural state survives", not byte-for-byte equality.

## Bootstrap Integration

`BlackforgeApp.bootstrap()` now wires `attack_graph_builder`,
`attack_graph_repository`, and `attack_graph_planner` into the application, and
`verify()` reports two new readiness keys — `attack_graph_ready` and
`planner_ready` — alongside the existing ones (105 capabilities registered).
No new capability IDs were added; the planner is a consumer of already-existing,
separately-authorized capabilities.