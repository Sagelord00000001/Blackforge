# Blackforge Evidence System

The evidence subsystem gives Blackforge a truthful, auditable record of *what
is known* and *how it became known*. It is fully orthogonal to the memory
system: **memory is the persistent memory of an agent**, **evidence is the
authoritative, epistemically-scored record** that memory work refers back to.

The system is **stdlib-only** (SQLite + pydantic). No model weights or external
services are required. Offensive operations (scanning, exploitation, recon)
are explicitly **out of scope**; this module only records and reasons about
findings.

---

## 1. Guiding principles

1. **Evidence is authoritative.** Everything a future planning or analysis
   phase relies on must be traceable to a stored evidence record. Memory
   records only *reference* evidence (`evidence_ids`); they never replace it.
2. **Status is epistemic, lifecycle is administrative.** A record's status
   describes *how much belief it warrants*; its lifecycle describes *what is
   happening to the record* (still considered, superseded, invalidated,
   archived). The two never conflate.
3. **No fake authority.** Output from an LLM may *suggest* a hypothesis but
   can never alone make evidence `VALIDATED`. `VALIDATED` requires an explicit,
   authorized validation step.
4. **Nothing is silently rewritten.** Superseding or invalidating a record
   never deletes history or downgrades its status — it changes the lifecycle
   flag and appends a typed relationship.
5. **Contradiction is preserved.** Conflicting observations both stay
   recorded and are linked with a `CONTRADICTS` relationship. An operator/AI
   decides which survives as active; the losing side remains in the ledger.
6. **Deterministic dedup.** Identical evidence (same mission, target,
   capability, type and content) maps to the same ID. Distinct observations
   are never merged.
7. **SQL is parameterized.** Evidence and memory content are untrusted input;
   there is no string interpolation into SQL.

---

## 2. Domain model

| Model | Purpose |
|---|---|
| `Evidence` | The core record: mission, session, source capability, target, type, status, lifecycle, confidence, provenance, content, timestamps, version. |
| `EvidenceStatus` | Epistemic status: `OBSERVED`, `INFERRED`, `HYPOTHESIZED`, `VALIDATED`. |
| `EvidenceLifecycle` | Administrative lifecycle: `ACTIVE`, `SUPERSEDED`, `INVALIDATED`, `ARCHIVED`. |
| `Confidence` | `LOW` (0.3), `MEDIUM` (0.5), `HIGH` (0.8), `CONFIRMED` (0.95) with `to_score()` / `from_score()`. |
| `ConfidenceChange` | Audited entry: previous, new, reason, timestamp. Appended, never rewritten. |
| `EvidenceRelation` | Typed links: `SUPPORTS`, `CONTRADICTS`, `VALIDATES`, `CORROBORATES`, `CAUSES`, `DERIVES_FROM`, `SUPERSEDES`, `INSTANTIATES`. |
| `EvidenceLink` | A stored relationship (source, relation, target, reason, metadata). |
| `EvidenceType` | `OBSERVATION`, `INFERENCE`, `CLAIM`, `VALIDATION_RESULT`, `CONTRADICTION_RESULT`, `TOOL_RESULT`. |
| `Provenance` | How the record came to be: capability, provenance type, hashes, evidence/task references. |
| `EvidenceQuery` | Immutable filter for searches/counts (status, lifecycle, mission, session, capability, target, relation, timestamps, limit, offset). |
| `EvidenceStore` | Facade + policy enforcement (see §3). |
| `EvidenceMemoryBridge` | The controlled link between evidence and memory (see §6). |

### Status lifecycle

| Status | Meaning |
|---|---|
| `OBSERVED` | Direct raw observation from a capability (e.g. a scanner), recorded as-is. |
| `INFERRED` | Derived from other records (e.g. a port implies a service). |
| `HYPOTHESIZED` | A claim or guess that is not yet confirmed — **the entry point for LLM output**. |
| `VALIDATED` | Confirmed by an authorized validation workflow. |

Allowed transitions (handled by the transition table in `EvidenceStore`):

```
OBSERVED    -> {INFERRED, HYPOTHESIZED, VALIDATED}
INFERRED    -> {HYPOTHESIZED, VALIDATED}
HYPOTHESIZED-> {VALIDATED}
VALIDATED   -> {}            (terminal)
```

Same-status is a no-op; any move *into* `VALIDATED` requires
`via_validation=True`, which only `add_validation()` uses. Illegal moves raise
`EvidenceRuleError`. Downgrades are **rejected at the status level** — that is
what the lifecycle flags exist for.

---

## 3. `EvidenceStore` API

```python
from blackforge.evidence.store import EvidenceStore

store = EvidenceStore()                       # in-memory (default)
store = EvidenceStore(SQLiteEvidenceRepository("data/evidence.db"))
```

| Method | Behavior |
|---|---|
| `add(evidence, *, via_validation=False)` | Store with policy enforcement, dedup, ID assignment. Raises `EvidenceRuleError` when required capability/data missing or `VALIDATED` without `via_validation`. |
| `add_claim(...)` | LLM/analysis output → `HYPOTHESIZED` claim. |
| `add_validation(...)` | The only path to `VALIDATED`; records a `VALIDATES` link when `validates_id` is given. Rejects unknown `validates_id`. |
| `get(id)` / `get_by_mission(mission_id)` | Retrieve singleton / mission-scoped records. |
| `count(mission_id=None)` | Count rows (mission-scoped or total). |
| `transition_status(id, target)` | Validate and apply a legal epistemic transition. |
| `adjust_confidence(id, confidence, reason)` | Set confidence, appending a `ConfidenceChange`. |
| `get_confidence_history(id)` | Return the append-only confidence trail. |
| `add_relationship(src, relation, target, reason=None)` | Create a typed link; rejects self-links and unknown endpoints. |
| `get_relationships(id, relation=None, direction=BOTH)` | Retrieve incoming/outgoing/both links, optionally filtered by type. |
| `related_evidence(id, relation=None)` | The linked evidence objects themselves. |
| `supersede(id, cause_id)` / `archive(id)` / `invalidate(id, ...)` | Lifecycle operations; `SUPERSEDES` relationship recorded. |
| `contradict(id, other, supersede=False)` | Record both records active + `CONTRADICTS` link (or supersede variant). |
| `search(query)` / `count(query)` | Filtered retrieval. |
| `hypothesize_from_evidence(id, ...)` | Promote a stored record to a `HYPOTHESIZED` claim. |
| `get_by_dedup_key(key)` / `count_pending()` | Dedup / operational helpers. |
| `close()` | Close the underlying repository. |

### Dedup identity

Dedup key = SHA256 of:

```
mission_id | target | source_capability | evidence_type | canonical(content)
```

Timestamps are excluded. Consequences:

- identical evidence in the same mission → same ID (idempotent adds);
- identical payload in *different* missions → separate records;
- different `raw_data` → separate records.

### Scoping

`EvidenceQuery` supports `mission_id`, `session_id`, `source_capability`,
`target`, `status`, `lifecycle`, `confidence`, `relation`, and timestamp
ranges, with `limit`. Results are ordered newest-first.

---

## 4. Rules module

`blackforge/evidence/rules.py` centralizes the invariant checks used by the
store so policy is testable in one place:

- `validate_evidence_for_add` — capability/summary requirements;
- `validate_status_transition` — the transition table above;
- `validate_validation` — `VALIDATED` requires the workflow flag;
- `validate_relationship` — no self-links, both endpoints must exist.

---

## 5. Repositories

| Class | Backend |
|---|---|
| `InMemoryEvidenceRepository` | dict-backed, thread-safe. Used by default and in tests. |
| `SQLiteEvidenceRepository` | single shared connection, `WAL`, parameterized SQL, `transaction()` context manager guaranteeing atomic rollback on error. Supports `":memory:"`. |

Schema includes `evidence`, `relationships` and `confidence_history` tables in
one file, so evidence + relationships + confidence trail persist atomically.

---

## 6. Evidence ↔ Memory Bridge

`blackforge/evidence/bridge.py` connects the two subsystems without giving up
the authoritative-evidence principle.

| Method | Behavior |
|---|---|
| `materialize_memory(evidence_or_id, *, memory_type, key, content, meta)` | Persist a memory record that *references* the evidence (`evidence_ids`), inheriting status, confidence score, mission/session context and provenance. Returns `None` if the evidence is unknown. |
| `memory_for_evidence(value)` | Reverse lookup: which memory records cite this evidence. |
| `evidence_for_memory(record_or_id)` | Which authoritative evidence backs a memory record. |
| `create_evidence_and_memory(evidence, ...)` | Store evidence first (authoritative), then materialize memory; on memory failure, compensates so no orphan/partial link remains in-process. |

`map_memory_source` maps evidence epistemic state to a memory source tag
(`VALIDATED_EXPERIMENT`, `LLM_INFERENCE`, `CAPABILITY_EXECUTION`) — it can
only ever **downgrade** the implied authority, never upgrade it.

### Transaction boundary (important)

Evidence and memory live in **separate SQLite files**, so a cross-store atomic
transaction is **NOT claimed**. The guarantee provided is:

- evidence is written first and is authoritative;
- if the memory write fails, the just-created memory record is removed
  (compensation) and the exception propagates;
- no partially-linked state is left **inside the process**.

If a future phase requires atomicity *across* the two files, that is a
documented, deliberate extension point — do not assume it exists today.

---

## 7. Bootstrap & configuration

`blackforge.runtime.bootstrap` resolves the evidence backend from config/env:

| Env var | Values |
|---|---|
| `BLACKFORGE_EVIDENCE_BACKEND` | `in_memory` (default) or `sqlite` |
| `BLACKFORGE_EVIDENCE_DB_PATH` | SQLite file path (e.g. `./data/evidence.db`) |
| `BLACKFORGE_MEMORY_DB_PATH` | SQLite file path for the memory side (Phase 2) |

`BlackforgeApp.verify()` exposes `evidence_store_ready` and
`evidence_memory_link_ready`. With a SQLite configuration, bootstrap preserves
records across restarts; the in-memory default keeps legacy tests unchanged.

---

## 8. Dependency edges

- `blackforge.core.types` — `EvidenceID`, `RelationshipID`, `ProvenanceType`, `Confidence`
- `blackforge.core.errors` — `EvidenceRuleError`
- `blackforge.evidence.*` → `blackforge.memory.base` / `manager` (bridge only)
- No dependency on any LLM provider; the subsystem is fully stdlib.

---

## 9. What this module intentionally does NOT do

- Does **not** perform or plan offensive actions, scans, or recon.
- Does **not** auto-validate LLM output (no fake authority).
- Does **not** rewrite epistemic history (status downgrades are rejected).
- Does **not** delete contradicting records.
- Does **not** claim cross-file (evidence↔memory) atomicity.

---

## 10. Tests

`tests/test_evidence_phase3.py` covers both backends (parameterized) and
verifies every table in this document, including: transition legality, dedup
determinism, all eight relationship types, contradiction and supersede
semantics, confidence audit history independence, mission/session scoping,
bridge materialization + reverse lookups, compensation on failing memory, SQLite
transaction rollback, and full evidence+relationship+memory restart
persistence.