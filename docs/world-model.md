# Blackforge World Model Foundation (Phase 4)

The world model gives Blackforge a **mission-scoped, deterministic, evidence-backed
picture of the operational environment**: what entities exist, how they relate, and —
critically — **how we know**. It is a foundation layer: a typed fact store with
strict identity, direction rules, and provenance. It does **not** reason about attack
paths and never will in this form.

The system is **stdlib-only** (SQLite + pydantic). No model weights or external
services are required. Offensive semantics — `LEADS_TO`, `ENABLES`, `CAN_COMPROMISE`,
`EXPLOITS`, privilege-escalation paths — are deliberately **rejected** and belong to a
future Attack-Graph layer that is **out of scope** for Phase 4.

---

## 1. Guiding principles

1. **Deterministic identity.** Entities are identified by a canonical key scoped to
   `(mission_id, entity_type, namespace, normalized_name)`. Internal IDs are never the
   dedup basis; the same logical entity always maps to the same record. Names are
   normalized cautiously (URLs: scheme+hostname+port+path; hostnames/keys: lowercase,
   trailing dots removed) — distinct-but-similar names are **never** merged.
2. **Typed model.** 13 entity kinds and 14 relationship types. Every edge is typed and
   directional, with per-type direction rules (see §4). Symmetric types dedup
   order-insensitively; directed types keep direction.
3. **Evidence-backed authority.** `OBSERVED` / `VALIDATED` entities and relationships
   require evidence references at insertion time. A claim without evidence enters as
   `HYPOTHESIZED` at best — **no fake authority**.
4. **Two orthogonal axes.** `EvidenceStatus` (how we know: hypothesize → observe →
   validate) is separate from `WorldLifecycle` (what happens to the record: active,
   superseded, archived). Supersession preserves version history; nothing is deleted.
5. **Contradiction is preserved.** A weaker/HYPOTHESIZED claim that conflicts with the
   authoritative record is stored as an **assertion** bound to the entity — the record is
   never silently overwritten. Only an authoritative (OBSERVED/VALIDATED) observation
   supersedes the previous version.
6. **Confidence is monotone under corroboration.** Corroborating observations raise
   confidence to the maximum observed; repetition never lowers it and never
   auto-increases beyond what the evidence supports.
7. **Mission isolation.** Every read and write is mission-scoped. Identical names in
   different missions are distinct records; cross-mission edges are rejected.
8. **Bounded, deterministic queries.** Neighborhood queries are depth-bounded and
   ordered deterministically. There is no pathfinding.
9. **SQL is parameterized.** Entity/relationship/assertion content is untrusted input;
   there is no string interpolation of values into SQL.

---

## 2. Entity types

| Entity | Canonical name treatment |
|---|---|
| `ASSET` | hostname / key, normalized |
| `SERVICE` | name, normalized |
| `APPLICATION` | name, normalized |
| `ENDPOINT` | full URL: scheme + host + port + path (case-insensitive host, default ports dropped) |
| `IDENTITY` | name |
| `ROLE` | name |
| `TECHNOLOGY` | name (lowercased) |
| `NETWORK` | name (lowercased) |
| `CLOUD_RESOURCE` | name |
| `CONTAINER` | name |
| `SOURCE_COMPONENT` | name |
| `DATA_STORE` | name |
| `TRUST_RELATION` | name |

---

## 3. Relationship types and direction rules

All edges are typed and directional at the data layer. `add_relationship` checks that
both endpoints exist, are `ACTIVE`, and belong to the same mission.

| Relationship | Symmetric? | Example |
|---|---|---|
| `HOSTS` | directed | network hosts service |
| `EXPOSES` | directed | service exposes endpoint |
| `RUNS` | directed | host runs service |
| `DEPENDS_ON` | directed | app depends_on library |
| `CALLS` | directed | service calls api |
| `CONNECTS_TO` | **symmetric** | network ↔ network |
| `AUTHENTICATES_TO` | directed* | identity authenticates_to service |
| `AUTHORIZED_FOR` | directed* | role authorized_for action |
| `BELONGS_TO` | directed | user belongs_to role |
| `CONTAINS` | directed | container contains component |
| `USES` | directed | app uses data_store |
| `LOCATED_IN` | directed | resource located_in region |
| `TRUSTS` | directed | component trusts identity |
| `ASSOCIATED_WITH` | **symmetric** | technology ↔ technology |

\* reciprocity maps to the paired inverse type rather than a second same-type edge.

Directed edges `A→B` and `B→A` are distinct records. Symmetric edges dedup
order-insensitively (evidence references merge on corroboration).

### Rejected by design

Attack-graph semantics are **not** accepted by `RelationshipType`:

`LEADS_TO`, `ENABLES`, `EXPLOITS`, `CAN_COMPROMISE`, `PRIVILEGE_ESCALATION_PATH`.

---

## 4. Decision table

| Input epistemic status | Existing record matching identity | Action |
|---|---|---|
| `HYPOTHESIZED` / `INFERRED`, differing properties | `ACTIVE` authoritative | `CONTRADICTION_RECORDED` — claim stored as assertion; record untouched |
| `OBSERVED` / `VALIDATED`, changed properties | `ACTIVE` | `SUPERSEDED` — new version created, old marked `SUPERSEDED`, `supersedes` link preserved |
| any, **same** content | `ACTIVE` **or** `ARCHIVED` | `CORROBORATED` — evidence merged, confidence raised to max, never lowered |
| — | no existing record | identity conflict resolution against `ARCHIVED` (reactivation only for corroboration) |

Versioning: each supersession increments `version`; `get_entity` returns the latest
`ACTIVE`, while `find_entity` (top-level key lookup) resolves the most recent version.
History is always retrievable by ID with its original properties and lifecycle.

---

## 5. Evidence provenance

Evidence references (`EvidenceLinkRef`) attach to entities, relationships, assertions,
and materialized facts. Links are stored in dedicated tables and are queryable in both
directions:

* `evidence_for_entity(entity_id)` / `evidence_for_relationship(rel_id)` / ...
  list the evidence IDs behind a record.
* `entities_for_evidence(evidence_id)` / `relationships_for_evidence(evidence_id)`
  trace which records a given evidence record supports.

Corroboration **merges** evidence links — a deduped record keeps every reference that
was ever attached.

---

## 6. The materializer (no fake authority)

`WorldMaterializer` turns inbound facts (`EntityFact` / `RelationshipFact`) into world
model mutations with an **evidence-driven status floor**:

* entities with no known evidence → `HYPOTHESIZED` (can never become authoritative);
* otherwise the entity's status is the **highest** epistemic status among its linked
  evidence (`HYPOTHESIZED < INFERRED < OBSERVED < VALIDATED`);
* identical facts are deduped and corroborated.

The materializer never fabricates authority: an LLM suggestion, without stored
`OBSERVED`/`VALIDATED` evidence, stays `HYPOTHESIZED`.

---

## 7. Query layer

| Query | Purpose |
|---|---|
| `WorldQuery` | entities by mission (filter: type, session, namespace, status, lifecycle, name-contains), paginated |
| `RelationshipQuery` | relationships by mission (filter: rel type, endpoint, direction), paginated |
| `neighborhood(entity_id, direction, max_depth)` | bounded, deterministic, depth ≤ 2, ordered by ID — **no pathfinding** |
| `count_entities` / counters | lifecycle-aware counts (default includes superseded history; filter `ACTIVE` explicitly) |

All queries require a `mission_id`; `session_id` is an optional narrowing filter.
Results are ordered deterministically.

---

## 8. Storage

Two interchangeable backends behind `WorldRepository`:

* `InMemoryWorldRepository` — transactional in-memory store (tests, notebooks).
* `SQLiteWorldRepository` — persistent; `WAL`-capable, table `world_entities`,
  `world_relationships`, `world_assertions`, and three `*_evidence` link tables.

Both implement `transaction()` with commit/rollback. SQLite transactions are
**re-entrant** (`_tx_depth`), so nested `with store.transaction():` blocks commit once
at the outermost level and roll back atomically on failure. Every mutation is
append-only: updates version records rather than overwriting, and deletions are used
only for test cleanup.

---

## 9. Security

* **No secrets.** The module stores no credentials or keys; content is treated as
  untrusted data.
* **Parameterized SQL only.** Column names in `SET`/`WHERE` clauses come from fixed
  internal allowlists; all values are bound with `?` placeholders. `LIKE` patterns are
  parameter-bound.
* **No execution or network.** No `eval`/`exec`/`subprocess`/sockets anywhere in
  `blackforge.world_model`. `urllib.parse.urlparse` is used purely for URL
  normalization — never for network I/O.
* **Mission-scoped reads.** Cross-mission entity access is impossible by construction.

---

## 10. Relationship to other subsystems

* **Evidence (Phase 3):** the world model is *fed by* evidence; every authoritative
  fact references evidence IDs. It never creates evidence.
* **Memory (Phase 2):** memory stays the agent's internal episodic store; the world
  model is orthogonal and mission-persistent.
* **Bootstrap:** `bootstrap()` exposes the configured store as `app.world_model` and
  reports `world_model_ready` from `app.verify()`.
* **Future Attack Graph:** explicitly out of scope; offensive edge types are rejected
  at the enum layer so no downstream phase can inject them silently.

See `docs/colab-validation.md` (Phase 4 section) for the one-click validation notebook.