# Blackforge Persistent Memory (Phase 2)

The Phase 2 foundation gives Blackforge a reliable, structured, and
provenance-aware memory subsystem that survives process restarts. It provides
the storage layer that later phases (autonomous reasoning, attack-path
analysis) will query — **without** implementing those systems.

## Principles

- **SQLite only.** Persistent memory lives in a single SQLite file via the
  standard library. No Postgres, no Redis, no vector database, no new
  runtime dependencies.
- **Stored content is untrusted data.** All queries are parameterized SQL;
  content is treated as opaque JSON. Nothing is ever `eval`-ed or executed.
- **Evidence is referenced, never copied.** Memory holds typed
  `evidence_ids`; the canonical records stay in the `EvidenceStore`.
- **Deterministic semantics.** Deduplication and versioning are based on a
  content hash and a stable logical key, so identical writes are idempotent
  by construction.

## Architecture

Layered as a facade over a persistence repository:

```
MemoryManager            →  application-facing API + dedup/versioning logic
   └── MemoryRepository  →  persistence contract (transactions, logical lookup)
         ├── SQLiteMemoryRepository   → durable SQLite store
         └── InMemoryRepository       → tests / discardable runtime
```

All subsystems depend on the `MemoryBackend` interface, never on a concrete
store. `MemoryManager` *is* a `MemoryBackend`, so upstream wiring (`bootstrap`,
orchestrators) is unchanged in shape.

## Core modules

| Module | Contents |
|---|---|
| `blackforge/memory/base.py` | `MemoryType`, `MemoryLifecycle`, `MemoryRecord`, `MemoryQuery`, `MemoryBackend` |
| `blackforge/memory/provenance.py` | `MemorySource`, `MemoryProvenance` |
| `blackforge/memory/repository.py` | `MemoryRepository`, `SQLiteMemoryRepository`, `InMemoryRepository`, `compute_dedup_key`, `canonical_json`, `coerce_query` |
| `blackforge/memory/manager.py` | `MemoryManager` |
| `blackforge/memory/models.py` | Backward-compatible aliases (`SQLiteMemoryBackend`, `InMemoryBackend`) |

## MemoryRecord

A record carries more than content:

| Field | Meaning |
|---|---|
| `memory_type` | `working` \| `knowledge` \| `experience` \| `evidence` |
| `key` | Stable logical key for the record |
| `content` | Any JSON-serializable value |
| `status` | Shared `EvidenceStatus` (`observed`/`inferred`/`hypothesized`/`validated`) |
| `confidence` | Float in `[0, 1]` |
| `mission_id`, `session_id` | Typed IDs tying memory to missions/sessions |
| `source` | `MemorySource` enum (observation, capability_execution, user_provided, …) |
| `provenance` | `MemoryProvenance` — task/capability link, input/output hashes, recorded time |
| `evidence_ids` | `list[EvidenceID]` — references into the `EvidenceStore` |
| `lifecycle` | `working` \| `active` \| `archived` \| `expired` \| `superseded` |
| `version`, `supersedes` | Logical versioning metadata |
| `dedup_key` | sha256 of `type|key|canonical(content)` |
| `expires_at`, `created_at`, `updated_at` | Time fields |

## Deduplication & versioning

`MemoryManager.store(record)` applies three rules atomically (one transaction):

1. **Deduplication no-op.** If a record with the same `dedup_key` already
   exists, the existing ID is returned and nothing is written. Content hashes
   use canonical JSON, so structurally equal content (regardless of key order)
   dedups identically.
2. **Logical versioning.** When new content is written under an existing
   `(memory_type, key)`, the previous record is marked `SUPERSEDED` and the new
   record is written as `version = previous + 1` with a `supersedes` pointer —
   all within the same transaction.
3. **Fresh insert.** Otherwise the record is written as `version = 1`.

`MemoryManager.update(record_id, updates)` is always **in-place**: same ID, same
version, `dedup_key` and `updated_at` recomputed.

## Search

`search()` / `count()` accept either a legacy positional form
(`search(query=..., memory_type=..., tags=..., limit=...)`) or a structured
`MemoryQuery`:

```python
MemoryQuery(
    memory_type=MemoryType.KNOWLEDGE,
    mission_id=MissionID("mission_a"),
    session_id=SessionID("sess_a"),
    status=EvidenceStatus.VALIDATED,
    lifecycle=MemoryLifecycle.ACTIVE,
    source=MemorySource.TOOL_OUTPUT,
    confidence_min=0.7,
    tags=["web"],
    keyword="nginx",
    created_after=..., created_before=...,
    limit=50, offset=0,
)
```

SQLite converts filters to parameterized `WHERE` clauses; tag matching uses
JSON-array containment on the serialized tags column. `list()` returns newest
first with `limit`/`offset` paging.

## Transactions

The SQLite repository runs in autocommit mode with **explicit
`BEGIN IMMEDIATE`** transactions under a re-entrant lock. `transaction()` is a
context manager; any exception inside rolls back the whole unit. Reads and
writes are serialized through the same lock, so a single connection is safe
even with `check_same_thread=False` and multiple threads.

```python
with repo.transaction():
    repo.store(record_a)
    repo.store(record_b)   # if this raises, record_a is also rolled back
```

## Bootstrap integration

`BlackforgeApp` resolves memory through `_resolve_memory(config, backend)`:

- **Explicit backend** → wrapped in a `MemoryManager`.
- **`memory.backend = "sqlite"`** (default) → `SQLiteMemoryRepository(config.memory.db_path)`.
- **`memory.backend = "in_memory"`** → `InMemoryRepository()`.

```python
# ~/.env or environment
BLACKFORGE_MEMORY_BACKEND=sqlite
BLACKFORGE_MEMORY_DB_PATH=./data/memory.db
```

The bootstrap health check runs `memory.health_check()` (a lightweight
`SELECT 1` for SQLite), surfaced as `memory_ready` in `app.verify()`.

## Backward compatibility

Phase 0 code keeps working:

- `blackforge.memory.models.SQLiteMemoryBackend` / `InMemoryBackend` remain as
  subclasses of the new repositories.
- The legacy `MemoryBackend.store/retrieve/update/delete/search` signatures
  still function on both backends and `MemoryManager`.
- `bootstrap(memory_backend=...)` accepts Phase 0 backends; the manager wraps
  them transparently. (`app.memory` is now a `MemoryManager`; the injected
  backend is available as `app.memory.repository`.)

## Out of scope (future phases)

Reconnaissance, scanning, exploitation, attack graphs, autonomous planning,
multi-agent orchestration, vector/embedding search, fine-tuning, and
self-modification are explicitly out of scope here. Nothing in this module
performs or enables any of those actions; it only provides the storage
foundation for reasoning layers built later.

## Usage example

```python
from blackforge.memory.base import MemoryRecord, MemoryType
from blackforge.memory.manager import MemoryManager
from blackforge.memory.repository import SQLiteMemoryRepository
from blackforge.core.types import MissionID, EvidenceStatus

manager = MemoryManager(SQLiteMemoryRepository("./data/memory.db"))

record_id = manager.store(MemoryRecord(
    memory_type=MemoryType.KNOWLEDGE,
    key="host:example.com",
    content={"service": "nginx", "port": 443},
    status=EvidenceStatus.OBSERVED,
    confidence=0.9,
    mission_id=MissionID("mission_a"),
    tags=["web"],
))

loaded = manager.retrieve(record_id)
manager.close()
```