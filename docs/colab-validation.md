# Phase 1 Colab Validation

## How to Open

Click the **Open in Colab** badge in the repository README, or manually open the notebook:

```
notebooks/blackforge_phase1_colab.ipynb
```

in Google Colab: https://colab.research.google.com

## What It Validates

The notebook performs a sequential, deterministic validation of the entire Phase 1 runtime:

| Stage | What it checks |
|---|---|
| Repository | Clones/updates repo, verifies commit history |
| Dependencies | Installs `blackforge[dev,llm]` (plus `hatchling` build backend) |
| Imports | All 24 Blackforge backend modules load cleanly |
| Tests | Full `pytest -q` suite (177 tests) |
| Bootstrap | `BlackforgeApp.healthy()` and `verify()` pass |
| Hardware | GPU/CPU detection via PyTorch + nvidia-smi |
| Real inference | HuggingFace model loads and generates output through provider abstraction |
| Structured output | JSON extraction, schema validation, parsed result |
| Tool-call flow | LLM → ToolCall → CapabilityRegistry → CapabilityResult → ChatContext |
| ModelRouter | All 6 TaskCategory routes + custom routing rules + health check |

## Expected Successful Output

The final cell prints:

```
============================================================
BLACKFORGE PHASE 1 VALIDATION
============================================================
Repository              PASS
Imports                 PASS
Automated tests         PASS
Bootstrap               PASS
Hardware                PASS
Real inference          PASS
Structured output       PASS
Tool-call flow          PASS
Model router            PASS
============================================================
OVERALL RESULT: PASS
============================================================
```

## What a Failed Test Means

- **Repository FAIL** — Git clone failed or repo structure changed
- **Imports FAIL** — A required module has a broken import (check `importlib` error)
- **Tests FAIL** — One or more pytest tests failed (check stderr above)
- **Bootstrap FAIL** — `BlackforgeApp` health check failed (config or LLM provider issue)
- **Hardware FAIL** — Should not happen (CPU fallback always works)
- **Real inference FAIL** — Model failed to load or generate output (memory, network, or transformers issue)
- **Structured output FAIL** — Model output could not be parsed as JSON matching the schema
- **Tool-call flow FAIL** — ToolCall normalization or CapabilityRegistry issue
- **Model router FAIL** — Routing rule or health check failure

## GPU Recommendations

The notebook auto-detects hardware and selects the model accordingly:

| Runtime | Model | Dtype | Notes |
|---|---|---|---|
| GPU (T4+) | Qwen/Qwen2.5-3B-Instruct | float16 | Default, works well |
| GPU (L4/A100) | Qwen/Qwen3-8B | float16 | Better quality (manual override) |
| No GPU (CPU) | Qwen/Qwen2.5-0.5B-Instruct | float32 | Auto-fallback, ~1 GB — fits free-tier RAM |

A 3B model in float32 (~6.7 GB) on a CPU-only runtime can OOM-kill the kernel; the notebook avoids this by picking the 0.5B model when no CUDA is detected.

## Important Notes

1. **First run downloads the model.** Qwen2.5-3B-Instruct is approximately 6 GB (GPU runtimes). CPU runtimes download Qwen2.5-0.5B-Instruct (~1 GB). Subsequent runs use the cached model.
2. **No offensive security actions.** The notebook runs a harmless validation prompt only.
3. **No secrets required.** The notebook uses local models only — no API keys needed.
4. **Rerunnable.** Safe to re-run on the same Colab instance. Cached model and installed packages are reused.
5. **CPU runtimes are slow but work.** Expect real inference to take several seconds on CPU vs sub-second on a T4.
6. **Avoid upgrading Colab's kernel packages.** The `colab` extra pulls in `ipython`/`jupyterlab`/`notebook`, which conflict with Google's pinned versions and can make the runtime unstable (stuck reconnects, random SIGKILL). If this happens, do **Runtime → Disconnect and delete runtime** and re-run from the top.

## Colab Execution Result

Executed on a free-tier **CPU** runtime (Python 3.13), September 2026:

```
============================================================
BLACKFORGE PHASE 1 VALIDATION
============================================================
Repository                PASS
Imports                   PASS
Automated tests           PASS
Bootstrap                 PASS
Hardware                  PASS
Real inference            PASS
Structured output         PASS
Tool-call flow            PASS
Model router              PASS
============================================================
OVERALL RESULT: PASS
============================================================
```

Real HuggingFace inference ran end-to-end on CPU with `Qwen/Qwen2.5-0.5B-Instruct` (float32), through the full provider abstraction chain.

## Known Fixes Applied During Validation

| Issue | Fix |
|---|---|
| Silent install failure (`--quiet \| tail -5` hid errors) | Install cell shows full `pip` output |
| `hatchling` not present before editable install | Explicit `pip install hatchling` first |
| Invalid PyPI classifier `Intended Audience :: Information Technology Industry` | Removed — broke metadata generation for editable installs |
| OOM kernel kill on CPU (3B float32) | Hardware-aware model selection: 0.5B on CPU, 3B float16 on GPU |
| `verify_inference()` missing `provider` key | Added `"provider": "huggingface"` to the diagnostics dict |

## Phase 2 Validation Notebook

`notebooks/blackforge_phase2_colab.ipynb` validates the Phase 2 persistent
memory foundation. It installs only `blackforge[dev]` (no torch/transformers,
so it is lightweight and OOM-free on CPU runtimes) and checks:

| Stage | What it checks |
|---|---|
| Import health | All memory/evidence/bootstrap modules load cleanly |
| Automated tests | Full `pytest -q` suite |
| Bootstrap | `app.healthy()` and `memory_ready` health check |
| Restart persistence | Write → close → reopen → retrieve on a fresh SQLite connection |
| Deduplication | Idempotent writes return the same ID, no duplicate rows |
| Logical versioning | Content change supersedes v1, creates v2 atomically |
| Structured search | Mission/session/status/lifecycle/source/confidence/tags/keyword filters |
| Transaction atomicity | Mid-transaction failure rolls back everything |
| Evidence integration | Memory references evidence by ID; hashes match the EvidenceStore |
| In-memory parity | `in_memory` backend behaves identically |

Expected final output:

```
============================================================
BLACKFORGE PHASE 2 VALIDATION (PERSISTENT MEMORY)
============================================================
Repository                   PASS
...
OVERALL RESULT: PASS
============================================================
```

See `docs/memory.md` for the full memory architecture.

## Phase 3 Validation Notebook

`notebooks/blackforge_phase3_colab.ipynb` validates the Phase 3
Evidence ↔ Memory Integration & Evidence Lifecycle subsystem. Like Phase 2 it
installs only `blackforge[dev]` (no torch/transformers), so it is lightweight
and OOM-free on CPU runtimes.

| Stage | What it checks |
|---|---|
| Import health | All evidence/memory/bootstrap modules load cleanly |
| Automated tests | Full `pytest -q` suite (evidence lifecycle + bridge included) |
| Bootstrap | `app.healthy()`, `evidence_store_ready`, `evidence_memory_link_ready` |
| No fake authority | LLM claim → `HYPOTHESIZED`; direct `VALIDATED` creation rejected; only `add_validation` reaches `VALIDATED` (+ `VALIDATES` link) |
| Status transitions | Legal moves applied, illegal downgrades raise, confidence changes audited and status-independent |
| Lifecycle | Supersede marks the old record without rewriting its status/history |
| Relationships | Typed links incl. `CORROBORATES` filter retrieval |
| Contradiction | Both records stay `ACTIVE`, linked by `CONTRADICTS`, nothing deleted |
| Dedup | Identical evidence same ID, distinct evidence separate IDs |
| Evidence ↔ memory | Materialize memory referencing evidence; reverse lookups both ways |
| Restart persistence | Evidence + relationships + linked memory survive close/reopen on fresh SQLite connections |
| Compensation boundary | Failing memory write leaves no dangling memory record (evidence remains authoritative) |

Expected final output:

```
============================================================
BLACKFORGE PHASE 3 VALIDATION (EVIDENCE <-> MEMORY INTEGRATION)
============================================================
Repository                             PASS
...
OVERALL RESULT: PASS
============================================================
```

See `docs/evidence.md` for the full evidence architecture.

> **Behavioral change vs Phase 2:** the Phase 2 notebook's Evidence Integration
> cell creates `VALIDATED` evidence directly. Phase 3 intentionally forbids
> that (no fake authority). The Phase 2 notebook is kept as-is for historical
> record; the Phase 3 notebook demonstrates the corrected workflow.

## Phase 4 Validation Notebook

`notebooks/blackforge_phase4_colab.ipynb` validates the Phase 4
**World Model Foundation** subsystem. Like Phase 2/3 it installs only
`blackforge[dev]` (no torch/transformers), so it is lightweight and OOM-free
on CPU runtimes.

| Stage | What it checks |
|---|---|
| Import health | All world model modules load cleanly |
| Automated tests | Full `pytest -q` suite (world model included) |
| Bootstrap | `app.healthy()` + new `world_model_ready` flag |
| Identity & dedup | Deterministic canonical keys; same identity corroborates to one record; similar names never merged; namespaces scope identity |
| No fake authority | `OBSERVED` without evidence rejected; materializer floors status at `HYPOTHESIZED`; only evidence raises it |
| Direction rules | Directed `A→B` ≠ `B→A`; symmetric `CONNECTS_TO` dedups order-insensitively; self-loops and cross-mission edges rejected |
| Provenance | Evidence linked to relationships/entities, merged on corroboration, queryable in both directions |
| Confidence | Corroboration raises to maximum, never lowers; repetition alone never increases |
| Contradiction | Weaker claim → assertion, authoritative record untouched; inferred disagreement never overwrites |
| Supersession | Authoritative change supersedes, version + `supersedes` + full history preserved |
| Mission/session isolation | Same identity in another mission is a distinct record; session context narrows reads |
| Neighborhood | Bounded, deterministic, depth ≤ 2 — no pathfinding |
| Restart persistence | Entities, relationships, assertions and evidence links survive close/reopen on fresh SQLite connections |
| Rule integrity | Rule failures leave no partial state; health probes are self-cleaning |

Expected final output:

```
PHASE 4 VALIDATION SUMMARY
============================================================
  [PASS] repository
  [PASS] phase4_modules
  ...
  [PASS] restart_persistence
============================================================
RESULT: 15 passed, 0 failed

PHASE 4 VALIDATION: OVERALL PASS
```

See `docs/world-model.md` for the full world model architecture.

> **Scope note:** the world model stores *what is known and how it is known*.
> Offensive edge types (`LEADS_TO`, `ENABLES`, `EXPLOITS`, `CAN_COMPROMISE`,
> privilege-escalation paths) are rejected at the enum layer. An Attack Graph
> layer is explicitly out of scope for Phase 4.
