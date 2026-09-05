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
