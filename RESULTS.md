# ReGenBench — Campaign Results

Fresh run, 2026-08-31, on this host (docker), seeded from the **100 real
HuggingFace checkpoints** (5 clusters × 20; no synthetic models). All figures
are measured from `data/regenbench_campaign.db` (and `data/shelf_life.db` for
H3); the per-scanner/bootstrap details are in the regenerable
`docs/evaluation-report.md`.

| Run | Type | Replicate | Generated | Valid | Confirmed Bypasses | Bypass Yield |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| guided-r1 | guided (oracle_aware, adaptive) | 1 | 500 | 473 | **223** | **47.1%** |
| unguided-r1 | unguided (current, random) | 1 | 473 | 401 | **74** | **18.5%** |

**ShadowPickle baseline** (H1 denominator, `data/regenbench_shadowpickle.db`):
80 candidates, 80 valid, 20 confirmed bypasses → **25.0%**.

**Search efficiency**: guided 47.1% vs unguided 18.5% — Fisher's exact p = 0.0,
z = 8.92. Queries-to-first-bypass: guided [4], unguided [3] (both modes find
bypasses quickly because the `pypi_injected` + `splice` vector is highly
effective).

## Per-scanner evasion (874 valid pickle candidates)

Confirmed bypasses are measured against the **format-native pickle panel**:
PickleScan + ModelScan. Fickling is excluded from the torch (`.pt`) panel — it
is a raw-pickle AST analyzer that cannot parse torch-zip checkpoints natively
(`fickling --trace` on a `.pt` → `No pickle files detected`), i.e. a
format-coverage gap, not an evasion. It still detects malicious raw `.pkl`.

| Scanner | Evaded | Evasion Rate | 95% Bootstrap CI |
| :--- | :---: | :---: | :--- |
| PickleScan | 297 | 34.0% | [30.9%, 37.1%] |
| ModelScan | 450 | 51.5% | [48.2%, 54.8%] |
| Fickling | N/A (torch format gap) | — | — |

## Cross-Format Summary (unified DB)

One database (`data/regenbench_campaign.db`), two surfaces — pickle candidates
(`format='pt'`) and GGUF (`format='gguf'`, inserted by
`scripts/insert_gguf_into_campaign.py`). Confirmed bypasses use the
format-native panel per format (`pt` → PickleScan+ModelScan; `gguf` →
ggufref+modelscan):

| Format | Format-native panel | Candidates | Valid | Confirmed bypasses | Yield |
|---|---|---:|---:|---:|---:|
| `pt` | PickleScan + ModelScan | 973 | 874 | 297 | 34.0% |
| `gguf` | ggufref + modelscan | 32 | 32 | 0 | 0.0% |

## Per-family bypasses (valid candidates)

293/297 confirmed bypasses are `pypi_injected` (via `splice`); the remaining 4
are `gadget` (`inject_payload_into_torch`). This concentration is a
scanner-bias finding, not a generator failure — see `PRESENTATION.md` §3.

| Run | Family | Valid | Bypasses |
| :--- | :--- | :---: | :---: |
| guided-r1 | pypi_injected | 223 | 223 |
| guided-r1 | external | 76 | 0 |
| guided-r1 | overwritten | 72 | 0 |
| guided-r1 | indirect_chain | 54 | 0 |
| guided-r1 | inject_payload_into_torch | 48 | 0 |
| unguided-r1 | pypi_injected | 93 | 70 |
| unguided-r1 | overwritten | 96 | 0 |
| unguided-r1 | external | 94 | 0 |
| unguided-r1 | indirect_chain | 75 | 0 |
| unguided-r1 | inject_payload_into_torch | 43 | 4 |

## Coverage growth

| Run | Opcode coverage (start → end) | Callable coverage (end) | Family entropy (end) |
| :--- | :---: | :---: | :---: |
| guided-r1 | 50.0% → 50.0% | 100.0% | 1.43 |
| unguided-r1 | 51.7% → 53.4% | 100.0% | 1.57 |

## Round-by-round detail

Per-round `valid` (ExecutionOracle-confirmed) and `bypasses` (confirmed
bypasses) per run. Guided generates 20/round and plateaus at ~9 bypasses/round
from round 8 — the family quota caps `pypi_injected` at 40% of a round.
Unguided generates 18–20/round and varies between 1 and 6 bypasses/round.

| Rounds | guided-r1 valid | guided-r1 bypasses | unguided-r1 valid | unguided-r1 bypasses |
| :---: | :---: | :---: | :---: | :---: |
| 1–8 | 17–20 | 7–9 | 14–19 | 1–4 |
| 9–16 | 18–20 | 9 | 15–19 | 1–6 |
| 17–24 | 19–20 | 9 | 15–18 | 1–5 |
| 25 | 20 | 9 | — | — |
| **Total** | **473** | **223** | **401** | **74** |

Guided's per-round bypasses are stable and high from round 1 (quota-driven,
not convergence-limited); unguided's are noisy and low.

## Hypotheses

| H | Verdict | Evidence |
| :--- | :--- | :--- |
| **H1** | **Supported** | Fuzzing 34.0% vs ShadowPickle baseline 25.0% confirmed-bypass rate (relative improvement 36%; non-overlapping bootstrap CIs on PickleScan) |
| **H2** | **Valid negative** | Uncorroborated == confirmed (297 == 297): the static panel already detects all non-executing candidates, so the dual-oracle adds no precision — dynamic validation confirms execution, not filters false evasions |
| **H3** | **Supported** | 99.3–99.7% retention of 297 bypasses across the format-native historical versions (picklescan 1.0.4/1.0.3, modelscan 0.8.7/0.8.6; 2 pypi_injected/splice bypasses caught by old rules — stagnation, not patch evasion) |

## Shelf-life retention (H3, `data/shelf_life.db`)

| Scanner Version | Total | Retained | Retention |
| :--- | :---: | :---: | :---: |
| fickling 0.1.11 | N/A (torch format gap) | — | — |
| fickling 0.1.10 | N/A (torch format gap) | — | — |
| modelscan 0.8.7 | 300 | 299 | 99.7% |
| modelscan 0.8.6 | 300 | 299 | 99.7% |
| picklescan 1.0.4 | 300 | 298 | 99.3% |
| picklescan 1.0.3 | 300 | 298 | 99.3% |

Retention is reported for the format-native pickle panel (picklescan +
modelscan). Fickling's historical 300/300 rows are omitted: it cannot parse
torch-zip, so its rescans are vacuous (a format gap, not patch resilience).

## Benign false positives (100 real checkpoints)

| Scanner | FP Detections / 100 | FP Rate |
| :--- | :---: | :---: |
| PickleScan | 0 | 0.0% |
| ModelScan | 0 | 0.0% |
| Fickling | N/A (torch format gap) | — |
| DynaHug (calibrated, supplementary) | 94 | 94.0% |

Ground truth is provenance-based (verified public HF repos). The ExecutionOracle
(trigger polling / StraceOracle) is 0% FP and gates bypass confirmation.

## Monitor & throughput

- **LoadTimeMonitor**: detection rate 100.0% (297 bypasses), false-alarm rate 0.0% (5 benign).
- **Pre-filter throughput** (`scripts/benchmark_perf.py`): 1.69× speedup (11.2s vs 18.9s over 10 files).

## GGUF attack surface (format-complexity demo)

A **format-complexity demo**, not a scanner-robustness claim: it generates 7
GGUF attack families and measures how the `ggufref` reference oracle and the
static panel react. All GGUF scanning goes through a single shared
`pipeline.scanners.run_scan(gguf_ref=True)` path, so
`scripts/run_task3_demo.py --backend docker` and the GGUF section of
`scripts/demo_task3.py --backend docker` emit byte-identical verdicts.

### Full detection matrix (all 6 panel scanners)

`BEN` = benign, `MAL` = malicious, `ERR` = error / no verdict. Rows shown are
the 7 attack files + synthetic benign + the 24-file real corpus (all real
files behave like the examples below).

| artifact | modelscan | picklescan | fickling | modeltracer | dynahug | ggufref |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| gguf_ssti_chat_template.gguf | BEN | BEN | MAL | ERR | ERR | **MAL** |
| gguf_malformed_nkv_overflow.gguf | BEN | BEN | MAL | ERR | ERR | **MAL** |
| gguf_malformed_ntensors_overflow.gguf | BEN | BEN | MAL | ERR | ERR | **MAL** |
| gguf_malformed_string_overflow.gguf | BEN | BEN | MAL | ERR | ERR | **MAL** |
| gguf_malformed_path_traversal.gguf | BEN | BEN | MAL | ERR | ERR | **MAL** |
| gguf_malformed_negative_dims.gguf | BEN | BEN | MAL | ERR | ERR | **MAL** |
| gguf_malformed_version_zero.gguf | BEN | BEN | MAL | ERR | ERR | **MAL** |
| benign-synth.gguf | BEN | BEN | MAL | ERR | ERR | BEN |
| ggml-vocab-aquila.gguf (24 real files) | BEN | BEN | MAL | ERR | ERR | BEN |

### Detection rates (measured)

Verdict buckets are `malicious` / `benign` / `error`; an `error` is an infra
failure, never a miss — if any `.gguf`-capable scanner errors, the run aborts
instead of reporting a misleading rate.

| scanner | malicious | benign | error | attack count | rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ggufref** | 7 | 0 | 0 | 7 | 100% |
| **modelscan** | 0 | 7 | 0 | 7 | 0% |

`ggufref` and `modelscan` are the only scanners the pipeline routes to
`.gguf` (`SCANNERS` exts). `picklescan`/`fickling`/`modeltracer`/`dynahug`
are a documented **format-coverage gap**, not a measured rate.

### Per-family findings (ggufref)

| family | ggufref findings |
| :--- | :--- |
| `ssti_chat_template` | `ssti:__class__`, `ssti:__subclasses__`, `ssti:__builtins__`, `ssti:__import__`, `ssti:popen`, `ssti:_module`, **`ssti:triggered`** (template render executed `os.popen("touch …")`) |
| `nkv_overflow` | `nkv-overflow`, `reference-error:IndexError: index 0 is out of bounds…` |
| `ntensors_overflow` | `ntensors-overflow`, `reference-error:IndexError: index 0 is out of bounds…` |
| `string_overflow` | `string-overflow`, `reference-error:IndexError: index 0 is out of bounds…` |
| `path_traversal` | `path-traversal`, `reference-error:ValueError: cannot reshape array of size 0…` |
| `negative_dims` | `negative-dims`, `reference-error:ValueError: Maximum allowed dimension exceeded` |
| `version_zero` | `version-zero`, `reference-error:ValueError: Sorry, file appears to be version 0…` |

Every malformed family is both **attributed by the heuristic classifier** and
**rejected by the ggml-org reference reader**; the SSTI family loads fine and
is caught by the render-driven execution signal (`triggered`).

### Real-corpus false positives (measured)

`scripts/crawl_gguf.py` fetched **24 real benign GGUFs** into
`data/gguf_benign_corpus/` (5 TinyLlama `stories*` + 19 llama.cpp
`ggml-vocab-*` models, ~127 MB). Measured over all 24:

| scanner | benign flagged | benign | error | benign scanned | FP rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ggufref** | 0 | 24 | 0 | 24 | 0% |
| **modelscan** | 0 | 24 | 0 | 24 | 0% |

Notably `stories260K-infill.gguf` triggers a **reference-reader bug**
(`reference-error:KeyError: 'Duplicate GGUF.version already in list at offset 69'`)
yet still verdicts `benign` — the oracle does not flag reader rejection
without an attack signature, which is exactly what keeps FP=0 on real
vocabulary files that contain `..` substrings, duplicate KVs, etc.

### SSTI render isolation

The `ssti_chat_template` check renders untrusted Jinja2 inside an isolated,
**network-disabled** container (`--network none`) with a container-scoped
`--tmpfs /tmp` and no host filesystem access; the loader observes the trigger
by polling inside the container. See `IMPLEMENTATION.md` §8.

### Reproduction

```sh
python3 scripts/crawl_gguf.py                            # -> data/gguf_benign_corpus/ (24 real GGUFs)
python3 scripts/run_task3_demo.py --backend docker       # -> docs/task3-demo.md (matrix + FP)
python3 scripts/demo_task3.py --backend docker           # -> docs/demo-report.md (GGUF section #5)
```

## How to reproduce

1. Crawl + link the 100-model corpus, validate/split the oracle, and
   recalibrate (commands in [`IMPLEMENTATION.md`](IMPLEMENTATION.md) §9).
2. Run `scripts/run_shadowpickle_baseline.py`, then the guided and unguided
   `scripts/run_fuzzing_campaign.py` commands in [`README.md`](README.md).
3. `python3 scripts/generate_evaluation_report.py` regenerates
   `docs/evaluation-report.md`; `python3 scripts/save_results.py` snapshots
   `results/<timestamp>/`. The interactive version of every step is in
   [`notebooks/`](notebooks/README.md).