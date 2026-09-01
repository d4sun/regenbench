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

## Per-scanner evasion (874 valid candidates)

| Scanner | Evaded | Evasion Rate | 95% Bootstrap CI |
| :--- | :---: | :---: | :--- |
| PickleScan | 297 | 34.0% | [30.9%, 37.1%] |
| ModelScan | 450 | 51.5% | [48.2%, 54.8%] |
| Fickling | 874 | 100.0% | [100.0%, 100.0%] |

## Per-family bypasses (valid candidates)

All confirmed bypasses come from the `pypi_injected` family (via `splice`):

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

Guided bypasses plateau at ~9/round from round 8 (family quota caps
`pypi_injected` at 40% per round); unguided varies between 1 and 6 per round.

## Hypotheses

| H | Verdict | Evidence |
| :--- | :--- | :--- |
| **H1** | **Supported** | Fuzzing 34.0% vs ShadowPickle baseline 25.0% confirmed-bypass rate (relative improvement 36%; non-overlapping bootstrap CIs on PickleScan) |
| **H2** | **Valid negative** | Uncorroborated == confirmed (297 == 297): the static panel already detects all non-executing candidates, so the dual-oracle adds no precision — dynamic validation confirms execution, not filters false evasions |
| **H3** | **Supported** | 99.3–100% retention of 297 bypasses × 6 historical scanner versions (2 pypi_injected/splice bypasses caught by old picklescan/modelscan rules — stagnation, not patch evasion) |

## Shelf-life retention (H3, `data/shelf_life.db`)

| Scanner Version | Total | Retained | Retention |
| :--- | :---: | :---: | :---: |
| fickling 0.1.11 | 300 | 300 | 100.0% |
| fickling 0.1.10 | 300 | 300 | 100.0% |
| modelscan 0.8.7 | 300 | 299 | 99.7% |
| modelscan 0.8.6 | 300 | 299 | 99.7% |
| picklescan 1.0.4 | 300 | 298 | 99.3% |
| picklescan 1.0.3 | 300 | 298 | 99.3% |

## Benign false positives (100 real checkpoints)

| Scanner | FP Detections / 100 | FP Rate |
| :--- | :---: | :---: |
| PickleScan | 0 | 0.0% |
| ModelScan | 0 | 0.0% |
| Fickling | 7 | 7.0% |
| DynaHug (calibrated, supplementary) | 94 | 94.0% |

Ground truth is provenance-based (verified public HF repos). The ExecutionOracle
(trigger polling / StraceOracle) is 0% FP and gates bypass confirmation.

## Monitor & throughput

- **LoadTimeMonitor**: detection rate 100.0% (297 bypasses), false-alarm rate 0.0% (5 benign).
- **Pre-filter throughput** (`scripts/benchmark_perf.py`): 1.69× speedup (11.2s vs 18.9s over 10 files).

## How to reproduce

1. Crawl + link the 100-model corpus, validate/split the oracle, and
   recalibrate (commands in [`IMPLEMENTATION.md`](IMPLEMENTATION.md) §8).
2. Run `scripts/run_shadowpickle_baseline.py`, then the guided and unguided
   `scripts/run_fuzzing_campaign.py` commands in [`README.md`](README.md).
3. `python3 scripts/generate_evaluation_report.py` regenerates
   `docs/evaluation-report.md`; `python3 scripts/save_results.py` snapshots
   `results/<timestamp>/`. The interactive version of every step is in
   [`notebooks/`](notebooks/README.md).