# RegenBench

A reproducible benchmark harness for security scanning of machine-learning
model artifacts. Each scanner (and a behavioral oracle) is packaged as a
reproducible container and wrapped behind a single
[unified verdict schema](docs/verdict-schema.md).

> **License**: [MIT](LICENSE).
>
> **Warning**: this is a security-research benchmark. It contains, generates,
> and downloads **real malicious and malformed ML artifacts** (code-executing
> Pickle/PyTorch checkpoints, real malicious Hugging Face models, GGUF
> malformed-header attacks and a Jinja2 SSTI payload). Only run artifacts
> inside the provided containers. See [DISCLAIMER.md](DISCLAIMER.md) before
> using this repository.

## Components

| Task | Component | Container / Path | Status |
|----|-----------|-----------|--------|
| T0.1 | Host spec & verification | — | [`docs/t0.1-host-spec.md`](docs/t0.1-host-spec.md) |
| T0.2 | Base image | `regenbench/base` | `containers/base` |
| T0.3 | PickleScan | `regenbench/picklescan` | `containers/picklescan` |
| T0.4 | ModelScan | `regenbench/modelscan` | `containers/modelscan` |
| T0.5 | Fickling | `regenbench/fickling` | `containers/fickling` |
| T0.6 | ModelTracer | `regenbench/modeltracer` | `containers/modeltracer` |
| T0.7 | DynaHug behavioral oracle | `regenbench/dynahug` | `containers/dynahug` |
| T0.8 | Smoke-test corpus + CI | — | `ci/` |
| T0.9 | MLflow experiment tracking | — | `pipeline/tracking.py` |
| T0.10| Local task orchestration | — | `pipeline/runner.py` |
| T1.1 | Published scanner metrics | — | [`reference/published-scanner-metrics.json`](reference/published-scanner-metrics.json) |
| T1.2 | Published DynaHug metrics | — | [`reference/published-dynahug-metrics.json`](reference/published-dynahug-metrics.json) |
| T1.3 | Pretrained DynaHug oracle check | — | [`scripts/oracle_sanity.py`](scripts/oracle_sanity.py) |
| T1.4 | Sanity smoke test | — | [`scripts/sanity_smoke.py`](scripts/sanity_smoke.py) |
| T1.5 | Comparison methodology and caveats | — | [`docs/comparison-methodology.md`](docs/comparison-methodology.md) |
| T2.1 | Parameterized Overwritten-Module template | — | [`pipeline/templates.py`](pipeline/templates.py) |
| T2.2 | Parameterized PyPI-Injected template | — | [`pipeline/templates.py`](pipeline/templates.py) |
| T2.3 | Parameterized External-Module template | — | [`pipeline/templates.py`](pipeline/templates.py) |
| T2.4 | Benign Hugging Face seed corpus | — | `data/crawled/` |
| T2.5 | Seed corpus manifest and versioning | — | [`data/crawled/seed_manifest.json`](data/crawled/seed_manifest.json) |
| T3.1 | Port PickleFuzzer opcode categorization | — | [`pipeline/opcodes.py`](pipeline/opcodes.py) |
| T3.2 | Build dangerous-callable registry | — | [`pipeline/dangerous_callables.yaml`](pipeline/dangerous_callables.yaml) |
| T3.3 | Implement candidate generator core | — | [`pipeline/generator.py`](pipeline/generator.py) |
| T3.4 | Implement mutation operators | — | [`pipeline/mutators.py`](pipeline/mutators.py) |
| T3.5 | Implement validity oracle | — | [`pipeline/validity.py`](pipeline/validity.py) |
| T3.6 | Unit/property tests for generator | — | [`scripts/test_generator_suite.py`](scripts/test_generator_suite.py) |
| T3.7 | GGUF parser/writer & attack generators | — | [`pipeline/gguf_tools.py`](pipeline/gguf_tools.py) |
| T3.8 | GGUF reference oracle container | `regenbench/gguf` | `containers/gguf` |
| T3.9 | Real GGUF benign crawler & corpus | — | [`scripts/crawl_gguf.py`](scripts/crawl_gguf.py), `data/gguf_benign_corpus/` |
| T3.10| MalHug real malicious corpus crawler | — | [`scripts/crawl_malhug.py`](scripts/crawl_malhug.py), `data/malhug/` |
| T3.11| GGUF attack surface demo & report | — | [`scripts/run_task3_demo.py`](scripts/run_task3_demo.py), [`docs/task3-demo.md`](docs/task3-demo.md) |
| T4.1 | Implement static pre-filter | — | [`pipeline/pre_filter.py`](pipeline/pre_filter.py) |
| T4.2 | Implement scanner panel runner | — | [`pipeline/runner.py`](pipeline/runner.py) |
| T4.3 | Implement behavioral oracle runner | — | [`pipeline/runner.py`](pipeline/runner.py) |
| T4.4 | Define unified candidate schema | — | [`pipeline/db.py`](pipeline/db.py) |
| T4.5 | E2E integration test suite | — | [`scripts/test_integration.py`](scripts/test_integration.py) |
| T4.6 | Throughput/latency benchmarking | — | [`scripts/benchmark_perf.py`](scripts/benchmark_perf.py) |
| T5.1 | Implement dual-oracle comparator | — | [`pipeline/comparator.py`](pipeline/comparator.py) |
| T5.2 | Implement distance-to-boundary fitness | — | [`pipeline/fitness.py`](pipeline/fitness.py) |
| T5.3 | Implement coverage tracker | — | [`pipeline/feedback.py`](pipeline/feedback.py) |
| T5.4 | Wire feedback into mutation weighting | — | [`pipeline/feedback.py`](pipeline/feedback.py) |
| T5.5 | Directed E2E fuzzing campaign | — | [`scripts/run_fuzzing_campaign.py`](scripts/run_fuzzing_campaign.py) |

Each `containers/<name>/` holds a `Dockerfile`, `wrapper.py` (or `validator.py`), and `build.sh`
(produces `regenbench/<name>:<version>` and `:latest`).

---

## Prerequisites

- **Container runtime**: `podman` (default) or `docker` (pass `--backend docker`
  to any script).
- **Python >= 3.10** on the host with the crawl/tracking dependencies:
  ```sh
  python3 -m pip install --user PyYAML  # required by the registry/drivers
  python3 -m pip install --user huggingface_hub  # only for the benign crawl
  python3 -m pip install --user "mlflow>=2.10,<3"  # optional: T0.9 tracking
  ```
- **Network access to Hugging Face Hub** (only if running the crawl).

All scanner/oracle dependencies live inside the containers; the host needs no
torch/sklearn installs.

## Building the scanner panel

Build order matters (each scanner `FROM` the base image):

```sh
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do
  containers/$d/build.sh
done
```

This produces `regenbench/<name>:<version>` plus a `:latest` tag for each.

---

## Running the framework

All commands run from the repository root and write results into the
repository (see [Saving results](#saving-results) below). The panel + oracle
containers must be built first (see above).

### 0. Validate the build (optional)

```sh
./ci/smoke.sh --no-build   # 64/64 assertions against ci/corpus/expected.json
```

### 1. Crawl a benign Hugging Face corpus (T2.4 / T2.5)

Downloads `pytorch_model.bin` weights from public, non-gated repositories,
deduplicates by SHA-256, and writes a versioned seed manifest:

```sh
python3 scripts/crawl_benign.py \
  --clusters text-classification,feature-extraction,text-generation \
  --limit-per-cluster 40 \
  --max-size 134217728 \
  --out-dir data/crawled
```

Outputs: `data/crawled/<cluster>/<repo>/pytorch_model.bin` and
`data/crawled/seed_manifest.json`. The crawl is resumable (re-running skips
already-downloaded hashes).

### 2. Populate the benign corpus and validate the oracle

The RQ3 false-positive study and oracle views operate on a flat corpus
directory. Link the crawled checkpoints in (hard links, no data copy):

```sh
mkdir -p real_benign_corpus/all
while IFS= read -r f; do
  repo=$(basename "$(dirname "$f")")
  cluster=$(basename "$(dirname "$(dirname "$f")")")
  ln "$f" "real_benign_corpus/all/${cluster}__${repo}.bin" 2>/dev/null
done < <(find data/crawled -mindepth 3 -maxdepth 3 -name "pytorch_model.bin")
```

Run the behavioral oracle over a random sample and organize the score-split
views:

```sh
python3 scripts/validate_oracle.py real_benign_corpus/all --sample 60 \
  --out real_benign_corpus/oracle-validation.json
python3 scripts/organize_corpus.py \
  --corpus real_benign_corpus/all \
  --report real_benign_corpus/oracle-validation.json \
  --out real_benign_corpus
```

### 3. Run fuzzing campaigns

Each campaign generates candidates from a benign torch checkpoint, mutates
them toward dangerous callables, validates them (container-sandboxed load +
trigger check), runs the scanner panel and the DynaHug oracle, and records
everything in the SQLite campaign DB.

Attack families are sampled per candidate from `--attack-families`
(default `gadget,overwritten,pypi_injected,external`):
`gadget` is the dangerous-callable `GLOBAL`/`REDUCE` injection, while
`overwritten` / `pypi_injected` / `external` are the three ShadowPickle
families (overwritten-module, PyPI-injected, external-module) implemented in
`pipeline/templates.py`. A real benign Hugging Face checkpoint from the
crawl can be used as the campaign seed via `--seed-corpus-dir
<cluster>__<repo>.bin`; the smallest valid checkpoint in the matching task
cluster is selected (Phase-1 element 1, "benign models, one cluster").
`--time-budget-hours` enforces the bounded-pilot time budget (Phase-1
element 5): the campaign stops early when the budget elapses and corrects
the recorded candidate total in the DB.

Pilot campaign (config-driven, `config/campaign_config.yaml`):

```sh
python3 scripts/run_pilot_campaign.py \
  --config config/campaign_config.yaml \
  --db data/regenbench_campaign.db \
  --attack-families gadget,overwritten,pypi_injected,external
```

Guided (coverage-guided) and unguided fuzz campaigns, one per replicate:

```sh
python3 scripts/run_fuzzing_campaign.py --mode guided   --rounds 5 \
  --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 5 \
  --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
  --attack-families gadget,overwritten,pypi_injected,external
```

`config/campaign_config.yaml` also sets the default `campaign.base_checkpoint`
(a real text-generation checkpoint rather than the synthetic toy), the round
schedule, and `campaign.time_budget_hours` used by the pilot.

The same DB accumulates all runs; each gets a `fuzzing-report-<run_id>.md`.

### 4. Run the evaluation & ablation suite

Computes RQ1-RQ4 statistics, benign false-positive rates over the corpus
(T7.5), guided vs unguided ablation (T7.6), pre-filter throughput ablation
(T7.7), the DynaHug cross-check (T7.8), coverage growth (T7.3), and the
guided-vs-unguided hypothesis test (T7.10). Regenerates
`docs/evaluation-report.md`:

```sh
python3 scripts/run_evaluation_suite.py \
  --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all
```

### 5. Task 3: GGUF attack surface demo & MalHug real malicious corpus

Crawl the real benign GGUF corpus (TinyLlama series + llama.cpp tokenizers)
and the MalHug malicious dataset (ASE 2024, real Hugging Face malicious models):

```sh
python3 scripts/crawl_gguf.py       # -> data/gguf_benign_corpus/ (~24 GGUF models)
python3 scripts/crawl_malhug.py     # -> data/malhug/ (~73 malicious models + manifest.json)
```

Run the Task 3 GGUF demo to scan 7 malicious attack families (Jinja2 SSTI
`tokenizer.chat_template` CVE-2024-34359 + 6 vellaveto malformed-header attacks)
and 24 real benign GGUFs across all scanners and the `ggufref` oracle:

```sh
python3 scripts/run_task3_demo.py --corpus data/gguf_benign_corpus  # -> docs/task3-demo.md
```

### 6. Supplementary reports

Throughput/latency benchmark (T4.6) and bypass triage (T6.4):

```sh
python3 scripts/benchmark_perf.py   # -> docs/perf-report.md
python3 scripts/triage_bypasses.py  # -> docs/triage-report.md
```

---

## Saving results

Every artifact is written into the repository under a fixed path, so a full
run is preserved by archiving the directories below. Confirmed scanner
bypasses are also exported to `data/bypasses/` as standalone, replayable JSON.

| What | Where | Notes |
| :--- | :--- | :--- |
| Campaign database | `data/regenbench_campaign.db` | SQLite: candidates, panel/oracle results, fitness, coverage, run metadata |
| Exported confirmed bypasses | `data/bypasses/<run_id>/` | Written by the pilot campaign driver (T6.3); empty if no bypasses confirmed |
| Generated candidates | `data/candidates/<run_id>/` | Per-round candidate checkpoints |
| Crawled benign torch corpus | `data/crawled/` + `seed_manifest.json` | Raw weights + SHA-256 provenance manifest |
| Benign corpus + views | `real_benign_corpus/all`, `oracle_positive/`, `oracle_negative/` | Hard links; `oracle-validation.json` holds the DynaHug scores |
| Benign GGUF corpus | `data/gguf_benign_corpus/` | Crawled TinyLlama + llama.cpp vocab GGUF models |
| MalHug malicious corpus | `data/malhug/` + `manifest.json` | Crawled real malicious Hugging Face models (ASE 2024) |
| Evaluation report | `docs/evaluation-report.md` | RQ1-RQ4 tables, FP rates, hypothesis verdicts |
| Task 3 GGUF demo report | `docs/task3-demo.md` | Scanner detection matrix on GGUF attack surface & blind spots |
| Fuzzing reports | `docs/fuzzing-report-<run_id>.md` | Per-campaign round tables |
| Perf report | `docs/perf-report.md` | Pre-filter throughput speedup |
| Triage report | `docs/triage-report.md` | Bypass profiles by dangerous callable |
| MLflow tracking | `mlruns/` | Optional (T0.9), via `MlflowSink` |

To archive a complete run for the record:

```sh
tar czf regenbench-results-$(date +%Y%m%d-%H%M%S).tar.gz \
  data/regenbench_campaign.db \
  data/bypasses data/candidates data/crawled \
  data/gguf_benign_corpus data/malhug \
  real_benign_corpus \
  docs/evaluation-report.md docs/task3-demo.md docs/fuzzing-report-*.md \
  docs/perf-report.md docs/triage-report.md
```

Or snapshot everything into a versioned `results/<timestamp>/` directory with
a machine-readable summary (campaign DB, all reports, bypass exports, corpus
metadata, GGUF/MalHug inventories, plus `results.md` / `results.json`):

```sh
python3 scripts/save_results.py \
  --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all
```

> **Reproducibility**: the campaign DB is self-contained — the eval suite and
> the report generation read from it. Re-exporting bypasses from a DB is done
> with `pipeline.corpus_manager.export_bypasses(db_path, output_dir)`.

---

## Latest results

Snapshot: `results/20260818-141227/` (see `results.md` / `results.json`).
Full detail: [`docs/evaluation-report.md`](docs/evaluation-report.md) and
[`docs/task3-demo.md`](docs/task3-demo.md).

**Campaigns** (7 runs, 700 candidates in `data/regenbench_campaign.db`):

| Run | Type | Replicate | Candidates | Valid | Confirmed Bypasses |
| :--- | :--- | :---: | :---: | :---: | :---: |
| pilot-20260816T030153Z | guided | 1 | 100 | 93 | 0 |
| guided-r1 | guided | 1 | 100 | 100 | 0 |
| guided-r2 | guided | 2 | 100 | 100 | 0 |
| unguided-r1 | unguided | 1 | 100 | 100 | 0 |
| unguided-r2 | unguided | 2 | 100 | 100 | 0 |
| pilot-20260817T101219Z | guided | 1 | 100 | 100 | 0 |
| guided-r3 | guided | 3 | 100 | 100 | 0 |

**RQ1 evasion**: 0/693 scanner evasions across all valid candidates →
`H1 not supported` on current data (evasion below the 70% threshold).

**RQ3 benign false positives** over 96 real HuggingFace checkpoints:

| Scanner | FP Detections / 96 | FP Rate |
| :--- | :---: | :---: |
| PickleScan | 0 | 0.0% |
| ModelScan | 0 | 0.0% |
| ModelTracer | 0 | 0.0% |
| Fickling | 6 | 6.2% |
| DynaHug (Calibrated Oracle) | 61 | 63.5% |

> **DynaHug caveat**: the upstream pretrained text-generation OCSVM
> (8ff8174) collapses in this container environment — every loadable
> checkpoint, benign or malicious, scores a constant ≈ -rho, so its verdict
> is non-discriminative (97.9% FP on this corpus). We therefore run the
> environment-calibrated oracle fit by `scripts/calibrate_oracle.py` on this
> host's syscall profiles (see `docs/oracle-calibration-deviation.md`). It
> restores a discriminative decision score but still has a **measured 63.5%
> FP rate** on real benign checkpoints — its traces are dominated by the
> loader's Python/torch startup baseline, so the OCSVM boundary sits close to
> zero. RQ3 reports this honestly rather than filtering the corpus by oracle
> verdict (ground truth is provenance-based).

**RQ4 ablations**: pre-filter throughput speedup **16.92x** (1.03s vs 17.47s
over 5 files); guided vs unguided confirmed-bypass rates 0/493 vs 0/200
(test not computable — both pooled proportions are 0).

**Task 3 (GGUF attack surface)**: `ggufref` detects 7/7 GGUF attacks
(6 malformed-header families + Jinja2 SSTI CVE-2024-34359) with 0 FP on
24 real benign GGUFs, while modelscan 0.8.8 misses all 7 (0/7) and fickling
flags every benign GGUF as malicious (24/24 FP).

**Hypotheses**: H2 not assessable (uncorroborated and confirmed evasions are
both 0); H3 is a simulated extrapolation (0.0% remaining efficacy, no
version-delta data).

### Evaluation correctness fixes (2026-08-19)

Two measurement bugs were found and fixed before this snapshot, and the RQ3
FP table above is the corrected measurement:

1. **SELinux mount race** (`pipeline/scanners.py`): every scan mounted the
   artifact with `:ro,Z` (a *private* SELinux relabel). When multiple
   scanners mount the *same* checkpoint concurrently — which the runner does
   by default — the relabels race and containers intermittently crash with
   `PermissionError` before reading the artifact. Fickling reports such a
   crash (exit 1) as *malicious*, so its FP rate was nondeterministic
   (measured 9.4%–43.8% across runs). The fix switches to `:ro,z` (shared,
   idempotent relabel); Fickling is now deterministic at **6.2% FP**.
2. **Calibrated DynaHug oracle not wired in** (`pipeline/runner.py`,
   `scripts/run_evaluation_suite.py`): the environment-calibrated OCSVM
   existed but the runner never passed `DYNAHUG_MODEL_DIR`, so the FP study
   silently used the collapsed upstream model (97.9% FP by construction).
   The runner now threads `Config.oracle_model_dir` through to the oracle
   container; the FP study uses the calibrated oracle and reports its genuine
   **63.5% FP rate** instead of the constant-score artifact.

---

## Running the smoke suite

Build the panel and validate every artifact against
`ci/corpus/expected.json`:

```sh
./ci/smoke.sh            # build base+panel, generate torch corpus, assert
./ci/smoke.sh --no-build # reuse already-built local images
```

The same run executes on every push/PR to `main` via
`.github/workflows/smoke.yml`. See [`ci/corpus/README.md`](ci/corpus/README.md)
for corpus layout and how to add artifacts.
