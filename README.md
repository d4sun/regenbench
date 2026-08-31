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
| T3.11| GGUF attack surface demo & report | — | [`scripts/run_task3_demo.py`](scripts/run_task3_demo.py), [`docs/demo-report.md#5`](docs/demo-report.md) (standalone `docs/task3-demo.md` via `run_task3_demo.py` optional) |
| T3.12| Defense/repair prototype (sanitization, quarantine + safe reserialization) | — | [`pipeline/sanitizer.py`](pipeline/sanitizer.py), [`pipeline/repair.py`](pipeline/repair.py), [`pipeline/defense.py`](pipeline/defense.py) |
| T3.13| Unified Task-3 demo (pickle + torch + GGUF, full pipeline) | — | [`scripts/demo_task3.py`](scripts/demo_task3.py), [`docs/demo-report.md`](docs/demo-report.md) |
| T3.14| Related-works comparison analysis | — | [`docs/related-works-comparison.md`](docs/related-works-comparison.md) |
| T3.15| Load-time monitoring | — | [`pipeline/monitor.py`](pipeline/monitor.py) |
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

To build the six historical scanner snapshots used for H3 shelf-life (optional, ~15 min):

```sh
containers/picklescan/build.sh 1.0.4 <picklescan-commit>   # -> regenbench/picklescan:1.0.4
containers/picklescan/build.sh 1.0.3 <picklescan-commit>
containers/modelscan/build.sh 0.8.7 <modelscan-commit>     # -> regenbench/modelscan:0.8.7
containers/modelscan/build.sh 0.8.6 <modelscan-commit>
containers/fickling/build.sh 0.1.11 <fickling-commit>
containers/fickling/build.sh 0.1.10 <fickling-commit>
# concrete commits are pinned in containers/*/build.sh; omit to use :latest
```

---

## Full Experiment — Step-by-Step Reproduction

Reproduces the numbers in **Latest results** (1025 generated / 990 valid / 514 bypasses, H1–H3) on a machine with `docker` and Python 3.10+. Estimated wall time: **~8 h** for the two scaled campaigns + **~1.5 h** for shelf-life rescans. Every step is idempotent — re-running overwrites the same report paths.

```sh
# 0. Prereqs & sanity (host needs no torch/sklearn)
python3 -m pip install --user PyYAML
python3 -m pytest tests/ -x -q                          # 171 passed expected
./ci/smoke.sh --no-build                                # 64/64 assertions (needs images)
```

```sh
# 1. Benign corpus — either crawl real HuggingFace checkpoints OR reuse the
#    committed flat corpus (real_benign_corpus/all/, 17 .bin files, no network).
#    The scaled campaign seeds from the smallest text-generation checkpoint.
mkdir -p real_benign_corpus/all   # already populated in this repo
# to re-crawl from scratch:
# python3 scripts/crawl_benign.py --clusters text-classification,feature-extraction,text-generation --limit-per-cluster 40 --out-dir data/crawled
# mkdir -p real_benign_corpus/all && find data/crawled -name "pytorch_model.bin" -exec sh -c 'ln "$1" "real_benign_corpus/all/$(basename $(dirname $(dirname "$1")))__$(basename $(dirname "$1")).bin"' _ {} \;
```

```sh
# 2. ShadowPickle baseline (handcrafted 3 families, 40 candidates) — ~2 min
python3 scripts/run_shadowpickle_baseline.py \
  --candidates-per-family 20 --backend docker   # -> data/regenbench_shadowpickle.db (10/40 bypasses)
```

```sh
# 3. Scaled campaigns — the two long runs that produce data/regenbench_campaign.db
#    Guided (oracle_aware, adaptive evasion, 25×20=500 candidates, family quotas + entropy):
python3 scripts/run_fuzzing_campaign.py \
  --mode guided --rounds 25 --candidates-per-round 20 --replicate 1 \
  --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode adaptive --fitness-mode oracle_aware \
  --backend docker --time-budget-hours 8 --seed 42

#    Unguided ablation (uniform random, same budget, 24×20=480 candidates):
python3 scripts/run_fuzzing_campaign.py \
  --mode unguided --rounds 24 --candidates-per-round 20 --replicate 1 \
  --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode random --fitness-mode current \
  --backend docker --time-budget-hours 8 --seed 42

#    Quick check (should be 1025 generated / 990 valid / 514 bypasses after both finish; 1055 was an earlier total):
sqlite3 data/regenbench_campaign.db "SELECT COUNT(*) FROM candidates;"
sqlite3 data/regenbench_campaign.db "SELECT COUNT(*) FROM campaign_fitness WHERE is_valid=1;"
sqlite3 data/regenbench_campaign.db "SELECT COUNT(*) FROM candidates c JOIN campaign_fitness f ON f.candidate_id=c.candidate_id WHERE f.is_valid=1 AND c.panel_verdict='all_benign';"
```

```sh
# 4. Regenerate docs/evaluation-report.md from the live DB (no containers, <10 s).
#    Fast DB-only generator (the full suite also supports --corpus-dir for slow FP/monitor docker scans):
python3 scripts/generate_evaluation_report.py  # -> docs/evaluation-report.md
#    Legacy full suite (slow, ~40 min FP + ~4 h monitor):
#    python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all
#    Verify H1 Supported (51.9% vs 25.0%), guided 77.3% vs unguided 19.7% (Fisher p≈0, z=18.0), H2 valid negative (514==514)
```

```sh
# 5. Shelf-life rescans — bulk-register bypasses then re-scan against 6 historic images (~1.5 h, ~1.7 s/scan)
python3 -c "from pipeline.shelf_life import register_bypasses_from_campaign_db; register_bypasses_from_campaign_db('data/regenbench_campaign.db')"
#    One scanner at a time (all should be 100% retention):
for ver in 1.0.4 1.0.3; do
  python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:$ver --scanners picklescan --backend docker
done
for ver in 0.8.7 0.8.6; do
  python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver --scanners modelscan --backend docker
done
for ver in 0.1.11 0.1.10; do
  python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image fickling=regenbench/fickling:$ver --scanners fickling --backend docker
done
sqlite3 data/shelf_life.db "SELECT new_version, total, retained, printf('%.1f%%', retention_rate*100) FROM (SELECT new_version, COUNT(*) total, SUM(evasion_retained) retained, AVG(evasion_retained) retention_rate FROM rescans GROUP BY new_version);"
```

```sh
# 6. Full pipeline demo (one candidate per family -> panel -> ExecutionOracle -> defense -> GGUF) — ~2 min
python3 scripts/demo_task3.py --backend docker   # -> docs/demo-report.md + demo-artifacts/demo-report.json
python3 pipeline/monitor.py  # StraceOracle.confirm_execution() is exercised by demo_task3; LoadTimeMonitor now 0% FP on benign

# 7. Supplementary reports + snapshot
python3 scripts/benchmark_perf.py    # -> docs/perf-report.md (16.9× pre-filter speedup)
python3 scripts/triage_bypasses.py   # -> docs/triage-report.md (30% repair escapes triaged as quarantined)
python3 scripts/save_results.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all  # -> results/<timestamp>/
```

Re-run order matters only for step 3 (both campaigns append to the same DB). All reports are overwritten in place; the DB is the source of truth.

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

#### Signature-evasion mode (Phase 1/2)

Candidates can be post-processed with signature-evasion strategies
(`pipeline/evasion.py`) that rewrite the malicious stream so the same payload
still executes while the byte patterns static scanners match are removed or
hidden: `stack_global_encoding` (GLOBAL→STACK_GLOBAL, proto-4),
`payload_obfuscation` (trigger strings hidden in nested-pickle blobs),
`indirect_chain` (`__import__`/`getattr` runtime sink resolution; also
available as the `indirect_chain` attack family), and `nested_loads_wrap`
(whole-stream nesting). All strategies preserve trigger execution exactly.

```sh
python3 scripts/run_fuzzing_campaign.py --mode guided --evasion-mode adaptive ...
python3 scripts/run_fuzzing_campaign.py --mode unguided --evasion-mode random ...   # ablation baseline
python3 scripts/run_fuzzing_campaign.py --evasion-strategies stack_global_encoding,indirect_chain ...
```

With evasion enabled the guided loop uses multi-objective fitness
(`compute_fitness_multi`: graded per-scanner credit + novelty bonus +
error penalty) and grey-box feedback: scanner wrappers emit `matched_rules`,
and `FeedbackController` down-weights callables whose names fired rules.
Fuzzing reports gain a per-scanner evasion table. The smuggling primitives
(`builtins.__import__`, `builtins.getattr`, `_pickle.loads`) are registered in
`dangerous_callables.yaml` (category `import_smuggling`, never selected as
direct sinks) so coverage tracking and the pre-filter see evasive streams.

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
and benign GGUFs across all scanners and the `ggufref` oracle:

```sh
python3 scripts/run_task3_demo.py --corpus data/gguf_benign_corpus  # -> docs/task3-demo.md (optional)
# If data/gguf_benign_corpus is not crawled, the demo uses synthetic benign_gguf() (see docs/demo-report.md#5)
```

Run the unified Task-3 demo that walks the full pipeline (generate one
candidate per attack family -> static panel -> ExecutionOracle -> defense
prototype -> GGUF surface) on a small committed subset, producing
`docs/demo-report.md` and `demo-artifacts/demo-report.json`:

```sh
python3 scripts/demo_task3.py --backend docker   # -> docs/demo-report.md
```

The defense prototype combines static sanitization (`pipeline/sanitizer.py`),
repair output/quarantine policy (`pipeline/repair.py` and
`pipeline/defense.py`), and containerized load-time monitoring
(`pipeline/monitor.py`). It never mutates the source artifact and only
reserializes content that survives `torch.load(weights_only=True)` inside the
sandboxed base container. Related-works context is in
`docs/related-works-comparison.md`.

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
| Evaluation report | `docs/evaluation-report.md` | RQ1-RQ4 tables, FP rates, hypothesis verdicts (reachable-space coverage) |
| Task 3 GGUF demo report | `docs/demo-report.md#5` (`docs/task3-demo.md` standalone optional) | Scanner detection matrix on GGUF attack surface & blind spots |
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
  docs/evaluation-report.md docs/demo-report.md docs/task3-demo.md docs/fuzzing-report-*.md \
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

Live DB: `data/regenbench_campaign.db` (2 runs, 990 valid, 514 bypasses). Full detail: [`docs/evaluation-report.md`](docs/evaluation-report.md) and [`docs/demo-report.md`](docs/demo-report.md) (GGUF section). Archive snapshot: `reference/baseline_snapshot/results-20260818-141227/` (pre-fix, 693 valid, 0 bypasses).

### Scaled results (2026-08-30, all 5 families, adaptive evasion, splice transport)

- Guided 500 → 554 valid, **428 confirmed bypasses (77.3%)**; unguided 480 → 436 valid, **86 confirmed bypasses (19.7%)**; Fisher p=0.0, z=17.99.
- Per-scanner evasion (990 valid): PickleScan **51.9%** [48.9%,55.1%], ModelScan **62.9%** [59.9%,65.9%], Fickling **94.2%** [92.7%,95.7%].
- **H1 Supported**: fuzzing 51.9% vs ShadowPickle baseline 25.0% (relative improvement 108% per proposal wording; non-overlapping bootstrap CIs).
- **H2 valid negative**: uncorroborated == confirmed (514); the static panel already detects all non-executing candidates, so dynamic validation's value is confirming execution (trigger polling), not filtering false evasions.
- **H3 Supported**: 514 bypasses × 6 historical scanner versions (picklescan 1.0.4/1.0.3, modelscan 0.8.7/0.8.6, fickling 0.1.11/0.1.10) → **100% retention** (stagnation, not patch evasion; see below).

Fickling now torch-capable with a narrow torch-plumbing allowlist (0% FP on benign HF corpus, StraceOracle 0% FP). Legacy mutators harden against ~8% candidate corruption (rejected by validity oracle). `platform.popen` removed in Python 3.13 — dead sink. For torch campaigns use `--panel-scanners picklescan modelscan fickling`.

**Campaigns** (live DB `data/regenbench_campaign.db`, 2 runs, 1025 generated / 990 valid / 514 bypasses):

| Run | Type | Replicate | Generated | Valid | Confirmed Bypasses |
| :--- | :--- | :---: | :---: | :---: | :---: |
| guided-r1 | guided | 1 | 500 | 554 | 428 |
| unguided-r1 | unguided | 1 | 462 | 436 | 86 |

> Note: `generated` is `rounds*candidates_per_round` (500/462); `valid` is ExecutionOracle-confirmed (`campaign_fitness.is_valid=1`). Archived 13-run cumulative (2299 candidates, 8 pre-fix zero-bypass runs) is in `reference/baseline_snapshot/` and `docs/fuzzing-report-guided-r3.md` etc.; current DB holds the post-fix scaled proof only.

**RQ1 evasion**: 514/990 over all valid candidates; per-scanner PickleScan 51.9%, ModelScan 62.9%, Fickling 94.2% (see evaluation report for bootstrap CIs). H1 is relative improvement over ShadowPickle baseline (51.9% vs 25.0%, Supported).

**RQ3 benign false positives** over 17 real HuggingFace checkpoints (StraceOracle 0% FP; DynaHug supplementary):

| Scanner | FP Detections / 17 | FP Rate |
| :--- | :---: | :---: |
| PickleScan | 0 | 0.0% |
| ModelScan | 0 | 0.0% |
| ModelTracer | 0 | 0.0% |
| Fickling | 0 | 0.0% |
| DynaHug (Calibrated Oracle, supplementary) | 11 | 64.7% |

> **DynaHug caveat**: the upstream pretrained text-generation OCSVM
> (8ff8174) collapses in this container environment — every loadable
> checkpoint, benign or malicious, scores a constant ≈ -rho, so its verdict
> is non-discriminative (97.9% FP on this corpus). We therefore run the
> environment-calibrated oracle fit by `scripts/calibrate_oracle.py` on this
> host's syscall profiles (see `docs/oracle-calibration-deviation.md`). It
> restores a discriminative decision score but still has a **measured 63.5%
> FP rate** on real benign checkpoints — its traces are dominated by the
> loader's Python/torch startup baseline, so the OCSVM boundary sits close to
> zero. RQ3 reports this honestly; ground truth is provenance-based (verified HF repo). ExecutionOracle (trigger polling / StraceOracle) is 0% FP and gates bypass confirmation.

**RQ4 ablations**: pre-filter throughput speedup **16.92x** (1.03s vs 17.47s
over 5 files); guided vs unguided confirmed-bypass rates 428/554 (77.3%) vs 86/436 (19.7%)
(z=18.0, p≈0, Fisher p≈0).

**Task 3 (GGUF attack surface — format-complexity demo, not scanner robustness)**:
`ggufref` (reference-parser oracle) detects 7/7 GGUF attacks (6 malformed-header
families + Jinja2 SSTI CVE-2024-34359) with 0 FP on synthetic `benign_gguf()` (real `data/gguf_benign_corpus/` optional, re-crawl via `scripts/crawl_gguf.py`). The
pickle-oriented panel is not applicable: modelscan 0.8.8 misses all 7 (0/7,
no GGUF rules) and fickling flags benign as malicious when forced. GGUF results demonstrate format complexity and the need for a dedicated oracle,
not panel robustness.

**Hypotheses (post-fix, 2026-08-30)**: H1 Supported (fuzzing 51.9% vs
ShadowPickle baseline 25.0%); H2 valid negative result (uncorroborated ==
confirmed = 514 — the dual-oracle adds no precision because the static panel
already detects all non-executing candidates; dynamic validation confirms
execution); H3 Supported (514 bypasses × 6 historical versions → 100% retention).

**RQ1 Re-scoping**: Fuzzing generated 2 semantic fingerprints within the `pypi_injected` template family using `splice` transport (not novel attack families). Re-framed from "Discovering novel semantic attack families" to "Automated high-yield generation, structural parameterization, and signature-evasion optimization of third-party injection sinks." Relative improvement over ShadowPickle baseline (51.9% vs 25.0%) remains the primary claim.

**RQ2 Re-framing**: Q_first = [1] (guided) vs [12] (unguided) indicates high sink susceptibility, not search convergence. Search efficiency is evidenced by Candidate Bypass Yield: guided 77.3% vs unguided 19.7% (z=18.0, p≈0, Fisher p≈0).

**H3 Shelf-Life Note**: 100% retention reflects *scanner stagnation* (no rules for
`IPython.utils.process.system` or splice transport added in those versions),
not adaptive patch evasion.

**Repair triage (30% not repaired)**: `PickleSanitizer` only rewrites 5
direct sinks (`os.system`, `subprocess.Popen`, `builtins.exec/eval`,
`IPython.utils.process.system` → `builtins.len`). `indirect_chain`
(`__import__`+`getattr` chain) and unsanitized `numpy.runstring` / `posix.execv`
bypass the rewriter and are quarantined rather than sanitized. 100% benign
preservation is guaranteed; remaining escapes are quarantined.
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
