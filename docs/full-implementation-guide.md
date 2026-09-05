# ReGenBench — Full Implementation Guide

A single step-by-step runbook for the **complete** ReGenBench implementation,
from a clean checkout to final results, charts, and snapshot. Every step lists
the exact commands, the artifacts they produce, and how to verify they worked.
Charts produced at each stage are written under `charts/<NN>_<step>/`.

> Time estimate on a machine with `docker` and the built images: **~1–2 h crawl
> + ~1.5 h campaigns + ~1 h rescans/eval + minutes per chart/report run**.

Related docs: [`README.md`](README.md) (overview), [`QUICKSTART.md`](QUICKSTART.md)
(slimmer "what to do"), [`IMPLEMENTATION.md`](IMPLEMENTATION.md) (how modules
work), [`RESULTS.md`](RESULTS.md) (measured outcomes).

---

## 00 — Preconditions (host + containers)

```sh
# Host Python deps (host-only analysis; containers hold torch/sklearn)
python3 -m pip install --user PyYAML huggingface_hub pytest matplotlib

# Host-only correctness suite (no docker needed)
python3 -m pytest tests/ -x -q          # 201 passed, 3 skipped expected

# Build the scanner/oracle panel (docker)
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do
  containers/$d/build.sh
done
docker images | grep regenbench         # base, picklescan, modelscan, fickling, modeltracer, dynahug, gguf

# Host gate: docker runtime, SELinux mount probe (:ro,z), concurrency sanity
./scripts/verify_host.sh
```
- **Verify**: `pytest` green; `verify_host.sh` exits 0; images listed above present.

---

## 01 — Crawl the real corpus (304 total: 179 PT + 125 GGUF)

```sh
python3 scripts/crawl_benign.py \
  --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering \
  --limit-per-cluster 25 --max-size 134217728 --out-dir data/crawled \
  --scan-cap 20000 --workers 8 --format both
```
- Produces `data/crawled/<cluster>/<repo>/pytorch_model.bin` (PT) and `data/crawled/<cluster>/<repo>/model.gguf` (GGUF) +
  `data/crawled/seed_manifest.json` with `"format": "pt"` or `"format": "gguf"`. Resumable; re-running skips existing
  hashes and backfills already-present files.
- **Verify**:
  ```sh
  python3 -c "import json; print(json.load(open('data/crawled/seed_manifest.json'))['summary'])"
  # -> total_models: 304, formats: {"pt": 179, "gguf": 125}

  mkdir -p real_benign_corpus/all_pt real_benign_corpus/all_gguf
  while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); \
    cluster=$(basename "$(dirname "$(dirname "$f")")"); \
    ln -f "$f" "real_benign_corpus/all_pt/${cluster}__${repo}.bin" 2>/dev/null; \
    done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
  while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); \
    cluster=$(basename "$(dirname "$(dirname "$f")")"); \
    ln -f "$f" "real_benign_corpus/all_gguf/${cluster}__${repo}.gguf" 2>/dev/null; \
    done < <(find data/crawled -mindepth 3 -maxdepth 3 -name "*.gguf")
  ls real_benign_corpus/all_pt | wc -l        # -> 179
  ls real_benign_corpus/all_gguf | wc -l       # -> 125
  ```
- **Chart**: `python3 scripts/generate_charts.py` → `charts/01_crawl/corpus_composition.png`.

---

## 02 — Oracle validation, views, disjoint split (PT + GGUF)

```sh
# Score every (sampled) real checkpoint with the DynaHug oracle (PT)
# Uses recalibrated model dir (--oracle-model-dir) and blank baseline for differential traces
python3 scripts/validate_oracle.py real_benign_corpus/all_pt --sample 100 \
  --out real_benign_corpus/oracle-validation.json --backend docker --format pt \
  --oracle-model-dir real_benign_corpus/oracle-calibrated/pt

# Build seed-selection views (oracle_positive / oracle_negative) for both formats
python3 scripts/organize_corpus.py --corpus-pt real_benign_corpus/all_pt \
  --corpus-gguf real_benign_corpus/all_gguf \
  --report real_benign_corpus/oracle-validation.json --out real_benign_corpus

# Deterministic cluster- AND format-stratified 50/50 train/eval split (FP study stays
# disjoint from calibration)
python3 scripts/check_oracle_disjointness.py --resplit
```
- **Verify**: `real_benign_corpus/oracle-split.json` has disjoint cluster- AND format-stratified `train`/`eval` halves.
- **Chart**: `charts/02_oracle/oracle_score_distribution.png`.

---

## 03 — Recalibrate the oracles on this corpus (PT + GGUF)

```sh
# PT (DynaHug) - Collect syscall traces on the train half only (never the eval half)
# Includes differential baseline subtraction (blank torch.load) for P2.2 Option A
python3 scripts/calibrate_oracle.py real_benign_corpus/all_pt \
  --split-file real_benign_corpus/oracle-split.json --split-role train \
  --out real_benign_corpus/oracle-calibrated/pt \
  --sample 50 --backend docker --seed 1337 --format pt

# The above fits OCSVM + vectorizer + scaler + writes blank_baseline.json in one pass
# (fit_oracle_sweep.py is deprecated; calibrate_oracle.py now handles the full pipeline)

# GGUF (ggufref) does not use OCSVM - it's a static reference reader + SSTI detection
# No calibration needed for GGUF; the oracle is deterministic

# FP on the disjoint eval half (PT only)
python3 scripts/fp_eval_oracle.py --format pt --model-dir real_benign_corpus/oracle-calibrated/pt \
  --split-file real_benign_corpus/oracle-split.json --role eval \
  --out real_benign_corpus/oracle-calibrated/pt/fp-eval-eval.json --backend docker
```
- **Verify**: `real_benign_corpus/oracle-calibrated/pt/` contains
  `oneclass_svm_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, `syscalls.txt`,
  `blank_baseline.json`, `fp-eval-eval.json`.
- **Chart**: `charts/03_calibrate/calibration_fp.png`.

---

## 04 — Baseline & fuzzing campaigns

### 04a. ShadowPickle baseline (H1 denominator)

```sh
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker
# -> data/regenbench_shadowpickle.db  (80 candidates, 20/80 = 25.0% bypass)
```

### 04b. Full guided + unguided campaigns (the headline run)

```sh
# guided: oracle-aware fitness, adaptive evasion, 25 rounds x 20
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 25 \
  --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42

# unguided: current fitness, random evasion, 24 rounds x 20
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 \
  --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode random --fitness-mode current --backend docker --seed 42
```
- Add `--validity-debug` to see full sandbox tracebacks for invalid candidates
  (default prints one readable line per failure).
- Produces `docs/fuzzing-report-<run>.md` per run.
- **Verify**:
  ```sh
  sqlite3 data/regenbench_campaign.db \
    "SELECT run_id, COUNT(*), SUM(is_valid) FROM campaign_fitness f JOIN candidates c ON c.candidate_id=f.candidate_id GROUP BY run_id;"
  ```

### 04c. Pilot (fast config-driven)

```sh
python3 scripts/run_pilot_campaign.py --quick \
  --attack-families gadget,overwritten,external,indirect_chain,pypi_injected
```

### 04d. 5x5 fitness ablation (20 campaigns) + analysis

```sh
bash run_fitness_ablation_experiment.sh      # guided current/oracle_aware/oracle_dominant + unguided, 5 replicates
python3 scripts/analyze_fitness_ablation.py --db data/regenbench_campaign.db \
  --json results/fitness_ablation_results.json
```

### 04e. Oracle-dominant validation (5 replicates)

```sh
bash run_oracle_dominant_validation.sh
python3 scripts/analyze_fitness_ablation.py --db data/regenbench_campaign.db \
  --json results/oracle_dominant_validation.json
```

### 04f. Parallel ablation (multiple fitness modes, seeds, workers)

```sh
python3 scripts/run_parallel_ablation.py --max-workers 4 --rounds 5 \
  --candidates-per-round 20 --seeds 1337 1338 1339 1340 1341 \
  --fitness-modes current oracle_aware oracle_dominant --backend docker \
  --seed-corpus-dir real_benign_corpus/all_pt --seed-cluster text-generation \
  --pt-corpus-dir real_benign_corpus/all_pt --gguf-corpus-dir real_benign_corpus/all_gguf \
  --format mixed --format-ratio 0.3 \
  --gguf-families ssti_chat_template,nkv_overflow,ntensors_overflow,string_overflow,path_traversal,negative_dims,version_zero,ssti_obfuscated_1,ssti_obfuscated_2,ssti_obfuscated_3
```
- **Verify**: `data/regenbench_campaign.db` contains the new run rows.
- **Charts**: `charts/04_campaigns/` — `coverage_opcode.png`,
  `coverage_callable.png`, `family_entropy.png`, `bypass_yield_per_round.png`,
  `per_family_bypasses.png`, `guided_vs_unguided_yield.png`.

---

## 05 — Evaluation & reports

```sh
# Fast, DB-only evaluation report (RQ1–RQ4, H1–H3, cross-format)
python3 scripts/generate_evaluation_report.py        # -> docs/evaluation-report.md

# Full suite: benign FP over the real corpus + defense + monitor (docker scans)
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all --fp-sample 100 --defense

# Bypass triage + per-scanner profile
python3 scripts/triage_bypasses.py                   # -> docs/triage-report.md

# Pre-filter throughput
python3 scripts/benchmark_perf.py                    # -> docs/perf-report.md

# Known-answer regression checks (pickle + GGUF)
python3 scripts/run_known_answers.py
```
- **Verify**: `docs/evaluation-report.md` regenerated with headline numbers
  matching `RESULTS.md`.
- **Charts**: `charts/05_evaluation/` — `per_scanner_evasion.png`,
  `cross_format_summary.png`.

---

## 06 — Defense (repair / monitor / demo)

```sh
# Static repair metrics over the committed CI corpus + LoadTimeMonitor over
# campaign bypasses and a benign sample (RQ4) — needs --defense
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all --fp-sample 100 --defense

# Interactive ModelDefense demo: one candidate per family -> generate ->
# panel -> ExecutionOracle -> quarantine/reserialize
python3 scripts/demo_task3.py --backend docker       # -> docs/demo-report.md
```
- **Verify**: `docs/evaluation-report.md` RQ4 section shows repair success /
  false-negative / correctness / overhead + monitor detection / false-alarm.
- **Chart**: `charts/06_defense/repair_metrics.png`.

---

## 07 — GGUF attack surface (format-complexity demo)

```sh
# Crawl 24 real benign TinyLlama + llama.cpp GGUFs (regenerable, gitignored)
python3 scripts/crawl_gguf.py                        # -> data/gguf_benign_corpus/

# GGUF-only detection matrix + FP over the real corpus
python3 scripts/run_task3_demo.py --backend docker   # -> docs/task3-demo.md

# Unified demo (pickle + GGUF + defense + monitor)
python3 scripts/demo_task3.py --backend docker       # -> docs/demo-report.md

# Insert the GGUF surface as format='gguf' candidates into the campaign DB
python3 scripts/insert_gguf_into_campaign.py
```
- **Verify**: `docs/task3-demo.md` shows ggufref 7/10, modelscan 0/10, FP 0/24;
  the campaign DB gains a `gguf-demo` run.
- **Chart**: `charts/07_gguf/gguf_detection_matrix.png`.

---

## 08 — Shelf-life rescans (H3)

```sh
# Bulk-register confirmed bypasses into data/shelf_life.db
python3 -c "from pipeline.shelf_life import register_bypasses_from_campaign_db; register_bypasses_from_campaign_db('data/regenbench_campaign.db')"

# Rescan each bypass against historical scanner versions
for ver in 1.0.4 1.0.3; do python3 scripts/shelf_life_rescan.py \
  --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:$ver \
  --scanners picklescan --backend docker; done
for ver in 0.8.7 0.8.6; do python3 scripts/shelf_life_rescan.py \
  --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver \
  --scanners modelscan --backend docker; done
for ver in 0.1.11 0.1.10; do python3 scripts/shelf_life_rescan.py \
  --db data/regenbench_campaign.db --image fickling=regenbench/fickling:$ver \
  --scanners fickling --backend docker; done

# Retention summary
sqlite3 data/shelf_life.db \
  "SELECT new_version, total, retained, printf('%.1f%%', retention_rate*100) FROM (SELECT new_version, COUNT(*) total, SUM(evasion_retained) retained, AVG(evasion_retained) retention_rate FROM rescans GROUP BY new_version);"
```
- Historical images are buildable with `containers/<name>/build.sh [VERSION] [SCANNER_COMMIT]`.
- **Chart**: `charts/08_shelf_life/retention_by_version.png`.

---

## 09 — Differential / cross-parser disagreement (RQ1 optional)

```sh
# Enable cross-parser disagreement mutation at 10% of candidates
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 5 \
  --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,external,indirect_chain,pypi_injected \
  --evasion-mode adaptive --fitness-mode oracle_aware --backend docker \
  --differential-prob 0.1 --seed 42
```
- **Verify**: new `guided` run rows in the DB with differential candidates.

---

## 10 — Disclosure report (coordinated disclosure drafts)

```sh
python3 scripts/generate_disclosure_report.py --db data/regenbench_campaign.db \
  --output-dir docs/disclosure --embargo-days 90
# add --notify to draft vendor notifications; --since-days N to filter recent
```
- **Verify**: `docs/disclosure/` populated with per-scanner disclosure drafts.

---

## 11 — Snapshot

```sh
python3 scripts/save_results.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all
# -> results/<timestamp>/ (results.json, results.md, reports, DB copy, bypasses)
```

---

## 12 — Charts (per-step folders)

```sh
python3 scripts/generate_charts.py
# -> charts/<NN>_<step>/*.png (skips any step whose data isn't present yet)
```
- Optional flags: `--db`, `--shelf-db`, `--out charts`, `--manifest`,
  `--oracle-validation`, `--fp-eval`, `--format png|svg`, `--dpi`.
- Requires `matplotlib` (host-only): `python3 -m pip install --user matplotlib`.
- **Verify**: `charts/` contains subfolders `01_crawl` … `08_shelf_life`.

---

## 13 — Notebooks (interactive equivalent)

```sh
python3 -m pip install --user nbformat jupyter-client ipykernel PyYAML huggingface_hub pytest matplotlib
# or: pip install -r notebooks/requirements.txt

# Headless execution (thin subprocess wrappers around every script above)
jupyter nbconvert --to notebook --execute --inplace notebooks/*.ipynb
# or interactively:
jupyter lab notebooks/
```
- Notebook map: `notebooks/README.md` (00 env → 01 crawl → 02/03 oracle →
  04 full campaign / 04b pilot → 05 evaluation → 06 shelf-life →
  07 demo defense / 07b defense eval → 08 snapshot).

---

## One-command reproduction (core path)

```bash
set -e
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
python3 scripts/crawl_benign.py --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering --limit-per-cluster 25 --max-size 134217728 --out-dir data/crawled --scan-cap 20000 --workers 8 --format both
mkdir -p real_benign_corpus/all_pt real_benign_corpus/all_gguf
while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")); ln -f "$f" "real_benign_corpus/all_pt/${cluster}__${repo}.bin" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")); ln -f "$f" "real_benign_corpus/all_gguf/${cluster}__${repo}.gguf" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name "*.gguf")
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 25 --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all_pt --seed-cluster text-generation --pt-corpus-dir real_benign_corpus/all_pt --gguf-corpus-dir real_benign_corpus/all_gguf --attack-families gadget,overwritten,external,indirect_chain,pypi_injected --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42 --format mixed --format-ratio 0.3
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all_pt --seed-cluster text-generation --pt-corpus-dir real_benign_corpus/all_pt --gguf-corpus-dir real_benign_corpus/all_gguf --attack-families gadget,overwritten,external,indirect_chain,pypi_injected --evasion-mode random --fitness-mode current --backend docker --seed 42 --format mixed --format-ratio 0.3
python3 scripts/generate_evaluation_report.py
python3 scripts/demo_task3.py --backend docker
python3 scripts/benchmark_perf.py
python3 scripts/triage_bypasses.py
python3 scripts/crawl_gguf.py
python3 scripts/run_task3_demo.py --backend docker
python3 scripts/insert_gguf_into_campaign.py
python3 scripts/generate_charts.py
python3 scripts/save_results.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all_pt --gguf-corpus-dir real_benign_corpus/all_gguf
```

---

## Artifact verification checklist

| Artifact | Check |
|----------|-------|
| `data/crawled/seed_manifest.json` | `total_models: 304`, formats: pt=179, gguf=125 |
| `real_benign_corpus/all/` | 100 hard links |
| `real_benign_corpus/oracle-split.json` | disjoint train/eval halves |
| `real_benign_corpus/oracle-calibrated/pt/` | model + vectorizer + scaler + blank_baseline + fp-eval |
| `data/regenbench_shadowpickle.db` | 80 valid, 20 bypasses (25.0%) |
| `data/regenbench_campaign.db` | guided-r1 (500/473/223) + unguided-r1 (473/401/74) + gguf-demo |
| `docs/evaluation-report.md` | H1 supported, H2 valid negative, H3 supported |
| `data/shelf_life.db` | 300 bypasses × 6 historical versions |
| `charts/<NN>_<step>/` | PNGs for every step whose data is present |
| `results/<timestamp>/` | full snapshot (reports + DB copy + bypasses) |