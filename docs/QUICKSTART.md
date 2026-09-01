# ReGenBench — Quickstart Guide

What to do, in order, from a clean checkout. Every step names its command, the
artifact it produces, and how to verify it succeeded. The notebooks in
`../notebooks/` wrap exactly these commands.

Estimated wall time for the full pipeline on a machine with `docker` and the
built images: **~2 h crawl + ~8–12 h campaigns + ~1.5 h rescans**.

## 0. Preconditions

```sh
python3 -m pip install --user PyYAML huggingface_hub
python3 -m pytest tests/ -x -q                 # 171 passed expected
docker images | grep regenbench                # base, picklescan, modelscan, fickling, dynahug, gguf
# build if missing:
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
```

## 1. Crawl 100 real benign models (5 clusters × 20)

```sh
python3 scripts/crawl_benign.py \
  --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering \
  --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled \
  --scan-cap 20000 --workers 8
```
- Produces `data/crawled/<cluster>/<repo>/pytorch_model.bin` + `data/crawled/seed_manifest.json`.
- **Resumable**: re-run to continue; already-downloaded files are backfilled into the manifest.
- **Verify**: `python3 -c "import json; print(json.load(open('data/crawled/seed_manifest.json'))['summary'])"` → `total_models: 100`.

Link the flat corpus view (hard links, no copy):

```sh
mkdir -p real_benign_corpus/all
while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")"); ln -f "$f" "real_benign_corpus/all/${cluster}__${repo}.bin" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
```
- **Verify**: `ls real_benign_corpus/all | wc -l` → `100`.

## 2. Oracle validation, views, disjoint split

```sh
python3 scripts/validate_oracle.py real_benign_corpus/all --sample 100 \
  --out real_benign_corpus/oracle-validation.json --backend docker
python3 scripts/organize_corpus.py --corpus real_benign_corpus/all \
  --report real_benign_corpus/oracle-validation.json --out real_benign_corpus
python3 scripts/check_oracle_disjointness.py --resplit
```
- **Verify**: `real_benign_corpus/oracle-split.json` has disjoint `train`/`eval` (50/50, cluster-stratified).

## 3. Recalibrate the oracle on this corpus

```sh
python3 scripts/calibrate_oracle.py real_benign_corpus/all \
  --split-file real_benign_corpus/oracle-split.json --split-role train \
  --out real_benign_corpus/oracle-calibrated/current \
  --sample 50 --backend docker --seed 1337
python3 scripts/fit_oracle_sweep.py \
  --traces real_benign_corpus/oracle-calibrated/current/traces.json \
  --export --gamma 0.1 --nu 0.01 \
  --export-dir real_benign_corpus/oracle-calibrated/current
python3 scripts/fp_eval_oracle.py --split real_benign_corpus/oracle-split.json \
  --role eval --out real_benign_corpus/oracle-calibrated/current/fp-eval-eval.json --backend docker
```
- **Verify**: `oracle-calibrated/current/calibration-report.json` shows a non-collapsed score distribution.

## 4. Campaigns

```sh
# baseline (H1 denominator)
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker

# guided (oracle-aware, adaptive evasion) and unguided (random) — seeded from real corpus
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 25 --candidates-per-round 20 \
  --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 --candidates-per-round 20 \
  --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode random --fitness-mode current --backend docker --seed 42
```
- **Verify**: `sqlite3 data/regenbench_campaign.db "SELECT run_id, COUNT(*) FROM candidates GROUP BY run_id;"` shows two fresh runs.

## 5. Evaluation & reports

```sh
python3 scripts/generate_evaluation_report.py            # fast, DB-only -> docs/evaluation-report.md
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all --fp-sample 100     # slow FP/monitor docker scans
python3 scripts/triage_bypasses.py                        # -> docs/triage-report.md
python3 scripts/benchmark_perf.py                         # -> docs/perf-report.md
python3 scripts/demo_task3.py --backend docker           # -> docs/demo-report.md
```

## 6. Shelf-life rescans (H3)

```sh
python3 -c "from pipeline.shelf_life import register_bypasses_from_campaign_db; register_bypasses_from_campaign_db('data/regenbench_campaign.db')"
for ver in 1.0.4 1.0.3; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:$ver --scanners picklescan --backend docker; done
for ver in 0.8.7 0.8.6; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver --scanners modelscan --backend docker; done
for ver in 0.1.11 0.1.10; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image fickling=regenbench/fickling:$ver --scanners fickling --backend docker; done
```

## 7. Snapshot

```sh
python3 scripts/save_results.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all
```

See `../README.md#Full Experiment` for the identical sequence with more
context, and `../notebooks/` for an interactive version.