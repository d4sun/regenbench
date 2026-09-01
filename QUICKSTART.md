# ReGenBench — Quickstart Guide

What to do, in order, from a clean checkout. Every step names its command, the
artifact it produces, and how to verify it succeeded. The notebooks in
[`notebooks/`](notebooks/README.md) wrap exactly these commands interactively.
The measured outcomes are in [`RESULTS.md`](RESULTS.md).

Estimated wall time on a machine with `docker` and the built images:
**~1–2 h crawl + ~1.5 h campaigns + ~1 h rescans/eval**.

## 0. Preconditions

```sh
python3 -m pip install --user PyYAML huggingface_hub matplotlib
python3 -m pytest tests/ -x -q                 # 197 passed, 3 skipped expected
docker images | grep regenbench                # base, picklescan, modelscan, fickling, dynahug, gguf
# build if missing:
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
./scripts/verify_host.sh                        # host gate (docker, SELinux :ro,z mount, concurrency)
```

## 1. Crawl 100 real benign models (5 clusters × 20)

```sh
python3 scripts/crawl_benign.py \
  --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering \
  --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled \
  --scan-cap 20000 --workers 8
```
- Produces `data/crawled/<cluster>/<repo>/pytorch_model.bin` +
  `data/crawled/seed_manifest.json`. Resumable; re-running skips existing
  hashes and backfills already-present files.
- **Verify**: `python3 -c "import json; print(json.load(open('data/crawled/seed_manifest.json'))['summary'])"`
  → `total_models: 100`, 5 clusters × 20.

Link the flat corpus (hard links, no copy):

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
- **Verify**: `real_benign_corpus/oracle-split.json` has disjoint cluster-stratified
  `train`/`eval` halves.

## 3. Recalibrate the oracle on this corpus

```sh
python3 scripts/calibrate_oracle.py real_benign_corpus/all \
  --split-file real_benign_corpus/oracle-split.json --split-role train \
  --out real_benign_corpus/oracle-calibrated/current \
  --sample 50 --backend docker --seed 1337 --traces-only
python3 scripts/fit_oracle_sweep.py \
  --traces real_benign_corpus/oracle-calibrated/current/traces.json \
  --export --gamma 0.1 --nu 0.01 \
  --export-dir real_benign_corpus/oracle-calibrated/current --backend docker
```
- **Verify**: `real_benign_corpus/oracle-calibrated/current/` contains
  `oneclass_svm_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, `syscalls.txt`.
  DynaHug stays supplementary; bypass confirmation is execution-gated.

## 4. Campaigns

```sh
# baseline (H1 denominator)
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker

# guided (oracle-aware, adaptive evasion) and unguided (random) — real-corpus seeded
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
- **Verify**: `sqlite3 data/regenbench_campaign.db "SELECT run_id, COUNT(*) FROM candidates GROUP BY run_id;"`
  shows the two fresh runs.

## 5. Evaluation & reports

```sh
python3 scripts/generate_evaluation_report.py          # fast, DB-only -> docs/evaluation-report.md
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all --fp-sample 100   # slow FP/monitor docker scans
python3 scripts/triage_bypasses.py                      # -> docs/triage-report.md
python3 scripts/benchmark_perf.py                       # -> docs/perf-report.md

# GGUF attack surface (format-complexity demo)
python3 scripts/crawl_gguf.py                           # -> data/gguf_benign_corpus/ (24 real GGUFs)
python3 scripts/run_task3_demo.py --backend docker      # -> docs/task3-demo.md (GGUF matrix + FP)
python3 scripts/demo_task3.py --backend docker          # -> docs/demo-report.md (incl. GGUF section)
python3 scripts/insert_gguf_into_campaign.py            # insert GGUF surface as format='gguf' in the DB

# Per-step charts (charts/<NN>_<step>/*.png; skips missing data)
python3 scripts/generate_charts.py
```
- Headline numbers (including GGUF: ggufref 7/10 vs modelscan 0/10, 3
  obfuscated-SSTI confirmed bypasses, FP 0/24)
  are consolidated in [`RESULTS.md`](RESULTS.md).

## 6. Shelf-life rescans (H3)

```sh
python3 -c "from pipeline.shelf_life import register_bypasses_from_campaign_db; register_bypasses_from_campaign_db('data/regenbench_campaign.db')"
for ver in 1.0.4 1.0.3; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:$ver --scanners picklescan --backend docker; done
for ver in 0.8.7 0.8.6; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver --scanners modelscan --backend docker; done
for ver in 0.1.11 0.1.10; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image fickling=regenbench/fickling:$ver --scanners fickling --backend docker; done
sqlite3 data/shelf_life.db "SELECT new_version, total, retained, printf('%.1f%%', retention_rate*100) FROM (SELECT new_version, COUNT(*) total, SUM(evasion_retained) retained, AVG(evasion_retained) retention_rate FROM rescans GROUP BY new_version);"
```

## 7. Snapshot

```sh
python3 scripts/save_results.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all
# -> results/<timestamp>/ (results.json, results.md, reports, DB copy, bypasses)
```

See [`README.md`](README.md) for the overview, [`IMPLEMENTATION.md`](IMPLEMENTATION.md)
for how it works, [`RESULTS.md`](RESULTS.md) for the latest measured numbers, and
[`docs/full-implementation-guide.md`](docs/full-implementation-guide.md) for the
complete step-by-step runbook (including ablations, GGUF, defense, disclosure,
and per-step charts).