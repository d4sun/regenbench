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

## 1. Crawl 100 real benign PT + 100 real benign GGUF models (5 clusters × 20 each)

```sh
python3 scripts/crawl_benign.py \
  --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering \
  --limit-per-cluster 25 --max-size 134217728 --out-dir data/crawled \
  --scan-cap 20000 --workers 8 --format both
```
- Produces `data/crawled/<cluster>/<repo>/pytorch_model.bin` (PT) and `data/crawled/<cluster>/<repo>/model.gguf` (GGUF) +
  `data/crawled/seed_manifest.json` with `"format": "pt"` or `"format": "gguf"`. Resumable; re-running skips existing
  hashes and backfills already-present files.
- **Verify**: `python3 -c "import json; print(json.load(open('data/crawled/seed_manifest.json'))['summary'])"`
  → `total_models: 200`, `formats: {"pt": 100, "gguf": 100}`, 5 clusters × 20 each.

Link the flat corpus (hard links, no copy):

```sh
mkdir -p real_benign_corpus/all_pt real_benign_corpus/all_gguf
while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")"); ln -f "$f" "real_benign_corpus/all_pt/${cluster}__${repo}.bin" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")"); ln -f "$f" "real_benign_corpus/all_gguf/${cluster}__${repo}.gguf" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name "*.gguf")
```
- **Verify**: `ls real_benign_corpus/all_pt | wc -l` → `100`; `ls real_benign_corpus/all_gguf | wc -l` → `100`.

## 2. Oracle validation, views, disjoint split (PT + GGUF)

```sh
python3 scripts/validate_oracle.py real_benign_corpus/all_pt --sample 100 \
  --out real_benign_corpus/oracle-validation.json --backend docker --format both
python3 scripts/organize_corpus.py --corpus-pt real_benign_corpus/all_pt \
  --corpus-gguf real_benign_corpus/all_gguf \
  --report real_benign_corpus/oracle-validation.json --out real_benign_corpus
python3 scripts/check_oracle_disjointness.py --resplit
```
- **Verify**: `real_benign_corpus/oracle-split.json` has disjoint cluster- AND format-stratified
  `train`/`eval` halves.

## 3. Recalibrate the oracles on this corpus (PT + GGUF)

```sh
# PT (DynaHug)
python3 scripts/calibrate_oracle.py real_benign_corpus/all_pt \
  --split-file real_benign_corpus/oracle-split.json --split-role train \
  --out real_benign_corpus/oracle-calibrated/pt \
  --sample 50 --backend docker --seed 1337 --traces-only --format pt
python3 scripts/fit_oracle_sweep.py \
  --traces real_benign_corpus/oracle-calibrated/pt/traces.json \
  --export --gamma 0.1 --nu 0.01 \
  --export-dir real_benign_corpus/oracle-calibrated/pt --backend docker --image regenbench/dynahug:latest

# GGUF (ggufref)
python3 scripts/calibrate_oracle.py real_benign_corpus/all_gguf \
  --split-file real_benign_corpus/oracle-split.json --split-role train \
  --out real_benign_corpus/oracle-calibrated/gguf \
  --sample 50 --backend docker --seed 1337 --traces-only --format gguf
python3 scripts/fit_oracle_sweep.py \
  --traces real_benign_corpus/oracle-calibrated/gguf/traces.json \
  --export --gamma 0.1 --nu 0.01 \
  --export-dir real_benign_corpus/oracle-calibrated/gguf --backend docker --image regenbench/gguf:latest
```
- **Verify**: `real_benign_corpus/oracle-calibrated/pt/` and `real_benign_corpus/oracle-calibrated/gguf/` each contain
  `oneclass_svm_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, `syscalls.txt`.
  DynaHug stays supplementary; bypass confirmation is execution-gated.

## 4. Campaigns (dual-format)

```sh
# baseline (H1 denominator) - PT only
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker

# guided (oracle-aware, adaptive evasion) and unguided (random) — real-corpus seeded, dual-format
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 25 --candidates-per-round 20 \
  --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all_pt --seed-cluster text-generation \
  --pt-corpus-dir real_benign_corpus/all_pt --gguf-corpus-dir real_benign_corpus/all_gguf \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --gguf-families ssti_chat_template,nkv_overflow,ntensors_overflow,string_overflow,path_traversal,negative_dims,version_zero,ssti_obfuscated_1,ssti_obfuscated_2,ssti_obfuscated_3 \
  --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42 \
  --format mixed --format-ratio 0.3
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 --candidates-per-round 20 \
  --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all_pt --seed-cluster text-generation \
  --pt-corpus-dir real_benign_corpus/all_pt --gguf-corpus-dir real_benign_corpus/all_gguf \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --gguf-families ssti_chat_template,nkv_overflow,ntensors_overflow,string_overflow,path_traversal,negative_dims,version_zero,ssti_obfuscated_1,ssti_obfuscated_2,ssti_obfuscated_3 \
  --evasion-mode random --fitness-mode current --backend docker --seed 42 \
  --format mixed --format-ratio 0.3
```
- **Verify**: `sqlite3 data/regenbench_campaign.db "SELECT run_id, COUNT(*), SUM(CASE WHEN format='gguf' THEN 1 ELSE 0 END) FROM candidates GROUP BY run_id;"`
  shows the two fresh runs with both PT and GGUF candidates.

## 5. Evaluation & reports

```sh
python3 scripts/generate_evaluation_report.py          # fast, DB-only -> docs/evaluation-report.md
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all_pt --fp-sample 100   # slow FP/monitor docker scans
python3 scripts/triage_bypasses.py                      # -> docs/triage-report.md
python3 scripts/benchmark_perf.py                       # -> docs/perf-report.md

# Per-step charts (charts/<NN>_<step>/*.png; skips missing data)
python3 scripts/generate_charts.py
```
- Headline numbers (including GGUF: ggufref 7/10 vs modelscan 0/10, 3
  obfuscated-SSTI confirmed bypasses, FP 0/24)
  are consolidated in [`RESULTS.md`](RESULTS.md).

## 6. Shelf-life rescans (H3)

```sh
python3 -c "from pipeline.shelf_life import register_bypasses_from_campaign_db; register_bypasses_from_campaign_db('data/regenbench_campaign.db')"
# PT shelf-life
for ver in 1.0.4 1.0.3; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:$ver --scanners picklescan --backend docker; done
for ver in 0.8.7 0.8.6; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver --scanners modelscan --backend docker; done
# GGUF shelf-life (ggufref + modelscan)
for ver in 0.8.7 0.8.6; do python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver --scanners modelscan --backend docker; done
# Note: ggufref historical versions TBD
sqlite3 data/shelf_life.db "SELECT new_version, total, retained, printf('%.1f%%', retention_rate*100) FROM (SELECT new_version, COUNT(*) total, SUM(evasion_retained) retained, AVG(evasion_retained) retention_rate FROM rescans GROUP BY new_version);"
```

## 7. Snapshot

```sh
python3 scripts/save_results.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all_pt --gguf-corpus-dir real_benign_corpus/all_gguf
# -> results/<timestamp>/ (results.json, results.md, reports, DB copy, bypasses)
```

See [`README.md`](README.md) for the overview, [`IMPLEMENTATION.md`](IMPLEMENTATION.md)
for how it works, [`RESULTS.md`](RESULTS.md) for the latest measured numbers, and
[`docs/full-implementation-guide.md`](docs/full-implementation-guide.md) for the
complete step-by-step runbook (including ablations, GGUF, defense, disclosure,
and per-step charts).