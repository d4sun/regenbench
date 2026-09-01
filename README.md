# ReGenBench

A reproducible benchmark for **ML-artifact scanner evasion**. ReGenBench
generates malicious Pickle / PyTorch candidates from **real benign HuggingFace
checkpoints**, fans them out to a static scanner panel plus a container-sandboxed
execution oracle, and scores them with coverage-guided fuzzing. Every scanner
and oracle runs in an isolated container behind a single verdict schema, so the
whole pipeline is reproducible on any host with `docker`.

> **Security warning**: this is a security-research benchmark. It contains,
> generates, and downloads real malicious and malformed ML artifacts
> (code-executing Pickle/PyTorch checkpoints, real malicious HuggingFace models,
> GGUF malformed-header attacks). Only run artifacts inside the provided
> containers. The `ggufref` SSTI check renders untrusted Jinja2 inside an
> isolated, network-disabled container (`--network none`) with a container-scoped
> `/tmp` tmpfs and no host filesystem access; do not point it at untrusted
> files outside this sandbox configuration. See [`DISCLAIMER.md`](DISCLAIMER.md)
> before use.
>
> **License**: [MIT](LICENSE).

## Architecture (high level)

```
  real benign corpus                malicious candidates              verdicts & feedback
  (100 HF checkpoints)              (.pt bytes)                       (SQLite + reports)
        │                                   │                                 ▲
        ▼                                   ▼                                 │
  CandidateGenerator ───────────►  Runner.run (ThreadPool fan-out) ────────────┘
  pipeline/generator.py               │
  + mutators/templates/evasion        ├─► static panel: picklescan │ fickling │ modelscan
  (benign seed + payload   )          ├─► dynahug oracle (decision_score, supplementary)
                                      └─► ExecutionOracle (container torch.load + trigger poll)
                                              │                                  │
                                              ▼                                  ▼
                                       confirmed bypass?                     FeedbackController
                                       (execution-gated)                    → next-round sampling
```

The loop: generate a candidate from a benign seed → sandbox-load it (did the
payload execute?) → scan it with the static panel → record verdicts, fitness and
coverage → feed the results back into the sampler for the next round.

## What it does

- **Crawls 100 real benign checkpoints** from Hugging Face Hub (5 task clusters
  × 20: text-generation, text-classification, feature-extraction,
  token-classification, question-answering), SHA-256-deduplicated, with
  provenance in `data/crawled/seed_manifest.json`. **No synthetic models.**
- **Generates malicious candidates** from five ShadowPickle-style attack
  families (`gadget`, `overwritten`, `external`, `indirect_chain`,
  `pypi_injected`) plus 11 static-signature evasion strategies.
- **Confirms execution** with a deterministic ExecutionOracle
  (container-sandboxed `torch.load` + trigger-sentinel polling / strace),
  not a statistical oracle — 0% false positives on the benign corpus.
- **Scores with coverage-guided fuzzing**: per-round family quotas, novelty +
  coverage feedback, 5 fitness modes (guided ablation vs uniform-random).
- **Scans a GGUF attack surface** (format-complexity demo, not a
  scanner-robustness claim): 10 GGUF attack families (Jinja2 SSTI
  `chat_template` + 6 malformed-header + 3 obfuscated-SSTI) via an isolated
  `ggufref` reference oracle; modelscan misses all 10 (no GGUF rules), and the
  oracle has 0% FP on 24 real TinyLlama/llama.cpp GGUFs. See
  [`RESULTS.md`](RESULTS.md#gguf-attack-surface-format-complexity-demo).
- **Measures the three hypotheses**: H1 fuzzing-vs-baseline evasion, H2
  dual-oracle precision, H3 shelf-life retention across historical scanner
  versions.

## Docs

| Doc | What it is |
|-----|-----------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Deep-dive: pipeline / container / lifecycle diagrams, DB schema, module map, invariants. |
| [`IMPLEMENTATION.md`](IMPLEMENTATION.md) | How each module works: generator, runner, scanners, oracle, fitness, feedback, defense, shelf-life, campaign design. |
| [`RESULTS.md`](RESULTS.md) | The fresh-run campaign results (guided vs unguided, per-scanner evasion, H1–H3, FP rates). |
| [`QUICKSTART.md`](QUICKSTART.md) | Step-by-step "what to do" with exact commands and verification. |
| [`docs/full-implementation-guide.md`](docs/full-implementation-guide.md) | The complete step-by-step runbook: every command, artifact, and verification, plus per-step chart generation. |
| [`notebooks/`](notebooks/README.md) | The same steps as interactive notebooks (thin wrappers around the scripts). |

## Steps (full implementation, step by step)

Run the steps in order from a clean checkout. Each step's commands, the
artifacts they produce, and how to verify them are detailed below; the same
commands with verification output are in
[`docs/full-implementation-guide.md`](docs/full-implementation-guide.md), and
the interactive (notebook) version is in [`notebooks/`](notebooks/README.md).
Estimated wall time with `docker` + built images: **~1–2 h crawl + ~1.5 h
campaigns + ~1 h rescans/eval**.

### Step 0 — Preconditions (host + containers)

```sh
python3 -m pip install --user PyYAML huggingface_hub pytest matplotlib
python3 -m pytest tests/ -x -q          # 201 passed, 3 skipped expected
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
docker images | grep regenbench         # base, picklescan, modelscan, fickling, modeltracer, dynahug, gguf
./scripts/verify_host.sh                # docker, SELinux :ro,z mount, concurrency gate
```

### Step 1 — Crawl the 100-model real corpus

```sh
python3 scripts/crawl_benign.py \
  --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering \
  --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled \
  --scan-cap 20000 --workers 8
mkdir -p real_benign_corpus/all && while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); \
  cluster=$(basename "$(dirname "$(dirname "$f")")"); \
  ln -f "$f" "real_benign_corpus/all/${cluster}__${repo}.bin" 2>/dev/null; \
  done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
```

### Step 2 — Oracle validation, views, disjoint split

```sh
python3 scripts/validate_oracle.py real_benign_corpus/all --sample 100 \
  --out real_benign_corpus/oracle-validation.json --backend docker
python3 scripts/organize_corpus.py --corpus real_benign_corpus/all \
  --report real_benign_corpus/oracle-validation.json --out real_benign_corpus
python3 scripts/check_oracle_disjointness.py --resplit
```

### Step 3 — Recalibrate the oracle

```sh
python3 scripts/calibrate_oracle.py real_benign_corpus/all \
  --split-file real_benign_corpus/oracle-split.json --split-role train \
  --out real_benign_corpus/oracle-calibrated/current \
  --sample 50 --backend docker --seed 1337 --traces-only
python3 scripts/fit_oracle_sweep.py \
  --traces real_benign_corpus/oracle-calibrated/current/traces.json \
  --export --gamma 0.1 --nu 0.01 \
  --export-dir real_benign_corpus/oracle-calibrated/current --backend docker
python3 scripts/fp_eval_oracle.py --split real_benign_corpus/oracle-split.json \
  --role eval --out real_benign_corpus/oracle-calibrated/current/fp-eval-eval.json --backend docker
```

### Step 4 — Baseline & fuzzing campaigns

```sh
# 4a. ShadowPickle baseline (H1 denominator)
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker

# 4b. Full guided (oracle-aware, adaptive) + unguided (random) campaigns
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

# 4c. Pilot (fast) — add --validity-debug for full sandbox tracebacks
python3 scripts/run_pilot_campaign.py --quick \
  --attack-families gadget,overwritten,external,indirect_chain,pypi_injected

# 4d. 5x5 fitness ablation + analysis
bash run_fitness_ablation_experiment.sh
python3 scripts/analyze_fitness_ablation.py --db data/regenbench_campaign.db \
  --json results/fitness_ablation_results.json

# 4e. Oracle-dominant validation
bash run_oracle_dominant_validation.sh

# 4f. Parallel ablation (multiple fitness modes / seeds / workers)
python3 scripts/run_parallel_ablation.py --max-workers 4 --rounds 5 \
  --candidates-per-round 20 --seeds 1337 1338 1339 1340 1341 \
  --fitness-modes current oracle_aware oracle_dominant --backend docker \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation
```

### Step 5 — Evaluation & reports

```sh
python3 scripts/generate_evaluation_report.py          # fast, DB-only -> docs/evaluation-report.md
python3 scripts/run_evaluation_suite.py --db data/regenbench_campaign.db \
  --corpus-dir real_benign_corpus/all --fp-sample 100 --defense   # FP + monitor + repair metrics
python3 scripts/triage_bypasses.py                      # -> docs/triage-report.md
python3 scripts/benchmark_perf.py                       # -> docs/perf-report.md
python3 scripts/run_known_answers.py                    # known-answer regression checks
```

### Step 6 — GGUF attack surface (format-complexity demo)

```sh
python3 scripts/crawl_gguf.py                           # -> data/gguf_benign_corpus/ (24 real GGUFs)
python3 scripts/run_task3_demo.py --backend docker      # -> docs/task3-demo.md (matrix + FP)
python3 scripts/demo_task3.py --backend docker          # -> docs/demo-report.md (incl. defense + GGUF)
python3 scripts/insert_gguf_into_campaign.py            # insert GGUF surface as format='gguf' in the DB
```

### Step 7 — Shelf-life rescans (H3)

```sh
python3 -c "from pipeline.shelf_life import register_bypasses_from_campaign_db; register_bypasses_from_campaign_db('data/regenbench_campaign.db')"
for ver in 1.0.4 1.0.3; do python3 scripts/shelf_life_rescan.py \
  --db data/regenbench_campaign.db --image picklescan=regenbench/picklescan:$ver \
  --scanners picklescan --backend docker; done
for ver in 0.8.7 0.8.6; do python3 scripts/shelf_life_rescan.py \
  --db data/regenbench_campaign.db --image modelscan=regenbench/modelscan:$ver \
  --scanners modelscan --backend docker; done
for ver in 0.1.11 0.1.10; do python3 scripts/shelf_life_rescan.py \
  --db data/regenbench_campaign.db --image fickling=regenbench/fickling:$ver \
  --scanners fickling --backend docker; done
```

### Step 8 — Differential / cross-parser disagreement (optional RQ1)

```sh
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 5 \
  --candidates-per-round 20 --replicate 1 --db data/regenbench_campaign.db \
  --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,external,indirect_chain,pypi_injected \
  --evasion-mode adaptive --fitness-mode oracle_aware --backend docker \
  --differential-prob 0.1 --seed 42
```

### Step 9 — Disclosure report

```sh
python3 scripts/generate_disclosure_report.py --db data/regenbench_campaign.db \
  --output-dir docs/disclosure --embargo-days 90
```

### Step 10 — Charts (per-step folders)

```sh
python3 scripts/generate_charts.py
# -> charts/<NN>_<step>/*.png (skips any step whose data isn't present yet)
```

### Step 11 — Snapshot

```sh
python3 scripts/save_results.py --db data/regenbench_campaign.db --corpus-dir real_benign_corpus/all
# -> results/<timestamp>/ (results.json, results.md, reports, DB copy, bypasses)
```

Headline results for the latest measured run are in
[`RESULTS.md`](RESULTS.md); a one-command reproduction of the core path is in
[`docs/full-implementation-guide.md`](docs/full-implementation-guide.md).

## Repository layout

| Path | Contents |
|------|----------|
| `pipeline/` | Core Python: generator, runner, scanners, oracle, fitness, feedback, db, defense, shelf-life |
| `scripts/` | Crawl, campaign, evaluation, calibration, triage, demo, report scripts |
| `containers/` | One buildable image per scanner/oracle (`regenbench/<name>`) |
| `tests/` | Host-only correctness suite (`python3 -m pytest tests/ -x -q`, 201 passed) |
| `notebooks/` | Interactive thin wrappers around every script |
| `data/crawled/` | Crawled real checkpoints + `seed_manifest.json` |
| `real_benign_corpus/` | Flat corpus view + oracle calibration |
| `charts/` | Per-step PNG charts from `scripts/generate_charts.py` (gitignored, regenerable) |
| `results/` | `save_results.py` snapshots (`results/<timestamp>/`) |

## Notes

- The host needs no `torch`/`sklearn`; all scanner/oracle dependencies live in
  the containers. Python 3.10+ with `PyYAML` and `huggingface_hub` suffices
  (`matplotlib` additionally, for `scripts/generate_charts.py`).
- The campaign DB (`data/regenbench_campaign.db`) is the source of truth for
  `RESULTS.md` and the generated `docs/evaluation-report.md`.