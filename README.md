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
> containers. See [`DISCLAIMER.md`](DISCLAIMER.md) before use.
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
| [`notebooks/`](notebooks/README.md) | The same steps as interactive notebooks (thin wrappers around the scripts). |

## Quick start (full detail in `QUICKSTART.md`)

```sh
# 0. Build the scanner panel (docker)
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done

# 1. Crawl 100 real benign checkpoints (5 clusters x 20, resumable, parallel)
python3 scripts/crawl_benign.py \
  --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering \
  --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled \
  --scan-cap 20000 --workers 8

# 2. Link the flat corpus and validate the oracle
mkdir -p real_benign_corpus/all && while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); \
  cluster=$(basename "$(dirname "$(dirname "$f")")"); \
  ln -f "$f" "real_benign_corpus/all/${cluster}__${repo}.bin" 2>/dev/null; \
  done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)

# 3. ShadowPickle baseline + guided/unguided campaigns
python3 scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker
python3 scripts/run_fuzzing_campaign.py --mode guided   --rounds 25 --candidates-per-round 20 \
  --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode adaptive --fitness-mode oracle_aware --backend docker --seed 42
python3 scripts/run_fuzzing_campaign.py --mode unguided --rounds 24 --candidates-per-round 20 \
  --db data/regenbench_campaign.db --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation \
  --attack-families gadget,overwritten,pypi_injected,external,indirect_chain \
  --evasion-mode random --fitness-mode current --backend docker --seed 42

# 4. Results
python3 scripts/generate_evaluation_report.py   # -> docs/evaluation-report.md (regenerable)
# headline numbers: see RESULTS.md
```

## Repository layout

| Path | Contents |
|------|----------|
| `pipeline/` | Core Python: generator, runner, scanners, oracle, fitness, feedback, db, defense, shelf-life |
| `scripts/` | Crawl, campaign, evaluation, calibration, triage, demo, report scripts |
| `containers/` | One buildable image per scanner/oracle (`regenbench/<name>`) |
| `tests/` | Host-only correctness suite (`python3 -m pytest tests/ -x -q`, 171 passed) |
| `notebooks/` | Interactive thin wrappers around every script |
| `data/crawled/` | Crawled real checkpoints + `seed_manifest.json` |
| `real_benign_corpus/` | Flat corpus view + oracle calibration |
| `results/` | `save_results.py` snapshots (`results/<timestamp>/`) |

## Notes

- The host needs no `torch`/`sklearn`; all scanner/oracle dependencies live in
  the containers. Python 3.10+ with `PyYAML` and `huggingface_hub` suffices.
- The campaign DB (`data/regenbench_campaign.db`) is the source of truth for
  `RESULTS.md` and the generated `docs/evaluation-report.md`.