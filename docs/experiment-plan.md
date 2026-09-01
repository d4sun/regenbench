# ReGenBench Experiment Plan

Staged experiment design driving `config/campaign_config.yaml`. The plan is
pilot-then-scale: prove the harness end-to-end on a bounded run, then run the
publication-strength sizes.

## Tiers

| | Pilot | Main |
|---|---|---|
| Real benign checkpoints | 100 | 600 |
| Guided candidates | 100 (5×20) | 500 (25×20) |
| Unguided candidates | 100 (5×20) | 500 (25×20) |
| Campaign replicates | 2 | 5 |
| Oracle validation sample | 60 | 100 |

## Corpus

Crawled from Hugging Face Hub (real `pytorch_model.bin` checkpoints only —
**no synthetic models**), 5 task clusters × 20 in the pilot:

`text-generation`, `text-classification`, `feature-extraction`,
`token-classification`, `question-answering`

Three populations, all under `real_benign_corpus/`:

| Population | Path | Role |
|---|---|---|
| All | `all/` | every downloaded checkpoint (flat `<cluster>__<repo>.bin`); the RQ3 FP study scans this **full** set |
| Oracle-positive | `oracle_positive/` | DynaHug score > 0 (seed selection only) |
| Oracle-negative | `oracle_negative/` | DynaHug score < 0 (seed selection only) |

Views are hard links built by `scripts/organize_corpus.py` from
`oracle-validation.json`; they never filter the FP study.

## Research questions & hypotheses

| RQ | Question | Measured by |
|----|----------|-------------|
| RQ1 | Does the generator produce high-yield, structurally valid candidates that evade the static panel? | Confirmed-bypass rate vs ShadowPickle baseline |
| RQ2 | Does feedback guidance improve search efficiency? | Guided vs unguided Candidate Bypass Yield (Fisher / z-test) |
| RQ3 | What is the false-positive rate on real benign models? | Full-panel + oracle over `real_benign_corpus/all` |
| RQ4 | Does the static pre-filter add throughput without precision loss? | Pre-filter ablation + detector agreement |

| H | Hypothesis | Verdict basis |
|----|-----------|---------------|
| H1 | Fuzzing improves bypass yield over ShadowPickle baseline | relative improvement, bootstrap CIs |
| H2 | The dual-oracle adds precision (filters false evasions) | uncorroborated == confirmed comparison |
| H3 | Bypasses survive historical scanner versions | shelf-life rescans (retention %) |

## Campaign

- **Seed**: real text-generation checkpoint from the corpus (smallest matching
  file under `--seed-corpus-dir`); never the synthetic CI toy in production runs.
- **Fitness modes** (`scripts/run_fuzzing_campaign.py --fitness-mode`):
  `current`, `oracle_aware`, `oracle_dominant`, `continuous`, `coverage_guided`.
- **Evasion**: `adaptive` (guided feedback picks strategy subsets),
  `random` (unguided ablation), `off` (legacy).
- **Family quotas**: per-round min 15% / max 40% per family, entropy target
  1.5, to keep exploration from collapsing into one family (P1.1).
- **Bypass confirmation**: ExecutionOracle (deterministic trigger polling);
  DynaHug is a supplementary decision-score signal.

## Hypothesis-test protocol

1. Run ShadowPickle baseline (H1 denominator).
2. Run guided + unguided campaigns into one DB.
3. Compute confirmed-bypass rates, bootstrap CIs, two-proportion z / Fisher.
4. RQ3 FP over the full corpus; report honestly (no blending of corpora).
5. Register confirmed bypasses into the shelf-life DB; rescan historical
   scanner images.

All artifacts land in `data/` + `docs/` (see `README.md#Saving results`); the
campaign DB is the source of truth for every report.