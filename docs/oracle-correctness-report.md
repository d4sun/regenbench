# ReGenBench — Oracle Correctness Report (Phase 4)

**Date**: 2026-08-22
**Status**: Authoritative
**Supersedes**: the DynaHug FP row of `docs/evaluation-report.md` (63.5%) and the calibration claims in `docs/oracle-calibration-deviation.md`

---

## 1. Corpus disjointness (Plan 4.1) — VIOLATION CONFIRMED, FIXED BY RESPLIT

`scripts/check_oracle_disjointness.py` compares every recorded identity of the
calibration trace pool against the 96-model benign FP corpus
(`real_benign_corpus/all`). Evidence (`reference/oracle-disjointness-report.json`):

| Evidence kind | Count | Meaning |
| :--- | :---: | :--- |
| `calibration-holdout-in-fp-corpus` | **4** | models in the recorded calibration holdout list are also scored by the FP study (e.g. `google_reformer-crime-and-punishment`, `concedo_OPT-19M-ChatSalad`, `junnyu_roformer_chinese_sim_char_small`, `EleutherAI_pythia-14m-deduped`) |
| `legacy-validation-sha-in-fp-corpus` | 60/60 | every file byte-traced by the legacy oracle validation reappears in the FP corpus |

The full 40-model *train* membership of the old calibration is not recoverable
from artifacts (the nested corpus layout it walked no longer exists), so the
counts above are a **lower bound**: the fit set demonstrably overlapped the FP
evaluation set. The reported 63.5% FP was therefore measured partly on the
oracle's own training data.

### Resplit

`real_benign_corpus/oracle-split.json` (seed 20260822): strictly disjoint,
cluster-stratified partition of the current flat corpus —

* **train** 48 models {feature-extraction: 20, text-classification: 20, text-generation: 8}
* **eval** 48 models {feature-extraction: 20, text-classification: 20, text-generation: 8}

`calibrate_oracle.py` gained `--split-file/--split-role/--traces-only`; the new
calibration traced only train-half models.

## 2. Hyperparameter re-derivation (Plan 4.2)

`scripts/fit_oracle_sweep.py` fits/sweeps **inside the dynahug container**
(sklearn 1.7.1 / joblib 1.5.2 pinned — same runtime that later joblib-loads the
artifacts), over traces persisted by calibration (`traces.json`; 47 usable).
Grid gamma ∈ {0.01, 0.05, 0.1, 0.5, 1.0} × nu ∈ {0.005, 0.01, 0.02, 0.05},
seeded 38/9 train/holdout split
(`real_benign_corpus/oracle-calibrated/text-generation-v2/hyperparameter-sweep.json`):

| gamma | nu | train positive | holdout positive | holdout spread |
| ---: | ---: | ---: | ---: | ---: |
| **0.01** | **0.05** | **0.947** | **0.778** | **0.213** |
| 0.01 | 0.02 | 0.947 | 0.778 | 0.085 |
| 0.05 | 0.05 | 0.921 | 0.778 | 0.213 |
| 0.1 (upstream) | 0.01 (upstream) | 0.868 | **0.444** | 0.037 |
| 1.0 | 0.005 | 0.763 | 0.000 | 0.016 |

**Conclusion**: the upstream choice `gamma=0.1, nu=0.01` retains only 44% of
held-out benign loads on this environment — the 63.5% figure was *"this specific
untuned choice"*, not a property of the approach. The exported replacement model
(`real_benign_corpus/oracle-calibrated/v2-disjoint`, gamma=0.01, nu=0.05,
fit in-container on train-half traces only) restores discriminative behavior.

## 3. Re-measured false-positive rate on disjoint data

`scripts/fp_eval_oracle.py --model-dir .../v2-disjoint` over the 48 held-out
eval-half models (`v2-disjoint/fp-eval-eval.json`):

| Oracle configuration | Corpus | FP rate | Score distribution (benign loads) |
| :--- | :--- | :---: | :--- |
| Old report: pretrained embedded OCSVM | 96 (collapsed) | ~100% (constant −1.349) | degenerate |
| Old report: v1 calibrated, untuned γ=0.1/ν=0.01 | 96 (**contaminated**) | **63.5%** (61/96) | not published per-model |
| **This report: v2-disjoint, tuned γ=0.01/ν=0.05** | **48 (strictly disjoint)** | **10.4% (5/48)** | median +0.090, mean +0.058, std 0.130, positive rate 89.4%, spread 0.73 |

Remaining FPs: `ibm-granite_granite-embedding-small-english-r2`,
`microsoft_MiniLM-L12-H384-uncased`, `jinaai_jina-embeddings-v2-small-en`,
`ai-guru_lakhclean_mmmtrack_4bars_d-2048`, `monsoon-nlp_hindi-bert`
(1 further artifact errored at load and is excluded from scoring).

**Impact on headline claims (RQ3)**: the qualitative conclusion survives — the
dynamic oracle has a nonzero benign-FP cost that static scanners do not — but
the magnitude changes from **63.5% → 10.4%**, and the earlier number must be
treated as invalid (contaminated split + untuned hyperparameters).

## 4. Feature-space diagnostic (Plan 4.3)

`scripts/diagnose_oracle_features.py`
(`reference/oracle-feature-diagnostics.json`) confirms the fix closes the
domain gap rather than blindly moving the boundary:

* Train-half vs eval-half syscall volume distributions are the **same domain**:
  median ratio 1.00; 89% of eval volumes inside the train [p05, p95] band;
  near-identical top-syscall profiles (newfstatat ≈ 13.4k, read ≈ 2.3k, …).
  Absolute volumes (~25.3k syscalls/load) remain far above upstream's training
  regime — the boundary is now fit *on* this regime.
* The decision score is **not a volume threshold in disguise**: total volume
  spans only ~6% of its median (interpreter startup dominates), and positive
  scores span the volume range (21% of positives ≤ p25 ≈ chance); Spearman
  (volume, score) = +0.35. Discrimination comes from profile shape
  (presence/frequency structure), as intended.

## 5. Decision-score sanity on an untouched third split (Plan 4.4)

The 48-model eval half was touched by neither fitting nor hyperparameter
selection (the sweep's holdout was carved from train-side traces only). Its
score distribution — median +0.090, positive rate 89.4%, std 0.130 — confirms
discriminative behavior on data never used for any tuning decision.

## 6. Constant-score regression guard (Plan 4.5)

`scripts/oracle_sanity.py --batch N` scores a diverse benign batch and fails
loudly (exit 2) if all scores are identical or all negative. Demonstrated:

* **Pretrained embedded oracle** (the Section 7a bug): 8/8 scores = −1.348883,
  spread 0.0 → `COLLAPSE`, exit 2. The guard catches the original bug.
* **v2-disjoint recalibrated oracle**: spread 0.144, positive rate 0.875 →
  `HEALTHY`, exit 0 (`reference/oracle-sanity-batch.json`).

## 7. Reproduction commands

```sh
python3 scripts/check_oracle_disjointness.py --resplit
PYTHONPATH=. python3 scripts/calibrate_oracle.py real_benign_corpus/all \
    --out real_benign_corpus/oracle-calibrated/text-generation-v2 \
    --split-file real_benign_corpus/oracle-split.json --split-role train \
    --traces-only
python3 scripts/fit_oracle_sweep.py \
    --traces real_benign_corpus/oracle-calibrated/text-generation-v2/traces.json
python3 scripts/fp_eval_oracle.py \
    --model-dir real_benign_corpus/oracle-calibrated/v2-disjoint
python3 scripts/diagnose_oracle_features.py \
    --train-traces real_benign_corpus/oracle-calibrated/text-generation-v2/traces.json \
    --eval-traces real_benign_corpus/oracle-traces/eval-half/traces.json \
    --fp-eval real_benign_corpus/oracle-calibrated/v2-disjoint/fp-eval-eval.json
python3 scripts/oracle_sanity.py --batch 8 \
    --model-dir real_benign_corpus/oracle-calibrated/v2-disjoint
```
