# ReGenBench Quantitative Evaluation & Ablation Report

This report presents the statistically supported answers to our core Research Questions (RQ1-RQ4) and evaluates hypotheses (H1-H3) using the measured results of the campaign database `data/regenbench_campaign.db` (7 campaign runs, 693 valid candidates).

**Data provenance**: campaign database `data/regenbench_campaign.db`; figures not labeled *simulated* are measured from the live pipeline or read from the database.

## RQ1: Robustness of Static Scanners
**Hypothesis H1**: *Directed fuzzing achieves high evasion rates against static scanners compared to published baselines.*

### Evasion Rates and 95% Confidence Intervals
| Scanner | Admitted Candidates | Evasion Count | Evasion Rate | 95% Bootstrap CI |
| :--- | :---: | :---: | :---: | :---: |
| **PickleScan** | 693 | 0 | 0.0% | [0.0%, 0.0%] |
| **Fickling** | 693 | 0 | 0.0% | [0.0%, 0.0%] |

**Verdict on H1**: Not supported on current data: measured evasion rates are below 70%.

---

## RQ2: Search Efficiency
We measured the number of queries/candidates generated before reaching the first confirmed scanner bypass, per campaign replicate (per run_id, ordered by round).
- **Queries-to-First-Bypass**: guided: Q_first per replicate = [101, 101, 101, 101, 101] (censored=5; right-censored at total+1 when no bypass found); unguided: Q_first per replicate = [101, 101] (censored=2; right-censored at total+1 when no bypass found); test not run: pairs unequal or too few for a paired test; consider independent Mann-Whitney on replicate Q_first values

---

## RQ3: Oracle Reliability and False-Positive Costs
Consistency between scanners and our dynamic behavior-based oracle (DynaHug).

### Benign False-Positive Cost Evaluation
| Scanner | Benign Models Scanned | False-Positive Detections | False-Positive Rate |
| :--- | :---: | :---: | :---: |
| **PickleScan** | 96 | 0 | 0.0% |
| **Fickling** | 96 | 6 | 6.2% |
| **ModelScan** | 96 | 0 | 0.0% |
| **ModelTracer** | 96 | 0 | 0.0% |
| **DynaHug (Calibrated Oracle)** | 96 | 61 | 63.5% |

**Ground truth note**: every checkpoint is benign by construction (downloaded from a verified public HuggingFace repository, non-gated, unmodified). Benignness is NOT defined by any detector's verdict.

**DynaHug oracle characterization**: the embedded text-generation OCSVM (upstream DynaHug 8ff8174, gamma=0.1 kernel=rbf nu=0.01) returns a constant decision score of approximately -rho (-1.349) for every loadable checkpoint in this environment -- real benign files and payload-carrying fuzz candidates alike -- because our sandbox traces 10-100x the syscall counts of the upstream training environment, so every input lands outside the learned support region (see docs/oracle-calibration-deviation.md). This suite therefore runs the environment-calibrated oracle (scripts/calibrate_oracle.py, fit on this environment's strace profiles), which restores a discriminative decision score and a measured 63.5% FP rate on the 96-model benign corpus. RQ3 reports this honestly rather than filtering the corpus by oracle verdict (ground truth is provenance-based).

### Detector Disagreement on Benign Corpus
> **Note (2026-08-19)**: this subsection was computed on a pre-fix FP run in
> which the SELinux mount race intermittently crashed scanner containers
> (reducing the per-pair sample sizes, e.g. "over 8 models"). It is superseded
> by the corrected FP table above and is retained only as an historical
> artifact; treat the pairwise agreement percentages below as unrepresentative.
- **fickling vs dynahug**: agreement 100.0% over 8 models (disagreement 0.0%)
- **fickling vs modelscan**: agreement 0.0% over 8 models (disagreement 100.0%)
- **fickling vs modeltracer**: agreement 0.0% over 5 models (disagreement 100.0%)
- **modelscan vs dynahug**: agreement 0.0% over 90 models (disagreement 100.0%)
- **modelscan vs modeltracer**: agreement 100.0% over 5 models (disagreement 0.0%)
- **modeltracer vs dynahug**: agreement 0.0% over 5 models (disagreement 100.0%)
- **picklescan vs dynahug**: agreement 0.0% over 87 models (disagreement 100.0%)
- **picklescan vs fickling**: agreement 0.0% over 2 models (disagreement 100.0%)
- **picklescan vs modelscan**: agreement 100.0% over 86 models (disagreement 0.0%)
- **picklescan vs modeltracer**: agreement 0.0% over 0 models (disagreement 100.0%)

---

## RQ4: Ablation Studies

### Ablation 1: Efficacy of Coverage-Guided Feedback (T7.6)
Per-replicate results from the campaign DB (each row is one run_id):
| Campaign | Replicate | Valid Candidates | Panel Evasions | Confirmed (Dual-Oracle) | Evasion Yield |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **guided** | 1 | 93 | 0 | 0 | 0.0% |
| **guided** | 1 | 100 | 0 | 0 | 0.0% |
| **guided** | 1 | 100 | 0 | 0 | 0.0% |
| **guided** | 2 | 100 | 0 | 0 | 0.0% |
| **guided** | 3 | 100 | 0 | 0 | 0.0% |
| **unguided** | 1 | 100 | 0 | 0 | 0.0% |
| **unguided** | 2 | 100 | 0 | 0 | 0.0% |
- **Unguided ablation harness**: mean fitness 1.555, evasion yield 0.0% (measured live, 10 candidates).
- **Guided vs unguided confirmed-bypass rates (T7.10)**: guided 0/493 vs unguided 0/200 (not computed: pooled proportion is 0 or 1, standard error is undefined)

### Coverage Breadth Across Rounds (T7.3)
| Run | Round | Opcode Coverage | Callable Coverage |
| :--- | :---: | :---: | :---: |
| guided-r1 | 1 | 0.4411764705882353 | 0.5555555555555556 |
| guided-r1 | 2 | 0.4411764705882353 | 0.7222222222222222 |
| guided-r1 | 3 | 0.4411764705882353 | 0.7777777777777778 |
| guided-r1 | 4 | 0.4411764705882353 | 0.7777777777777778 |
| guided-r1 | 5 | 0.4411764705882353 | 0.7777777777777778 |
| guided-r2 | 1 | 0.4411764705882353 | 0.6111111111111112 |
| guided-r2 | 2 | 0.4411764705882353 | 0.6666666666666666 |
| guided-r2 | 3 | 0.4411764705882353 | 0.7222222222222222 |
| guided-r2 | 4 | 0.4411764705882353 | 0.7222222222222222 |
| guided-r2 | 5 | 0.4411764705882353 | 0.7777777777777778 |
| guided-r3 | 1 | 0.4411764705882353 | 0.3333333333333333 |
| guided-r3 | 2 | 0.45588235294117646 | 0.4444444444444444 |
| guided-r3 | 3 | 0.45588235294117646 | 0.5 |
| guided-r3 | 4 | 0.45588235294117646 | 0.5555555555555556 |
| guided-r3 | 5 | 0.45588235294117646 | 0.6111111111111112 |
| pilot-20260816T030153Z | 1 | 0.4264705882352941 | 0.7222222222222222 |
| pilot-20260816T030153Z | 2 | 0.4264705882352941 | 0.8888888888888888 |
| pilot-20260816T030153Z | 3 | 0.4264705882352941 | 0.8888888888888888 |
| pilot-20260816T030153Z | 4 | 0.4264705882352941 | 0.9444444444444444 |
| pilot-20260816T030153Z | 5 | 0.4264705882352941 | 0.9444444444444444 |
| pilot-20260817T101219Z | 1 | 0.4411764705882353 | 0.3333333333333333 |
| pilot-20260817T101219Z | 2 | 0.45588235294117646 | 0.5555555555555556 |
| pilot-20260817T101219Z | 3 | 0.45588235294117646 | 0.6111111111111112 |
| pilot-20260817T101219Z | 4 | 0.45588235294117646 | 0.6666666666666666 |
| pilot-20260817T101219Z | 5 | 0.45588235294117646 | 0.6666666666666666 |
| unguided-r1 | 1 | 0.4264705882352941 | 0.6666666666666666 |
| unguided-r1 | 2 | 0.4264705882352941 | 0.7222222222222222 |
| unguided-r1 | 3 | 0.4411764705882353 | 0.7777777777777778 |
| unguided-r1 | 4 | 0.4411764705882353 | 0.7777777777777778 |
| unguided-r1 | 5 | 0.4411764705882353 | 0.7777777777777778 |
| unguided-r2 | 1 | 0.4411764705882353 | 0.6666666666666666 |
| unguided-r2 | 2 | 0.4411764705882353 | 0.7777777777777778 |
| unguided-r2 | 3 | 0.4411764705882353 | 0.7777777777777778 |
| unguided-r2 | 4 | 0.4411764705882353 | 0.7777777777777778 |
| unguided-r2 | 5 | 0.4411764705882353 | 0.7777777777777778 |
- **Growth**: opcode coverage 0.4411764705882353 -> 0.4411764705882353; callable coverage 0.5555555555555556 -> 0.7777777777777778 from round 1 to round 5.
### Ablation 2: Pre-filtering Throughput Contribution (T7.7)
| Metric | With Static Pre-Filter | Without Pre-Filter | Throughput Speedup |
| :--- | :---: | :---: | :---: |
| **Execution Duration (5 files)** | 1.03s | 17.47s | **16.92x** |

### Ablation 3: Efficacy of DynaHug Cross-Check (T7.8 / Hypothesis H2)
**Hypothesis H2**: *Without dynamic validation, scanner bypass counts are significantly inflated.*
| Metric | Evasion Count | Rate |
| :--- | :---: | :---: |
| **Uncorroborated Evasions (Panel-Only)** | 0 | 0.0% |
| **Confirmed Evasions (Dual-Oracle)** | 0 | 0.0% |

**Verdict on H2**: Not assessable on current data: uncorroborated and confirmed evasion counts are both 0.

---

## Evasion Shelf-Life Decay (T7.9 / Hypothesis H3)
**Hypothesis H3**: *Confirmed bypasses retain evasion efficacy across minor version scanner updates.*
The following curve is a **simulated** extrapolation from the measured baseline evasion rate (no empirical version-delta data):
- **v1.0 (Baseline)**: 0.0% remaining efficacy *(simulated)*
- **v1.1 (+1 month)**: 0.0% remaining efficacy *(simulated)*
- **v1.2 (+2 months)**: 0.0% remaining efficacy *(simulated)*
- **v1.3 (+3 months)**: 0.0% remaining efficacy *(simulated)*

## Conclusion
The evaluation suite reports measured results only; every simulated or unmeasured quantity is explicitly labeled as such. Re-run the pilot campaign (T6.2) and populate the database before drawing quantitative conclusions.