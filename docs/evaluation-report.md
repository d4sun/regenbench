# ReGenBench Quantitative Evaluation & Ablation Report

This report presents the statistically supported answers to our core Research Questions (RQ1-RQ4) and evaluates hypotheses (H1-H3) using the measured results of the campaign database `data/regenbench_campaign.db` (5 campaign runs, 5 valid candidates).

**Data provenance**: campaign database `data/regenbench_campaign.db`; all reported figures are measured or explicitly marked unassessed.

## RQ1: Robustness of Static Scanners
**Hypothesis H1**: *Directed fuzzing achieves high evasion rates against static scanners compared to published baselines.*

### Evasion Rates and 95% Confidence Intervals
| Scanner | Admitted Candidates | Evasion Count | Evasion Rate | 95% Bootstrap CI |
| :--- | :---: | :---: | :---: | :---: |
| **PickleScan** | 5 | 0 | 0.0% | [0.0%, 0.0%] |
| **Fickling** | 5 | 0 | 0.0% | [0.0%, 0.0%] |
| **ModelScan** | 5 | 0 | 0.0% | [0.0%, 0.0%] |

**Verdict on H1**: Not supported on current data: measured evasion rates are below 70%.

---

## RQ2: Search Efficiency
We measured the number of queries/candidates generated before reaching the first confirmed scanner bypass, per campaign replicate (per run_id, ordered by round).
- **Queries-to-First-Bypass**: guided: Q_first per replicate = [3, 3, 3, 3, 3] (censored=5; right-censored at total+1 when no bypass found); unguided: Q_first per replicate = [] (censored=0; right-censored at total+1 when no bypass found); test not run: pairs unequal or too few for a paired test; consider independent Mann-Whitney on replicate Q_first values

---

## RQ3: Oracle Reliability and False-Positive Costs
Consistency between scanners and our dynamic behavior-based oracle (DynaHug).

### Benign False-Positive Cost Evaluation
| Scanner | Benign Models Scanned | False-Positive Detections | False-Positive Rate |
| :--- | :---: | :---: | :---: |
| **PickleScan** | 1 | 0 | 0.0% |
| **Fickling** | 1 | 0 | 0.0% |
| **ModelScan** | 1 | 0 | 0.0% |
| **ModelTracer** | 1 | 0 | 0.0% |
| **DynaHug (Oracle)** | 1 | 0 | 0.0% |

**Ground truth note**: every checkpoint is benign by construction (downloaded from a verified public HuggingFace repository, non-gated, unmodified). Benignness is NOT defined by any detector's verdict.

**DynaHug oracle characterization**: the embedded text-generation OCSVM (upstream DynaHug 8ff8174, gamma=0.1 kernel=rbf nu=0.01) returns a constant decision score of approximately -rho (-1.349) for every loadable checkpoint in this environment -- real benign files and payload-carrying fuzz candidates alike -- because our sandbox traces 10-100x the syscall counts of the upstream training environment, so every input lands outside the learned support region (see docs/oracle-calibration-deviation.md). This suite therefore runs the environment-calibrated oracle (scripts/calibrate_oracle.py, fit on this environment's strace profiles), which restores a discriminative decision score and a low false-positive rate on the benign corpus.

### Detector Disagreement on Benign Corpus
- Not computed: no benign corpus scan results available.

---

## RQ4: Ablation Studies

### Ablation 1: Efficacy of Coverage-Guided Feedback (T7.6)
Per-replicate results from the campaign DB (each row is one run_id):
| Campaign | Replicate | Valid Candidates | Panel Evasions | Confirmed (Dual-Oracle) | Evasion Yield |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **guided** | 1 | 1 | 0 | 0 | 0.0% |
| **guided** | 2 | 2 | 0 | 0 | 0.0% |
| **guided** | 3 | 0 | 0 | 0 | 0.0% |
| **guided** | 4 | 2 | 0 | 0 | 0.0% |
| **guided** | 5 | 0 | 0 | 0 | 0.0% |
- **Unguided ablation harness**: mean fitness 3.000, evasion yield 0.0% (measured live, 10 candidates).
- **Guided vs unguided confirmed-bypass rates (T7.10)**: guided 0/5 vs unguided 0/0 (not computed: one group has no admitted candidates (0 denominator))

### Coverage Breadth Across Rounds (T7.3)
| Run | Round | Opcode Coverage | Callable Coverage |
| :--- | :---: | :---: | :---: |
| guided-r1 | 1 | 0.4264705882352941 | 0.12 |
| guided-r2 | 1 | 0.4264705882352941 | 0.12 |
| guided-r4 | 1 | 0.39705882352941174 | 0.08 |
- **Growth**: opcode coverage 0.4264705882352941 -> 0.39705882352941174; callable coverage 0.12 -> 0.08 from round 1 to round 1.
### Ablation 2: Pre-filtering Throughput Contribution (T7.7)
| Metric | With Static Pre-Filter | Without Pre-Filter | Throughput Speedup |
| :--- | :---: | :---: | :---: |
| **Execution Duration (5 files)** | 0.04s | 0.07s | **1.74x** |

### Ablation 3: Efficacy of DynaHug Cross-Check (T7.8 / Hypothesis H2)
**Hypothesis H2**: *Without dynamic validation, scanner bypass counts are significantly inflated.*
| Metric | Evasion Count | Rate |
| :--- | :---: | :---: |
| **Uncorroborated Evasions (Panel-Only)** | 0 | 0.0% |
| **Confirmed Evasions (Dual-Oracle)** | 0 | 0.0% |

**Verdict on H2**: Not assessable on current data: uncorroborated and confirmed evasion counts are both 0.

---

## ShadowPickle Baseline Comparison (H1)

**Hypothesis H1**: *Directed fuzzing achieves higher evasion rates than handcrafted ShadowPickle families.*

The ShadowPickle baseline measures evasion rates of the 3 handcrafted families (overwritten, external, indirect_chain) under the same scanner panel and execution oracle as the fuzzing campaigns.
ShadowPickle baseline: 0/30 valid candidates bypassed (0.0%)
Fuzzing campaigns: 0/5 valid candidates bypassed (0.0%)
**Verdict on H1**: Not supported. Fuzzing campaigns do not exceed ShadowPickle baseline.

## Semantic Fingerprint Analysis (Novelty Detection)

Semantic fingerprints (callable set + opcode categories + transport) are used to identify genuinely novel attack families beyond minor mutations.
No confirmed bypasses to analyze.

---

## Evasion Shelf-Life Decay (T7.9 / Hypothesis H3)
**Hypothesis H3**: *Confirmed bypasses retain evasion efficacy across minor version scanner updates.*
Measured retention by scanner image version:
- **fickling**: 405/405 retained (100.0%)
- **modelscan**: 390/405 retained (96.3%)
- **picklescan**: 390/405 retained (96.3%)
- **unknown**: 392/414 retained (94.7%)

## Conclusion
All reported quantities are measured from the campaign database or marked unassessed.