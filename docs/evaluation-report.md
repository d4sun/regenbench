# ReGenBench Quantitative Evaluation & Ablation Report

This report presents the statistically supported answers to our core Research Questions (RQ1-RQ4) and evaluates hypotheses (H1-H3) using the results of our pilot campaigns.

**Data provenance**: campaign database `data/regenbench_campaign.db`; figures not labeled *simulated* are measured from the live pipeline or read from the database.

## RQ1: Robustness of Static Scanners
**Hypothesis H1**: *Directed fuzzing achieves high evasion rates against static scanners compared to published baselines.*

### Evasion Rates and 95% Confidence Intervals
| Scanner | Admitted Candidates | Evasion Count | Evasion Rate | 95% Bootstrap CI |
| :--- | :---: | :---: | :---: | :---: |
| **PickleScan** | 21 | 0 | 0.0% | [0.0%, 0.0%] |
| **Fickling** | 21 | 0 | 0.0% | [0.0%, 0.0%] |

**Verdict on H1**: Not assessable: no campaign data in the database, so evasion rates are 0/unmeasured.

---

## RQ2: Search Efficiency
We measured the number of queries/candidates generated before reaching the first confirmed scanner bypass.
- **Queries-to-First-Bypass**: requires per-candidate ordering in the campaign DB; not currently extracted.
- **Wilcoxon Signed-Rank Test**: Not implemented: would require per-candidate guided-vs-unguided query counts from the campaign DB; no hardcoded p-value is reported.

---

## RQ3: Oracle Reliability and False-Positive Costs
Consistency between scanners and our dynamic behavior-based oracle (DynaHug).

### Benign False-Positive Cost Evaluation
| Scanner | Benign Models Scanned | False-Positive Detections | False-Positive Rate |
| :--- | :---: | :---: | :---: |
| **PickleScan** | 1 | 0 | 0.0% |
| **Fickling** | 1 | 0 | 0.0% |
| **DynaHug (Oracle)** | 1 | 0 | 0.0% |

Note: the FP check currently scans a single benign checkpoint; the rates above are pass/fail indicators, not population rates.

---

## RQ4: Ablation Studies

### Ablation 1: Efficacy of Coverage-Guided Feedback (T7.6)
| Condition | Mean Fitness Score | Evasion Yield |
| :--- | :---: | :---: |
| **Guided Fuzzing (Feedback On)** | see campaign DB | 0.0% |
| **Unguided Fuzzing (Feedback Off)** | 0.000 | 0.0% |
### Ablation 2: Pre-filtering Throughput Contribution (T7.7)
| Metric | With Static Pre-Filter | Without Pre-Filter | Throughput Speedup |
| :--- | :---: | :---: | :---: |
| **Execution Duration (5 files)** | 0.47s | 0.49s | **1.04x** |

### Ablation 3: Efficacy of DynaHug Cross-Check (T7.8 / Hypothesis H2)
**Hypothesis H2**: *Without dynamic validation, scanner bypass counts are significantly inflated.*
| Metric | Evasion Count | Rate |
| :--- | :---: | :---: |
| **Uncorroborated Evasions (Panel-Only)** | 0 | 0.0% |
| **Confirmed Evasions (Dual-Oracle)** | 0 | 0.0% |

**Verdict on H2**: Not assessable: no campaign data in the database.

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