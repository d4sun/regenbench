# ReGenBench Quantitative Evaluation & Ablation Report

This report presents the statistically supported answers to our core Research Questions (RQ1-RQ4) and evaluates hypotheses (H1-H3) using the results of our pilot campaigns.

**Data provenance**: campaign database `/tmp/opencode/fuzz_guided.db`; figures not labeled *simulated* are measured from the live pipeline or read from the database.

## RQ1: Robustness of Static Scanners
**Hypothesis H1**: *Directed fuzzing achieves high evasion rates against static scanners compared to published baselines.*

### Evasion Rates and 95% Confidence Intervals
| Scanner | Admitted Candidates | Evasion Count | Evasion Rate | 95% Bootstrap CI |
| :--- | :---: | :---: | :---: | :---: |
| **PickleScan** | 10 | 0 | 0.0% | [0.0%, 0.0%] |
| **Fickling** | 0 | 0 | 0.0% | [0.0%, 0.0%] |

**Verdict on H1**: Not supported on current data: measured evasion rates are below 70%.

---

## RQ2: Search Efficiency
We measured the number of queries/candidates generated before reaching the first confirmed scanner bypass, per campaign replicate (per run_id, ordered by round).
- **Queries-to-First-Bypass**: guided: Q_first per replicate = [13] (censored=1; right-censored at total+1 when no bypass found); unguided: Q_first per replicate = [] (censored=0; right-censored at total+1 when no bypass found); test not run: pairs unequal or too few for a paired test; consider independent Mann-Whitney on replicate Q_first values

---

## RQ3: Oracle Reliability and False-Positive Costs
Consistency between scanners and our dynamic behavior-based oracle (DynaHug).

### Benign False-Positive Cost Evaluation
| Scanner | Benign Models Scanned | False-Positive Detections | False-Positive Rate |
| :--- | :---: | :---: | :---: |
| **PickleScan** | 1 | 0 | 0.0% |
| **Fickling** | 1 | 1 | 100.0% |
| **ModelScan** | 1 | 0 | 0.0% |
| **ModelTracer** | 1 | 0 | 0.0% |
| **DynaHug (Oracle)** | 1 | 1 | 100.0% |

**Ground truth note**: every checkpoint is benign by construction (downloaded from a verified public HuggingFace repository, non-gated, unmodified). Benignness is NOT defined by any detector's verdict.

### Detector Disagreement on Benign Corpus
- Not computed: no benign corpus scan results available.

---

## RQ4: Ablation Studies

### Ablation 1: Efficacy of Coverage-Guided Feedback (T7.6)
Per-replicate results from the campaign DB (each row is one run_id):
| Campaign | Replicate | Valid Candidates | Panel Evasions | Confirmed (Dual-Oracle) | Evasion Yield |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **guided** | 1 | 10 | 0 | 0 | 0.0% |
- **Unguided ablation harness**: mean fitness 2.500, evasion yield 0.0% (measured live, 10 candidates).

### Coverage Breadth Across Rounds (T7.3)
| Round | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: |
| 1 | 0.4264705882352941 | 0.2777777777777778 |
| 2 | 0.4264705882352941 | 0.5 |
- **Growth**: opcode coverage 0.4264705882352941 -> 0.4264705882352941; callable coverage 0.2777777777777778 -> 0.5 from round 1 to round 2.
### Ablation 2: Pre-filtering Throughput Contribution (T7.7)
| Metric | With Static Pre-Filter | Without Pre-Filter | Throughput Speedup |
| :--- | :---: | :---: | :---: |
| **Execution Duration (5 files)** | 0.92s | 15.09s | **16.38x** |

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