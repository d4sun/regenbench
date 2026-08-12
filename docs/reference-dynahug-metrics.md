# Reference: published DynaHug metrics (T1.2)

Transcribed baseline numbers for the ReGenBench behavioral oracle. These are
**published results from the cited paper**, not re-derived here. See
[`docs/comparison-methodology.md`](comparison-methodology.md) for the
directional-comparison caveat.

Machine-readable copy:
[`reference/published-dynahug-metrics.json`](../reference/published-dynahug-metrics.json).

## Source

| Paper | arXiv | Tables used |
|---|---|---|
| Malicious ML Model Detection by Learning Dynamic Behaviors (DynaHug) | arXiv:2604.19438 | 5, 6, 7, 8 |

## Model context

- **Default model:** `text-generation/2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best/OneClassSVM/params-gamma_0.1_kernel_rbf_nu_0.01`
- **Architecture:** One-Class SVM (RBF kernel, γ=0.1, ν=0.01), trained on 2,000 benign PTMs only.
- **Features:** presence + frequency of system calls, extracted from `strace -c` count summary of `torch.load(weights_only=False)` in Docker.
- **Split:** 80:10:10; malicious val/test = half MalHug + half MalHug-injected.

## Table 5 — Per-cluster performance

| Cluster | Benign (real) | Malicious (real + injected) | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| text-generation | 2025 | 25 + 2000 | 2011 | 2024 | 1 | 14 | 0.9995 | 0.9931 | **0.9963** |
| text-classification | 2004 | 4 + 2000 | 1989 | 1976 | 28 | 15 | 0.9861 | 0.9925 | 0.9893 |
| feature-extraction | 2017 | 17 + 2000 | 2007 | 1999 | 18 | 10 | 0.9911 | 0.9950 | 0.9930 |

## Table 6 — DynaHug vs open-source SOTA (text-generation test set, 2025 malignant = 25 Real + 1000 MalHug + 1000 PyPI)

| Detector | Type | Benign HF | Real | MalHug | PyPI | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PickleScan | Static | 0 | 23 | 1000 | 44 | 1067 | 2025 | 0 | 958 | 1.0000 | 0.5269 | 0.6902 |
| ModelScan | Static | 0 | 23 | 1000 | 44 | 1067 | 2025 | 0 | 958 | 1.0000 | 0.5269 | 0.6902 |
| Fickling | Static | 2025 | 25 | 1000 | 1000 | 2025 | 0 | 2025 | 0 | 0.5000 | 1.0000 | 0.6667 |
| ModelTracer | Dynamic | 0 | 25 | 828 | 907 | 1760 | 2025 | 0 | 265 | 1.0000 | 0.8691 | 0.9299 |
| Llama-3.1 | Dynamic+LLM | 1337 | 22 | 993 | 995 | 2010 | 688 | 1337 | 15 | 0.6005 | 0.9926 | 0.7483 |
| GPT-5.2 | Dynamic+LLM | 12 | 20 | 988 | 796 | 1804 | 2013 | 12 | 221 | 0.9933 | 0.8909 | 0.9393 |
| DynaHug (default) | Dynamic | 1 | 25 | 1000 | 986 | 2011 | 2024 | 1 | 14 | 0.9995 | 0.9931 | **0.9963** |

Headline claims: DynaHug is up to **44%** more effective than best static
baselines (0.9963 vs 0.6902), **~5%** better than GPT-5.2, **33%** better
than Llama-3.1.

## Table 7 — Analysis-type ablation (dynamic is ~2x static)

| Analysis type | Detector | Benign HF | Real | Injected | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Static | DynaHug | 2025 | 25 | 2000 | 2025 | 0 | 2025 | 0 | 0.5000 | 1.0000 | 0.6667 |
| Dynamic | DynaHug (default) | 1 | 25 | 1986 | 2011 | 2024 | 1 | 14 | 0.9995 | 0.9931 | **0.9963** |
| Hybrid | DynaHug | 1 | 25 | 1986 | 2011 | 2024 | 1 | 14 | 0.9995 | 0.9931 | **0.9963** |

Hybrid = dynamic (no improvement over dynamic alone).

## Table 8 — Feature-set ablation (frequency is the key feature)

| Feature set | Detector | Benign HF | Real | Injected | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| presence | DynaHug | 0 | 22 | 1664 | 1686 | 2025 | 0 | 339 | 1.0000 | 0.8326 | 0.9086 |
| freq | DynaHug | 1 | 25 | 1986 | 2011 | 2024 | 1 | 14 | 0.9995 | 0.9931 | 0.9963 |
| presence, freq | DynaHug (default) | 1 | 25 | 1986 | 2011 | 2024 | 1 | 14 | 0.9995 | 0.9931 | **0.9963** |
| presence, freq, seq | DynaHug | 33 | 24 | 2000 | 2024 | 1992 | 33 | 1 | 0.9840 | 0.9995 | 0.9917 |
| presence, freq, seq, proc seq | DynaHug | 51 | 24 | 2000 | 2024 | 1974 | 51 | 1 | 0.9754 | 0.9995 | 0.9873 |

## Relevance to ReGenBench

DynaHug Table 6 re-tests our exact four open-source scanners (PickleScan,
ModelScan, Fickling, ModelTracer) on the same MalHug/PyPI-injected runtime
signal. Its F1 for those four (*0.6902 / 0.6902 / 0.6667 / 0.9299*) plus the
LLM baselines (Llama-3.1 *0.7483*, GPT-5.2 *0.9393*) is the reference against
which our panel+oracle runs are compared — **directionally**, per the
methodology note, because versions and corpora differ.