# Reference: published scanner metrics (T1.1)

Transcribed baseline numbers for the ReGenBench scanner panel. These figures
are **published results from the cited papers**, not re-derived in this
repository. See [`docs/comparison-methodology.md`](comparison-methodology.md)
for the directional-comparison caveat that applies whenever these are compared
against our own numbers.

Machine-readable copy: [`reference/published-scanner-metrics.json`](../reference/published-scanner-metrics.json).

## Sources

| Paper | arXiv | Tables used |
|---|---|---|
| ShadowPickle: Evading Machine Learning Model Scanners via Stealthy Pickle Deserialization Attacks | arXiv:2607.17503 | IV (RQ1), VI (RQ2), XII (versions) |
| PickleFuzzer: A Case Study in Fuzzing for Discrepancies Between Python Pickle Implementations | arXiv:2605.15084 | I (discrepancies) |

## Scanner versions

Versions as pinned in *ShadowPickle* Table XII (Appendix J):

| Scanner | Version | Commit |
|---|---|---|
| PickleScan | 0.0.32 | `d3273f42` |
| ModelScan | 0.8.7 | `abc4b151` |
| Fickling | 0.1.5 | `8a302e69` |
| Weights-only | 2.9.1 (torch) | `dc48fef6` |
| ModelTracer | 0.0.1 | `5725b26f` |

**Note:** ReGenBench pins newer tool versions (PickleScan v1.0.5, ModelScan
v0.8.8, Fickling v0.1.12, ModelTracer 0.1.0). The published numbers above are
therefore not directly comparable to our runs — comparisons are directional.

## ShadowPickle Table IV — Effectiveness of ShadowPickle on open-source scanners (RQ1)

Corpus (PickleBench): 3,000 benign HF PTMs (top-3000 most-liked,
text-generation task tag) plus 3,000 malicious (1,000 PyPI, 1,000 External
Module, 1,000 Overwritten Module). Injected into top-3600..4600 most-liked
models, with a 600-model contamination interlude.

| Detector | Type | Benign HF flagged | PyPI det. | External det. | Overwritten det. | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PickleScan | Static | 0 | 0 | 0 | 0 | 0 | 0 | 3000 | 3000 | 0 | 0 | 0 |
| ModelScan | Static | 0 | 0 | 0 | 0 | 0 | 0 | 3000 | 3000 | 0 | 0 | 0 |
| Fickling | Static | 2834 | 1000 | 1000 | 1000 | 3000 | 2834 | 166 | 0 | 0.5142 | 1 | 0.6791 |
| Weights-only | Static | 54 | 1000 | 1000 | 39 | 2039 | 54 | 2946 | 961 | 0.9742 | 0.6797 | 0.8007 |
| ModelTracer | Dynamic | 0 | 907 | 953 | 821 | 2681 | 0 | 3000 | 319 | 1 | 0.8937 | 0.9438 |

Per-attack TPR / FNR (mean per-attack detection rate across all five scanners,
i.e. `sum(detections) / (5 scanners × 1000 attacks)`):

| Attack type | TPR | FNR |
|---|---|---|
| PyPI | 0.5814 | 0.4186 |
| External Module | 0.5906 | 0.4094 |
| Overwritten Module | 0.372 | 0.628 |

## ShadowPickle Table VI — ShadowPickle vs SOTA attacks (RQ2)

SOTA attacks: Stacked Pickles (n=5), Library Import (n=1), PickleCloak Module
Surface (n=3), PickleCloak EOP (n=1, "*" crash/failure), PickleCloak
Gadget-Based (n=57). ShadowPickle columns are per-attack detection counts out
of 1,000 each.

| Detector | PyPI | External | Overwritten | PCS Module (3) | PCS EOP (1) | PCS Gadget (57) | Stacked (5) | LibImport (1) |
|---|---|---|---|---|---|---|---|---|
| PickleScan | 0 | 0 | 0 | 0 | 1 | 7 | 5 | 1 |
| ModelScan | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| Fickling | 1000 | 1000 | 1000 | 3 | 1 | 57 | 5 | 1 |
| Weights-only | 1000 | 1000 | 39 | 3 | 1 | 57 | 5 | 1 |
| ModelTracer | 907 | 953 | 821 | 3 | 1 | 45 | 5 | 1 |

Aggregate TPR / FNR:

| Attack | TPR | FNR |
|---|---|---|
| PyPI | 0.5814 | 0.4186 |
| External Module | 0.5906 | 0.4094 |
| Overwritten Module | 0.372 | 0.628 |
| PickleCloak Module Surface | 0.6 | 0.4 |
| PickleCloak EOP | 0.8 | 0.2 |
| PickleCloak Gadget-Based | 0.5824 | 0.4176 |
| Stacked Pickles | 0.8 | 0.2 |
| Library Import | 1.0 | 0.0 |

Headline claim: Overwritten Module is undetected ~50% more than SOTA attacks
(0.372 vs 0.756 TPR on average) and evades the open-source scanners 36.12%
more than PickleCloak (0.72 vs 0.5824).

## PickleFuzzer Table I — pickle-implementation discrepancies

Differential fuzzing of CPython 3.13.0's three pickle implementations
(`pickle` Python, `_pickle` C, `pickletools` disassembler). 14 discrepancies
found by fuzzing (13 in the week-long campaign — most within the first 6
minutes — and 1 in the relaxed-limits 12-hour campaign); 18 total including
manual-analysis findings. All discrepancies involve 1–5 opcodes (avg 2.4).
4 are scanner-bypass-critical (#1, #2, #3, #5): pickletools raises an error
that pickle/_pickle do not, so a pickletools-based scanner (e.g. PickleScan,
ModelScan) can be bypassed. Disclosed to the Python Software Foundation and
huntr.com ($750 bounty); 6 published fixes to date.

| # | Description (condensed) | Manual | Fuzzing | Type | Module | Security | Issue | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | INT/LONG base: pickletools uses base 10, others base 0 | ✓ | ✓ | Error | pickletools | ✓ | [126992](https://github.com/python/cpython/issues/126992) | Fixed |
| 2 | Newline-terminated args ended early by null bytes in _pickle | ✓ | ✓ | Error | _pickle | ✓ | [126996](https://github.com/python/cpython/issues/126996) | Open |
| 3 | pickletools lacks encoding support → invalid byte→str transform | ✓ | ✓ | Error | pickletools | ✓ | [126997](https://github.com/python/cpython/issues/126997) | Fixed |
| 4 | pickletools errors if items left on stack at STOP | ✓ | ✓ | Error | pickletools | ✗ | [127079](https://github.com/python/cpython/issues/127079) | Not Fixed |
| 5 | pickletools errors if memo key set multiple times | ✓ | ✓ | Error | pickletools | ✓ | [123309](https://github.com/python/cpython/issues/123309) | Fixed |
| 6 | _pickle INT decodes argument as bool True/False vs 1/0 | ✓ | ✓ | Storage | _pickle | ✗ | [135241](https://github.com/python/cpython/issues/135241) | Fixed |
| 7 | BINSTRING length > 0x80000000: _pickle positive/valid, others negative/invalid | ✓ | ✗ | Error | _pickle | ✓ | [135321](https://github.com/python/cpython/issues/135321) | Fixed |
| 8 | pickle errors if APPENDS/ADDITEMS precedes MARK on stack | ✓ | ✓ | Error | pickle | ✗ | [135573](https://github.com/python/cpython/issues/135573) | Fixed |
| 9 | PUT arg restrained to ssize_t in _pickle only | ✓ | ✗ | Error | _pickle | ✗ | [144410](https://github.com/python/cpython/issues/144410) | Not Fixed |
| 10 | Large memo indices → Out-Of-Memory in _pickle | ✓ | ✓ | Error | _pickle | ✗ | [115952](https://github.com/python/cpython/issues/115952) | Fixed |
| 11 | NEWOBJ/NEWOBJ_EX arg must be tuple in _pickle only | ✓ | ✓ | Error | _pickle | ✗ | [135579](https://github.com/python/cpython/issues/135579) | Not Fixed |
| 12 | Whitespace in FLOAT arg errors _pickle, not others | ✗ | ✓ | Error | _pickle | ✗ | [135580](https://github.com/python/cpython/issues/135580) | Open |
| 13 | BUILD state: _pickle checks Py_None, others check falsy | ✗ | ✓ | Error | _pickle | ✗ | [128965](https://github.com/python/cpython/issues/128965) | Open |
| 14 | FRAME: _pickle requires n bytes, others up-to-n | ✓ | ✓ | Error | _pickle | ✗ | [128853](https://github.com/python/cpython/issues/128853) | Not Fixed |
| 15 | Opcode+arg split across frames errors in pickle only | ✓ | ✗ | Error | pickle | ✗ | [128853](https://github.com/python/cpython/issues/128853) | Not Fixed |
| 16 | Frames cannot overlap in pickle, can in _pickle | ✓ | ✗ | Error | pickle | ✗ | [128853](https://github.com/python/cpython/issues/128853) | Not Fixed |
| 17 | REDUCE args must be tuple in _pickle only | ✗ | ✓ | Error | _pickle | ✗ | [144412](https://github.com/python/cpython/issues/144412) | Open |
| 18 | BUILD slotstate must be dict in _pickle only | ✗ | ✓ | Error | _pickle | ✗ | [144411](https://github.com/python/cpython/issues/144411) | Open |

Security column notes: Table I marks Security Impact ✓ on #1,2,3,5,7; the
paper's RQ2 text names exactly four scanner-bypass-critical discrepancies
(#1,2,3,5) where pickletools errors while a deserializer succeeds. The extra
✓ on #7 is transcribed verbatim from the table.