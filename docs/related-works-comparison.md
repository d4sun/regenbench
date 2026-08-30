# ReGenBench -- Related-Works Comparison

How ReGenBench extends and compares against the three anchoring works, mapped
from the transcribed reference datasets in `reference/` to measured ReGenBench
results. Published numbers are quoted from the papers (see
`reference/published-scanner-metrics.json` and
`reference/published-dynahug-metrics.json`); they are **not re-derived** in
this repository. Scanner version pins differ between the papers and this
repository's containers (see the `scanner_versions_*` blocks in the reference
JSON), so all cross-paper comparisons are **directional**, not numerical
equivalences.

## Summary table

| Work | Their approach | ReGenBench extension | Their result | ReGenBench result | Comparable? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ShadowPickle** (arXiv:2607.17503) | 3 handcrafted families (PyPI-injected, External Module, Overwritten Module) on PickleBench; static + dynamic scanner panel | 5 families (`gadget`, `overwritten`, `external`, `indirect_chain`, `pypi_injected`), grammar-guided + coverage-guided mutation, 11-strategy evasion pipeline, ExecutionOracle confirmation, defense prototype | Mean per-attack TPR across 5 scanners 0.58/0.59/0.37 (Table IV); Fickling F1 0.6791, Weights-only 0.8007, ModelTracer 0.9438 | Baseline replication: 10/40 (25.0%) confirmed bypasses; fuzzing campaigns 47.2% vs 25.0% (H1 relative improvement). **Genuine evasion** (PickleScan 47.2%, ModelScan 62.9%) vs **Rule Absence** (Fickling 100% - no AST rule for IPython.utils.process.system) | Directional. Our containers pin newer versions (picklescan 1.0.x vs paper 0.0.32); both show Fickling saturates (100% / recall 1.0) while the other scanners miss the families |
| **PickleFuzzer** (arXiv:2605.15084) | Grammar-based differential fuzzing across CPython `pickle`, `_pickle`, `pickletools`; 14 discrepancies (13 error, 1 storage); 4 scanner-bypass-critical | Ported opcode taxonomy (`pipeline/opcodes.py`, T3.1), cross-parser disagreement generation (`pipeline/differential.py`, wired behind `differential_prob`) | 14 discrepancies, 4 critical (scanner-bypass); fixes released upstream | Differential operator implemented + unit-exercised but **de-scoped** from the headline campaign in favor of coverage-guided mutation (see Adaptations #4) | Not directly comparable. PickleFuzzer targets *parser implementations*; ReGenBench targets *scanner evasion yield*. The differential operator is available for RQ1 novelty but was not the dominant signal |
| **DynaHug** (arXiv:2604.19438) | Dynamic ML classifier: OCSVM on `strace -c` syscall presence/frequency profiles during `torch.load`; F1 0.9963 on text-generation cluster | DynaHug container (`containers/dynahug`), environment-calibrated OCSVM (`scripts/calibrate_oracle.py`), demoted to supplementary `decision_score` | 0.9963 F1 (text-generation), 1 benign FP / 2025 TN | Environment mismatch: upstream model returns constant `-rho` for all inputs here; calibrated model restores discrimination at 63.5% FP on benign corpus -> ExecutionOracle (0% FP, deterministic) gates confirmation | Not directly comparable. DynaHug's 0.9963 F1 is measured in its own sandbox with its own feature pipeline; ours traces 10-100x more syscalls, moving every input outside the learned support region. The negative result is documented, not hidden |
| **JFrog "Llama Drama"** (CVE-2024-34359) | Jinja2 SSTI in `tokenizer.chat_template` for GGUF/llama.cpp | GGUF builder + reference reader + SSTI render oracle (`pipeline/gguf_tools.py`, `containers/gguf`); 6 vellaveto malformed-header families reproduced | CVE in the wild; vellaveto PoC shows modelscan 0.8.8 misses the header attacks | `docs/task3-demo.md`: modelscan misses all 6 malformed-header families; ggufref oracle flags all 7 (including SSTI side-effect) at FP=0 on real benign GGUFs | Directional. Our ggufref oracle is signature-driven for header families + render-driven for SSTI, matching the reference reader behavior |

## Scanner-version caveat

The papers pin older scanner releases (e.g. ShadowPickle uses picklescan
0.0.32; this repository builds picklescan 1.0.x). Detection deltas across
versions are measured in the H3 shelf-life study (446 bypasses x 6 historical
versions, 100% retention), but no claim is made that a given evasion rate
transfers across versions or datasets.

## What is genuinely new in ReGenBench

1. **Coverage-guided generation with execution-gated confirmation** -- a
   fuzzing loop whose bypass verdicts are confirmed by a deterministic
   trigger-side-effect oracle rather than a statistical anomaly score.
2. **11-strategy static-signature evasion pipeline** applied to real
   scanner-matched rules (GLOBAL->STACK_GLOBAL, nested-loads wrapping, indirect
   callable resolution, payload obfuscation).
3. **A defensive prototype** (`pipeline/sanitizer.py`, `pipeline/repair.py`,
   `pipeline/defense.py`) that statically rewrites supported dangerous pickle
   references, quarantines unrepairable artifacts, and reserializes only
   `weights_only=True`-loadable content inside a container. `pipeline/monitor.py`
   adds load-time syscall, file, and network observation.
4. **The GGUF attack surface** -- a format the pickle-oriented scanners cannot
   see, with a reference-reader oracle.

## Attached related-works note

Any additional papers beyond ShadowPickle, PickleFuzzer, DynaHug, and the
JFrog/vellaveto GGUF advisories are not present in this workspace; if a
specific attached paper should be compared, provide its citation and the
comparison can be added here.
