# ReGenBench — Documentation Index

What each doc is, and when it matters. Everything else in this repository is
either source (`pipeline/`, `scripts/`, `tests/`, `containers/`, `crates/`) or
data (see `README.md#Saving results`).

## Getting started

| Doc | What it is |
|-----|-----------|
| [`QUICKSTART.md`](QUICKSTART.md) | **Step-by-step "what to do":** ordered commands, what each produces, how to verify. Start here. |
| `../README.md` | Project overview, component map, full reproduction, saving results. |
| `../notebooks/README.md` | The interactive equivalent of QUICKSTART (notebooks wrap the same scripts). |
| `../REPRODUCIBILITY.md` | One-command repro + artifact verification checklist. |
| `../CLAUDE.md` | AI-assistant context: architecture, module map, known bugs, workflow recipe. |

## Design & architecture

| Doc | What it is |
|-----|-----------|
| [`implementation-report.md`](implementation-report.md) | Current implementation documentation: modules, invariants, evaluation setup. |
| [`experiment-plan.md`](experiment-plan.md) | Staged experiment design: pilot/main tiers, RQ1–RQ4, corpus & campaign sizing. |
| [`t0.1-host-spec.md`](t0.1-host-spec.md) | Host prerequisites and verification (`scripts/verify_host.sh`). |
| [`verdict-schema.md`](verdict-schema.md) | Unified scanner/oracle JSON verdict schema. |
| [`oracle-spec.md`](oracle-spec.md) | ExecutionOracle / StraceOracle / DynaHug roles. |
| [`oracle-calibration-deviation.md`](oracle-calibration-deviation.md) | Why the pretrained DynaHug OCSVM is recalibrated on this environment. |
| [`comparison-methodology.md`](comparison-methodology.md) | Caveats for comparing against published ShadowPickle/PickleFuzzer/DynaHug numbers. |
| [`related-works-comparison.md`](related-works-comparison.md) | How ReGenBench relates to the anchoring works. |

## Evaluation results (regenerated from the live DB)

| Doc | What it is |
|-----|-----------|
| [`evaluation-report.md`](evaluation-report.md) | RQ1–RQ4 statistics, hypotheses H1–H3, FP rates. The canonical results doc. |
| [`demo-report.md`](demo-report.md) | Unified Task-3 demo: pipeline walk-through incl. GGUF section. |
| [`perf-report.md`](perf-report.md) | Pre-filter throughput / latency benchmark. |
| [`triage-report.md`](triage-report.md) | Bypass profiles by dangerous callable. |
| [`fuzzing-report-<run>.md`](fuzzing-report-guided-r1.md) | Per-campaign round tables (one per campaign run; regenerated on each run). |
| [`coverage-growth-v2.md`](coverage-growth-v2.md) | Reachable-space coverage measurement and fixes. |
| [`family-diversity-report.md`](family-diversity-report.md) | Per-family bypass diversity target. |
| [`quota-ablation.md`](quota-ablation.md) | Per-round family quotas ablation. |

## Methodology notes (honest framing)

| Doc | What it is |
|-----|-----------|
| [`pre-filter-reconciliation.md`](pre-filter-reconciliation.md) | Pre-filter vs container-panel agreement on benign corpus. |
| [`repair-validation.md`](repair-validation.md) | Defense repair: payload removal + `weights_only=True` loadability. |
| [`repair-failure-triage.md`](repair-failure-triage.md) | Repair escapes (indirect_chain / runstring) — quarantined, not sanitized. |
| [`shelf-life-longitudinal.md`](shelf-life-longitudinal.md) | H3 514×6 100% retention: blind-spot persistence vs patch-resilience. |

## Responsible disclosure

| Doc | What it is |
|-----|-----------|
| [`disclosures/`](disclosures/) | Reproduction notes for each confirmed scanner bypass family. |

## Out-of-scope / removed

Docs that were removed in the 2026-08-31 clean-slate pass (superseded,
archival, or synthetic-corpus-specific): `evaluation-report-v2.md`,
`benign-expansion-100.md`, `synthetic-patch-evaluation.md`,
`implementation-plan.md`, and the pre-fix `fuzzing-report-{guided-r3,guided-r5}.md`.
Their content, where still relevant, lives in the docs above or in git history.

`task3-demo.md` is not maintained in the repo: it is a regenerable standalone
report written by `scripts/run_task3_demo.py` when you run it (the canonical
GGUF section is `demo-report.md#5`).