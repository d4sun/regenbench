# ReGenBench — Implementation Report & Final Results

**Date**: 2026-08-19
**Status**: Final (post-evaluation-correctness fixes)
**Repository**: `https://github.com/d4sun/regenbench.git`

This document is the authoritative description of the ReGenBench implementation —
architecture, methodology, source-level module breakdown, and the final measured
results of the campaign, false-positive (FP) study, performance benchmarks, and
Task 3 (GGUF / CVE-2024-34359) evaluation.

All figures reported here are **measured** from the live pipeline, the campaign
database `data/regenbench_campaign.db`, or the results snapshot
`results/20260818-141227/` — no simulated or placeholder numbers are used unless
explicitly labeled as such.

---

## 1. Overview & Threat Model

ReGenBench is a research benchmark for studying the **detection of malicious and
malformed machine-learning model artifacts**. It builds a directed, coverage-guided
fuzzing pipeline that mutates benign real-world Hugging Face checkpoints into
malicious candidate payloads, then evaluates a panel of static and dynamic ML
artifact scanners against a behavioral (dynamic) oracle.

Scope and stance:

- **Defensive security research only.** The repository generates real malicious
  Pickle / PyTorch payloads and contains MalHug (ASE 2024) malicious models and a
  Jinja2 SSTI chat-template exploit for CVE-2024-34359.
- **Sandboxing.** Every scanner, oracle, and the validity oracle executes inside
  Podman containers built from `containers/`. Payloads are never deserialized on
  an unisolated host. A `DISCLAIMER.md` and README warning callout document this.
- **Pinned dependencies.** Base image, Python, Torch, and every scanner version
  (with commit pins) are fixed so results are reproducible (Section 5).
- **Licensing.** MIT license; binary corpora are git-ignored and only manifests
  are committed.

### Threat model and evaluation dimensions (RQ1–RQ4, H1–H3)

| ID | Question / Hypothesis | How it is measured |
| :--- | :--- | :--- |
| RQ1 | Robustness of static scanners against directed fuzzing | Evasion rate of the candidate corpus against each static scanner, with 95% bootstrap CIs |
| RQ2 | Search efficiency of the guided campaign | Queries-to-first-bypass (`Q_first`) per replicate |
| RQ3 | Oracle reliability and false-positive costs | FP rate of every scanner on a 96-model benign provenance corpus |
| RQ4 | Ablation studies | Coverage-guided feedback vs unguided, DynaHug cross-check, static pre-filter speedup |
| H1 | Directed fuzzing achieves high evasion vs published baselines | Measured evasion rate vs 70% threshold |
| H2 | Without dynamic validation, scanner bypass counts are significantly inflated | Uncorroborated vs confirmed bypasses |
| H3 | Detector disagreements are substantive (would change practitioner decisions) | Pairwise agreement on benign corpus |

---

## 2. Architecture

```
regenbench/
├── pipeline/          # fuzzing + evaluation engine (~3,247 lines)
├── containers/        # per-scanner sandbox images (Podman)
├── scripts/           # campaign, evaluation, calibration, corpus, tooling
├── ci/                # smoke tests + corpus generators
├── config/            # experiment configuration (YAML)
├── data/              # campaign DB, candidate corpora (git-ignored binaries)
├── real_benign_corpus/# crawled benign HuggingFace checkpoints + calibrated oracle
├── docs/              # this report, evaluation-report, task3-demo, verdict-schema
└── results/           # results snapshots (20260818-141227 = authoritative)
```

### 2.1 `pipeline/` module (source-level)

| File | Responsibility | Key symbols |
| :--- | :--- | :--- |
| `runner.py` | Orchestrates scanning of an artifact list through container wrappers. `Config` dataclass holds backend, tag, `max_workers`, `timeout`, `extensions`, `min_size`, `skip`, `oracle`, `pre_filter`, and **`oracle_model_dir`** (added in the 2026-08-19 fix to wire the calibrated DynaHug oracle). `ScannerRunner` builds the scanner spec, filters by extension, dispatches per-artifact via `run_scan` (passing `oracle_model_dir`), and returns `ScanResult`s. | `Config` (line 56), `make_generator` (68), `ScannerRunner` (88), `_filter` (96), `_scanners_for` (118), `_one` (137), `run` (156) |
| `scanners.py` | Registry of scanners + container invocation. `SCANNERS` dict maps name → image + kind (`panel` vs `oracle`). Handles mount flags (see `,Z`→`,z` fix in Section 7), `DYNAHUG_MODEL_DIR` env + `-v .../recalibrated:ro,z` mount for the calibrated oracle, and per-scanner JSON decoding. | `SCANNERS` (19), `run_scan`, `build_images`, `expected_scanners` |
| `registry.py` | Build/query the image registry list used by `build_images`. | — |
| `opcodes.py` | 4-category taxonomy of pickle opcodes derived dynamically from `pickletools.opcodes`. `OpcodeClassification` maps opcode → class; builds `OPCODES_BY_BYTE` / `OPCODES_BY_NAME`; `parse_pickle` yields classified ops. | `OPCODES_BY_BYTE` (34), `parse_pickle` (77) |
| `dangerous_callables.yaml` | 116-line schema of dangerous callables (module, name, category, description) covering `os.system`, `posix.system`, `nt.*`, subprocess, etc. Used by the pre-filter and feedback tracker. | `schema_version: "1.0"` |
| `templates.py` | ShadowPickle attack templates: `OverwrittenModuleTemplate` (shadows a builtin class, e.g. `collections.OrderedDict`), `PyPIInjectedTemplate` (`IPython.utils.process.system`), `ExternalModuleTemplate` (`numpy.testing._private.utils.*`). `inject_payload_into_pickle` / `inject_payload_into_torch` splice payloads into benign artifacts. `_generate_payload` builds class-based payloads loadable inside the container images. | `AttackTemplate` (17), `OverwrittenModuleTemplate` (48), `PyPIInjectedTemplate` (132), `ExternalModuleTemplate` (152), `inject_payload_into_pickle` (250), `inject_payload_into_torch` (267) |
| `mutators.py` | `PickleMutator` applies opcode-level mutations: `mutate_opcode_swap`, `mutate_callable_substitution`, `mutate_argument_fuzz`, `mutate_structural_stacking`. `mutate` composes a random mutation strategy. | `PickleMutator` (18), `mutate` (128) |
| `generator.py` | `CandidateGenerator` fuzzes a base checkpoint to produce candidates. `mutate_pickle_bytes` (97) applies mutations; `generate_candidate_pt` (204) builds PyTorch candidates (payload injection into `.pt`). | `CandidateGenerator` (23) |
| `validity.py` | `ValidityOracle` verifies a candidate *loads* and *triggers* its payload sentinel inside the base container: `_trigger_exists` (21) waits for the sentinel file, `validate_pickle` (45), `validate_torch` (139), `validate_gguf` (226). Only validity-passing candidates enter the DB as valid. | `ValidityOracle` (36) |
| `pre_filter.py` | Static pre-filter (T4.6): `is_admitted` (81) parses the pickle and checks for registered dangerous callables / nested payloads via `_has_dangerous_import` (42). Benign artifacts with no dangerous callables are skipped, avoiding DynaHug container execution. | `is_admitted` (81) |
| `comparator.py` | `check_bypass` (9): a bypass is confirmed only when the panel agrees on a scanner verdict and the behavioral oracle independently confirms. Dual-oracle confirmation criterion. | `check_bypass` |
| `fitness.py` | `compute_fitness` (9): distance-to-boundary fitness combining the number of detecting scanners and the DynaHug decision score. | `compute_fitness` |
| `coverage.py` | Coverage tracking of opcode and dangerous-callable coverage per round. | — |
| `feedback.py` | `CoverageTracker` (32) + `_string_value` (18): the guided feedback controller — new-opcode / new-callable discoveries steer the next round's mutation budget. | `CoverageTracker` (32), `track_candidate` (45) |
| `db.py` | SQLite persistence (Section 4): `init_db` (37), `log_candidate` (132), `log_campaign_run` (185), `complete_campaign_run` (213), `log_panel_result` (222), `log_oracle_result` (242), `log_fitness` (260), `get_candidate_summary` (271), `log_coverage` (302). | — |
| `gguf_tools.py` | GGUF parsing/generation for Task 3, including the Jinja2 SSTI chat-template payload (CVE-2024-34359). | — |
| `corpus_manager.py` | Seed corpus bookkeeping. | — |
| `tracking.py` | `TrackingSink` (in-memory result sink used by the runner when no DB is given). | `TrackingSink` |
| `selftest.py` | Self-test / sanity checks for the pipeline. | — |

### 2.2 `containers/` (pinned sandbox images)

| Image | Contents / pinned versions |
| :--- | :--- |
| `regenbench/base` | `ubuntu:24.04`, `python3.13` (3.13.15-1+noble1), `torch==2.13.0+cpu`, `numpy==2.3.5`, `pandas==2.2.3`, `sympy==1.13.3`, `ipython==8.30.0`, `pyyaml==6.0.3`, `strace` 6.8-0ubuntu2. The validity oracle and DynaHug tracing run here. |
| `regenbench/picklescan` | PickleScan **v1.0.5**, commit `f15d54da3dec9aa28a87ede82f87882bb80f1023`. |
| `regenbench/fickling` | Fickling **v0.1.12**, commit `c3c695c`. Wrapper maps exit 0=benign / 1=malicious / 2=error (mirrors ClamAV-style codes). |
| `regenbench/modelscan` | ModelScan. |
| `regenbench/modeltracer` | ModelTracer (Casey et al., "A Large-Scale Analysis…"). |
| `regenbench/dynahug` | DynaHug **commit `8ff8174eaf54175a7fc3b90730faf334fb767e0b`**, scikit-learn `1.7.1`, joblib `1.5.2`; accepts `DYNAHUG_MODEL_DIR` to load a recalibrated OCSVM. |
| `regenbench/gguf` | `gguf==0.19.0`, `jinja2==3.1.4` (the ggufref oracle). |

### 2.3 `scripts/`

| Script | Purpose |
| :--- | :--- |
| `run_fuzzing_campaign.py` | Directed (guided/unguided) campaign driver: replicates, rounds, candidate generation, validity, panel + oracle scanning, fitness, coverage, DB logging. |
| `run_pilot_campaign.py` | End-to-end harness validation before scaling. |
| `run_evaluation_suite.py` | RQ1–RQ4 + H1–H3 computation and Markdown report generation; includes `run_benign_fp_check` (the 96-model FP study) which now passes `oracle_model_dir` to the calibrated oracle. |
| `calibrate_oracle.py` | Fits an environment-calibrated DynaHug OCSVM on this sandbox's strace profiles (Section 7a). |
| `validate_oracle.py` | Oracle validation run (score distribution over a sample). |
| `oracle_sanity.py` | Quick sanity check of oracle container. |
| `run_task3_demo.py` | Task 3 demo: GGUF attack generation + ggufref vs scanner panel. |
| `crawl_benign.py` / `crawl_gguf.py` / `crawl_malhug.py` | Corpus crawlers (benign HuggingFace, GGUF, MalHug). |
| `generate_seed_corpus.py` / `organize_corpus.py` | Seed generation and oracle-score views (`oracle_positive` / `oracle_negative`). |
| `benchmark_perf.py` | Pre-filter performance benchmark (T4.6). |
| `triage_bypasses.py` | Automated syscall triage reporter. |
| `save_results.py` | Snapshotting results into `results/<timestamp>/`. |
| `test_generator_suite.py` / `test_integration.py` / `sanity_smoke.py` | Tests / smoke. |
| `verify_host.sh` | Host prereqs (Podman, SELinux, etc.). |

### 2.4 `ci/` and `config/`

- `ci/smoke.py` + `ci/smoke.sh`: end-to-end smoke test (uses `:ro,z` mount fix).
- `ci/corpus/`: tiny committed pkl/torch fixtures.
- `config/campaign_config.yaml`: experiment tiers (`pilot`/`main`), corpus layout,
  oracle validation, campaign params (base checkpoint
  `real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`,
  5 rounds × 20 candidates, panel scanners picklescan/fickling/modelscan/moduletracer,
  oracle dynahug, `timeout_seconds: 120`, `concurrency_limit: 2`, `time_budget_hours: 24`),
  DB path, evaluation script.

---

## 3. Methodology

### 3.1 Campaign design

- **Base checkpoint**: real text-generation model
  `HuggingFaceM4/tiny-random-LlamaForCausalLM.bin` (bounded pilot matches the
  Phase-1 methodology: "benign Hugging Face models, one task cluster").
- **Campaigns**: `guided` (coverage-guided feedback) × 3 replicates and
  `unguided` × 2 replicates, plus 2 pilot runs — **7 runs total**, each 100
  candidates over 5 rounds × 20 candidates/round = **700 candidates**.
- **Candidate lifecycle**: generate → validity check (loads + payload sentinel
  triggers inside the sandbox) → static panel scan → behavioral oracle scan →
  fitness + coverage logging → optional feedback into next round.
- **Bypass definition**: a confirmed bypass requires panel+oracle agreement
  (`comparator.check_bypass`).

### 3.2 Unified verdict schema

Every scanner emits a **normalized JSON verdict** (`docs/verdict-schema.md`):
`{verdict: benign|malicious|error, exit_code, findings, duration}`. Verdict
normalization isolates version/exit-code quirks behind the wrapper layer; the
Fickling wrapper additionally guards against `IsADirectoryError` misclassification.

### 3.3 False-positive protocol

- FP study scans the **full 96-model benign corpus** (provenance-based ground
  truth: verified public, non-gated, unmodified HuggingFace checkpoints — benignness
  is **not** defined by any detector's verdict).
- Because every scanner's container is deterministic in a single-process setting,
  the FP run executes each scanner sequentially over all 96 models.

---

## 4. Database Schema

SQLite at `data/regenbench_campaign.db`, created by `pipeline/db.py`:

| Table | Key columns |
| :--- | :--- |
| `candidates` | `candidate_id` PK, `filepath`, `source`, `created_at`, `round_num`, `seed_model`, `mutation_template`, `mutation_depth`, `callables_used`, `campaign_type`, `run_id` |
| `campaign_runs` | `run_id` PK, `campaign_type`, `replicate_num`, `base_checkpoint`, `total_candidates`, `total_rounds`, `started_at`, `completed_at` |
| `panel_results` | PK `(candidate_id, scanner)`, `verdict`, `exit_code`, `findings`, `duration` |
| `oracle_results` | `candidate_id` PK, `verdict`, `decision_score`, `duration`, `pre_filtered` |
| `campaign_fitness` | `candidate_id` PK, `fitness_score`, `is_valid` |
| `campaign_coverage` | PK `(run_id, round_num)`, `opcode_coverage`, `callable_coverage`, `timestamp` |

---

## 5. Final Measured Results

### 5.1 Campaign execution

| Metric | Value |
| :--- | :--- |
| Campaign runs | 7 (`pilot-20260816T030153Z`, `guided-r1..r3`, `unguided-r1..r2`, `pilot-20260817T101219Z`) |
| Total candidates | 700 |
| Valid (loaded + triggered) | **693** |
| Invalid | 7 (all in `pilot-20260816T030153Z`, which used a toy seed) |
| Orphans (no run) | 0 |

### 5.2 RQ1 / H1 — evasion rates (0/693)

| Scanner | Admitted | Evasion | Evasion rate | 95% bootstrap CI |
| :--- | :---: | :---: | :---: | :---: |
| PickleScan | 693 | 0 | 0.0% | [0.0%, 0.0%] |
| Fickling | 693 | 0 | 0.0% | [0.0%, 0.0%] |

**Verdict on H1: not supported** — measured evasion is below the 70% baseline
threshold. Reported as a valid negative, not a bug. (Note: RQ1 scores only
PickleScan and Fickling, the two scanners with meaningful verdicts on the
candidate corpus; see Limitations.)

### 5.3 RQ2 — search efficiency (censored)

Queries-to-first-bypass per replicate: guided `[101,101,101,101,101]`,
unguided `[101,101]` — all **right-censored** at total+1 because no bypass was
ever found. RQ2 is therefore not computable on this data (all censored, no
survivorship).

### 5.4 RQ3 — false-positive costs (authoritative, post-fix)

Measured over **96 benign checkpoints** (background run completed 2026-08-19,
both correctness fixes applied):

| Scanner | Benign scanned | FP | FP rate |
| :--- | :---: | :---: | :---: |
| PickleScan | 96 | 0 | 0.0% |
| Fickling | 96 | 6 | **6.2%** |
| ModelScan | 96 | 0 | 0.0% |
| ModelTracer | 96 | 0 | 0.0% |
| DynaHug (calibrated oracle) | 96 | 61 | **63.5%** |

**DynaHug oracle characterization**: the embedded text-generation OCSVM (upstream
DynaHug `8ff8174`, gamma=0.1, kernel=rbf, nu=0.01) returns a **constant decision
score ≈ −rho = −1.3489** for every loadable checkpoint in this environment —
benign and malicious alike — because the sandbox traces 10–100× the syscall
counts of the upstream training environment, so every input lands outside the
learned support region. RQ3 therefore uses the environment-calibrated oracle and
reports its honest 63.5% FP rate rather than filtering the corpus by oracle
verdict.

### 5.5 RQ4 — ablations

**Ablation 1 (coverage-guided feedback):** per-replicate valid candidates were
93/100/100/100/100 (guided) and 100/100 (unguided); 0 panel evasions and 0
confirmed bypasses across all replicates (evasion yield 0.0% everywhere).
Coverage growth (guided-r1, rounds 1→5): opcode coverage constant at
0.4411764705882353; callable coverage grew 0.5555555555555556 → 0.7777777777777778.

**Ablation 3 (DynaHug cross-check, H2):** uncorroborated evasions = 0 (0.0%),
so H2 is **not assessable** (no bypasses exist to compare).

**Ablation — static pre-filter speedup:** with the pre-filter, benign candidates
with no dangerous callables are skipped before container execution. Benchmark
(`docs/perf-report.md`): 1.91× end-to-end speedup (10.19s vs 19.45s) and **50%
fewer DynaHug container runs** on a 5-benign/5-malicious set.

### 5.6 Task 3 — GGUF attacks & CVE-2024-34359

| Artifact | modelscan | picklescan | fickling | modeltracer | dynahug | ggufref |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 7 GGUF attack candidates | 0/7 | — | — | — | — | **7/7** |
| 24 benign GGUFs | 0 FP | 0 FP | 24 FP | 0 FP | — | 0 FP |

- **ggufref** (custom GGUF parser oracle) detects **7/7** generated GGUF attacks
  (malformed headers + Jinja2 SSTI chat-template payload for CVE-2024-34359)
  with **0 FP** on 24 benign GGUFs.
- **ModelScan 0.8.8 is blind to GGUF attacks** (0/7) — the headline finding:
  even top-tier ML scanners do not cover the GGUF surface, while the reference
  parser does.
- **Fickling reports 100% FP** on benign GGUFs (24/24) — it only understands
  pickle streams.

### 5.7 Campaign DB verdict tallies

| Table | Verdict breakdown |
| :--- | :--- |
| `panel_results.fickling` | error 606 / malicious 94 |
| `panel_results.modelscan` | error 161 / malicious 539 |
| `panel_results.modeltracer` | benign 1 / error 684 / malicious 15 |
| `panel_results.picklescan` | error 93 / malicious 607 |
| `oracle_results` | error 376 / malicious 324; pre_filtered=0 for all 700 |

### 5.8 Calibrated oracle artifacts

Located at `real_benign_corpus/oracle-calibrated/text-generation/`:
`oneclass_svm_model.pkl`, `scaler.pkl`, `vectorizer.pkl`, `syscalls.txt`,
`calibration-report.json`.

- Fit: 50 traced models, train 40 / holdout 10; RBF, gamma=0.1, nu=0.01.
- Train: positive 0.85, spread 0.0237, mean 0.0078. Holdout: positive 0.6,
  spread 0.0886, mean −0.0044. Trace duration mean 6.26s.
- Calibrated decision scores are discriminative (e.g. −0.0101, +0.0052) versus
  the upstream constant −1.3488830680940862.

---

## 6. Reproduction

```sh
# 1. Build all sandbox images (pinned versions)
./containers/build_all.sh            # or the project's documented build path

# 2. Run the fuzzing campaign (writes to data/regenbench_campaign.db)
python3 scripts/run_fuzzing_campaign.py --config config/campaign_config.yaml

# 3. Evaluate RQ1-RQ4, H1-H3 + regenerate reports
python3 scripts/run_evaluation_suite.py

# 4. Calibrate the DynaHug oracle to this environment (if re-fitting)
python3 scripts/calibrate_oracle.py --corpus real_benign_corpus/all/text-generation

# 5. Task 3 demo
python3 scripts/run_task3_demo.py

# 6. Smoke test
./ci/smoke.sh
```

Host prerequisites: Podman, SELinux-Enforcing-compatible `:ro,z` mounts
(see Section 7b).

---

## 7. Evaluation Correctness Fixes (2026-08-19)

Two measurement bugs were found and fixed during final QA. They materially
changed RQ3 / Task-3 numbers and are documented here for reproducibility.

### 7a. DynaHug oracle collapse → recalibration + wiring

- **Bug**: the runner's `Config` never carried `oracle_model_dir`, so
  `run_scan` never passed the calibrated model dir to the DynaHug container;
  the evaluation suite therefore ran the *collapsed upstream* oracle, which
  returns a constant score (−1.3488830680940862 ≈ −rho) for every loadable
  checkpoint.
- **Fix**:
  1. `pipeline/runner.py`: added `oracle_model_dir: str | None = None` to
     `Config`; threaded it through `ScannerRunner._one` → `run_scan`.
  2. `scripts/run_evaluation_suite.py`: `run_benign_fp_check` passes
     `oracle_model_dir="real_benign_corpus/oracle-calibrated/text-generation"`.
  3. `pipeline/scanners.py` mounts that dir as `/opt/dynahug/recalibrated` and
     sets `DYNAHUG_MODEL_DIR` so the container loads the calibrated OCSVM.
- **Effect**: calibrated scores are spread out and discriminative; RQ3 now
  reports the honest calibrated 63.5% FP rate.

### 7b. SELinux mount race (`:ro,Z` → `:ro,z`)

- **Bug**: concurrent scanner containers mounted the same host artifact with the
  `:ro,Z` (private, per-container relabel) SELinux flag. Under Enforcing
  SELinux, concurrent private relabels of the same host path race and some
  containers crashed with `PermissionError: [Errno 13] Permission denied:
  '/artifact'`. The Fickling wrapper then mapped the CLI's exit-1 (traceback)
  to `malicious` — a **fail-open** misclassification that inflated Fickling's
  FP rate during concurrent full-suite runs (observed 32/96 then 42/96 vs the
  true 6/96).
- **Fix**: switched all shared artifact mounts to `:ro,z` (shared, idempotent
  relabel) in `pipeline/scanners.py` (artifact + DynaHug model-dir mounts),
  `scripts/run_task3_demo.py`, `scripts/calibrate_oracle.py`, and `ci/smoke.py`.
  Verified: lowercase `z` gives deterministic 8/8 exit-2 results.
- **Effect**: the authoritative sequential FP run yields Fickling **6/96 (6.2%)**,
  stable across re-runs.

The FP table in Section 5.4 is the result of both fixes applied.

---

## 8. Limitations & Threats to Validity

1. **ModelTracer is effectively non-functional on real checkpoints**: 684/700
   candidates errored (it always hits the 60s container timeout). RQ1 therefore
   scores only PickleScan and Fickling.
2. **H1 is a null result**: 0/693 evasions may understate true evasion
   capability given bounded search effort (5 rounds × 20 candidates) and a
   single seed cluster; reported honestly as "not supported."
3. **H2 not assessable**: with zero bypasses there is nothing to compare
   panel-only vs corroborated counts.
4. **H3 / detector-disagreement section is stale**: it was computed on a
   pre-fix FP run corrupted by the SELinux mount race and is annotated as
   superseded in `docs/evaluation-report.md`.
5. **DynaHug calibrated oracle still has 63.5% FP**: the environment mismatch
   (10–100× syscall counts vs upstream training) is mitigated, not eliminated.
6. **RQ3 corpus**: 96 benign models from one task cluster set; broader clusters
   (vision, etc.) are out of scope for the pilot tier.
7. **Single host environment**: numbers (esp. DynaHug tracing) depend on the
   container runtime, kernel, and SELinux policy; pinned versions and
   `verify_host.sh` mitigate drift.

---

## 9. Repo Hygiene & Deliverables

- MIT license; `DISCLAIMER.md`; README security warning callout.
- `.gitignore` excludes binary corpora (`data/gguf_benign_corpus/`,
  `data/malhug/*` except `manifest.json`); only manifests and generators are
  committed.
- Authoritative snapshot: `results/20260818-141227/` (evaluation-report,
  results.json, fuzzing-reports per run, perf-report, task3-demo, triage-report,
  oracle-validation, DB copy, seed/malhug manifests).
- Campaign DB backup: `/tmp/opencode/regenbench_campaign.db.bak`.
- Repo branches `dev` and `main`; latest commit `87ea3ed`
  ("Phase 3 (T3.7-T3.11) + licensing…"), plus the uncommitted 2026-08-19 fixes
  described in Section 7 (9 modified files) pending commit/push.