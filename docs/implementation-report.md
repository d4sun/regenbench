# RegenBench — Comprehensive Implementation Documentation

**Branch**: dev  
**Generated**: 2026-08-28  
**Version**: v1.0-dev

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Methodology & Hypothesis](#2-methodology--hypothesis)
3. [File-by-File Implementation Description](#3-file-by-file-implementation-description)
   - [Core Pipeline Modules](#31-core-pipeline-modules)
   - [Scanner/Container Infrastructure](#32-scannercontainer-infrastructure)
   - [Experiment & Evaluation Scripts](#33-experiment--evaluation-scripts)
   - [Data & Corpus](#34-data--corpus)
   - [Rust Performance Components](#35-rust-performance-components)
   - [Configuration & Reference Data](#36-configuration--reference-data)
   - [Container Definitions](#37-container-definitions)
   - [Documentation & Reports](#38-documentation--reports)
4. [Evaluation Mechanism](#4-evaluation-mechanism)
5. [Evaluation Results](#5-evaluation-results)
6. [Architecture & Data Flow](#6-architecture--data-flow)

---

## 1. System Overview

**RegenBench** is a reproducible benchmark harness for security scanning of machine-learning model artifacts. It systematically generates malicious pickle/PyTorch candidates from benign seeds, subjects them to a panel of static scanners and a behavioral oracle (DynaHug), and quantifies scanner evasion rates, false-positive costs, and the efficacy of coverage-guided fuzzing.

**Core capabilities**:
- Candidate generation from benign seeds via opcode-level mutation and ShadowPickle attack templates
- Signature-evasion pipeline (stack_global_encoding, indirect_chain, payload_obfuscation, nested_loads_wrap, and more)
- Dual-oracle bypass confirmation (static panel + DynaHug behavioral oracle)
- Coverage-guided feedback loop with adaptive mutation weighting
- Quantitative evaluation suite: FP rates, ablations, bootstrap CIs, statistical significance tests
- Shelf-life tracking for confirmed bypasses across scanner version updates

**Scanner panel** (static analysis):
| Scanner | Container | Target |
|---------|-----------|--------|
| PickleScan | `regenbench/picklescan` | Pickle-based attack patterns |
| ModelScan | `regenbench/modelscan` | ML model security issues |
| Fickling | `regenbench/fickling` | Pickle deserialization risks |
| ModelTracer | `regenbench/modeltracer` | Dynamic syscall tracing |

**Behavioral oracle**:
| Oracle | Container | Target |
|--------|-----------|--------|
| DynaHug | `regenbench/dynahug` | Behavioral analysis via syscall profiling + OCSVM |
| ggufref | `regenbench/gguf` | GGUF reference parser (Task 3) |

---

## 2. Methodology & Hypothesis

### Research Questions

| RQ | Question |
|----|----------|
| **RQ1** | Robustness of static scanners: can directed fuzzing achieve high evasion rates? |
| **RQ2** | Search efficiency: how many queries before first confirmed bypass? |
| **RQ3** | Oracle reliability and false-positive costs on real benign corpora |
| **RQ4** | Ablation studies: guided vs unguided, pre-filter throughput, DynaHug cross-check efficacy |

### Hypotheses

| Hypothesis | Statement | Status |
|------------|-----------|--------|
| **H1** | *Directed fuzzing achieves high evasion rates against static scanners compared to published baselines.* | **Not supported** on current data: measured evasion rates are below 70% (0% across all static scanners in the baseline snapshot) |
| **H2** | *Without dynamic validation, scanner bypass counts are significantly inflated.* | **Not assessable**: uncorroborated and confirmed evasion counts are both 0 in the baseline; dynamic validation does not inflate counts when no evasions exist |
| **H3** | *Confirmed bypasses retain evasion efficacy across minor version scanner updates.* | **Unassessed**: no empirical version-delta rescans recorded; simulated decay curve placeholder only |

### Experimental Design

**Phase-1 methodology elements**:
1. **Benign models, one task cluster**: campaigns seed from real HuggingFace checkpoints in the `text-generation` cluster
2. **Candidate generation**: mutate benign pickle streams with opcode swaps, callable substitutions, argument fuzzing, structural stacking, and ShadowPickle attack templates
3. **Static scanner panel**: PickleScan, ModelScan, Fickling, ModelTracer (where capable)
4. **Dual-oracle confirmation**: panel verdicts corroborated against DynaHug behavioral oracle
5. **Bounded pilot time budget**: 24-hour budget per campaign, early termination with corrected totals
6. **Replicated campaigns**: guided and unguided modes, multiple replicates for statistical power

### Attack Families

| Family | Description | Template |
|--------|-------------|----------|
| `gadget` | Dangerous-callable GLOBAL/REDUCE injection into benign pickle stream | Generator's `mutate_pickle_bytes` |
| `overwritten` | ShadowPickle: overwrite a standard module (e.g. `collections.OrderedDict`) with malicious shadow that execs payload in `__new__` | `OverwrittenModuleTemplate` |
| `pypi_injected` | ShadowPickle: import a third-party PyPI callable (default `IPython.utils.process.system`) that naturally executes code | `PyPIInjectedTemplate` |
| `external` | ShadowPickle: import an existing built-in callable (default `numpy.testing._private.utils.runstring`) to execute code | `ExternalModuleTemplate` |
| `indirect_chain` | Stealth: resolve sink through `builtins.__import__` + `builtins.getattr` chain, never naming the dangerous pair in any GLOBAL operand | `IndirectChainTemplate` / `IndirectChain` evasion |

### Evasion Strategies (Phase 1)

| Strategy | ID | Targets | Mechanism |
|----------|-----|---------|-----------|
| StackGlobalEncoding | `stack_global_encoding` | picklescan, modelscan, fickling | Rewrite GLOBAL/INST to STACK_GLOBAL (proto-4 SHORT_BINUNICODE pushes) |
| NestedLoadsWrap | `nested_loads_wrap` | picklescan, modelscan, fickling | Wrap stream in `_pickle.loads(BINBYTES(<stream>))` |
| PayloadObfuscation | `payload_obfuscation` | picklescan, modelscan | Hide trigger strings inside nested loads(BINBYTES(inner)) |
| IndirectChain | `indirect_chain` | picklescan, modelscan, fickling | Resolve sink via builtins.__import__ + builtins.getattr |
| OpcodeReordering | `opcode_reordering` | picklescan | Shuffle independent BUILD/APPEND/SETITEM blocks |
| DeadCodeInjection | `dead_code_injection` | picklescan | Inject MARK/POP no-op sequences |
| StringEncodingVariants | `string_encoding_variants` | picklescan | Alternate string encoding opcodes (SHORT_BINUNICODE/BINUNICODE/UNICODE) |
| ProtocolDowngrade | `protocol_downgrade` | picklescan | Downgrade proto 4/5 to proto 2 |
| AttributeMasking | `attribute_masking` | modelscan | (placeholder) attribute-name masking |
| ModuleAliasing | `module_aliasing` | modelscan | Use module alias paths for dangerous imports |
| NestedLoadObfuscation | `nested_load_obfuscation` | modelscan | Double-wrap nested loads |

**Application order** (`PIPELINE_ORDER`): payload_obfuscation → string_encoding_variants → indirect_chain → stack_global_encoding → module_aliasing → opcode_reordering → dead_code_injection → protocol_downgrade → attribute_masking → nested_load_obfuscation → nested_loads_wrap

---

## 3. File-by-File Implementation Description

### 3.1 Core Pipeline Modules

#### `pipeline/__init__.py`
Package init exposing all public pipeline modules: scanners, runner, tracking, selftest, templates, opcodes, registry, generator, mutators, validity, pre_filter, db, comparator, fitness, feedback, corpus_manager.

#### `pipeline/opcodes.py` (T3.1)
**Pickle opcode taxonomy and parser.**

Dynamically constructs a 4-category taxonomy from `pickletools.opcodes`:
- `NO_ARG` — opcodes with no arguments (STOP, POP, MARK, REDUCE, BUILD, etc.)
- `FIXED_ARG` — opcodes with fixed-width arguments (BININT1/2/4, BINFLOAT, FRAME, etc.)
- `LENGTH_PREFIXED` — opcodes with length-prefixed payloads (SHORT_BINUNICODE, BINBYTES, STRING, etc.)
- `DELIMITED` — newline-delimited literals (GLOBAL, INST, INT, FLOAT, STRING, etc.)

**Key functions**:
- `parse_pickle(data: bytes) -> list[tuple[OpcodeClassification, bytes]]` — parses raw pickle bytes into classified opcode/argument tuples. Handles all four categories, including the special two-field GLOBAL/INST parsing and nested payload recursion.
- `OPCODES_BY_BYTE: dict[bytes, OpcodeClassification]` — 256-entry lookup by opcode byte
- `OPCODES_BY_NAME: dict[str, OpcodeClassification]` — lookup by opcode name

**Reconstruction invariant**: `b"".join(op.code + arg for op, arg in parse_pickle(data)) == data` for all valid pickle streams.

#### `pipeline/registry.py` (T3.2)
**Dangerous-callable registry.**

Loads `dangerous_callables.yaml` into `RegistryEntry` objects keyed by `(module, name)`.

**Key functions**:
- `load_registry(yaml_path)` — loads YAML, filters platform-restricted entries (e.g. `nt.*` on Linux)
- `is_dangerous(module, name) -> bool` — quick lookup
- `get_all_entries() -> list[RegistryEntry]` — all registered callables
- `get_armable_entries() -> list[RegistryEntry]` — excludes NON_ARMABLE sinks that cannot carry inline payloads:
  - `runpy.run_module` — takes module name, no inline code slot
  - `pandas.eval` — expression engine rejects `__import__` calls
  - `sympy.sympify` — raises SympifyError on empty shell output
  - `yaml.unsafe_load` — parses YAML; Python code string never constructs executable object graph
  - `builtins.__import__`, `builtins.getattr`, `_pickle.loads` — smuggling primitives (used by evasion chains, never selected as direct sinks)

**Registry categories**: `command_execution` (os.system, subprocess.Popen/run/call/check_call/check_output, posix.system, nt.system), `code_evaluation` (builtins.eval, pandas.eval), `code_execution` (builtins.exec, runpy.run_module, runpy.run_path, numpy.testing._private.utils.runstring), `import_smuggling` (builtins.__import__, builtins.getattr, _pickle.loads).

#### `pipeline/templates.py` (T2.1–T2.3, T3.9)
**ShadowPickle attack templates and torch injection.**

**Attack templates** (all subclass `AttackTemplate`):
- `OverwrittenModuleTemplate` (T2.1): Generates a two-stage pickle. Stage 1: `exec(shadow_module_code, {})` installs a malicious shadow of `collections.OrderedDict` (or other) into `sys.modules`. Stage 2: `GLOBAL collections OrderedDict` with payload as constructor arg — the shadow's `__new__` execs the payload. Self-contained, no external files needed.
- `PyPIInjectedTemplate` (T2.2): `sink_kind = "system"`. Calls `IPython.utils.process.system` with `python3 -c <payload>`.
- `ExternalModuleTemplate` (T2.3): `sink_kind = "runstring"`. Calls `numpy.testing._private.utils.runstring` with `(payload_code, {})`.
- `IndirectChainTemplate`: Stealth family. Resolves sink via `builtins.getattr(builtins.__import__('os'), 'system')` — no GLOBAL operand names the dangerous pair.

**Family registry**:
- `FAMILY_TEMPLATES: dict[str, AttackTemplate]` — maps family id to template instance
- `FAMILIES: tuple[str, ...]` — `("gadget", "overwritten", "external", "indirect_chain")`
- `FAMILY_LABELS: dict[str, str]` — stable per-family labels for DB records

**Injection helpers**:
- `inject_payload_into_pickle(benign_pkl_path, malicious_pkl_path, payload_bytes)` — loads benign pickle, inserts `_InjectHelper` wrapper object, saves.
- `inject_payload_into_torch(benign_pt_path, malicious_pt_path, payload_bytes, transport)` — modifies PyTorch ZIP archive's `data.pkl`:
  - `transport="loads"` (legacy): wraps payload in `_pickle.loads(BINBYTES(...))` before STOP
  - `transport="splice"` (evasion): splices payload opcodes directly before STOP, drops return value with POP, removes FRAME opcodes to avoid frame-nesting errors, fixes PROTO frame length descriptor

**`_InjectHelper` class**: Object with custom `__reduce__` that returns `(pickle.loads, (self.pickle_bytes,))` — when unpickled, executes the embedded payload.

#### `pipeline/generator.py` (T3.3)
**Candidate generator core.**

`CandidateGenerator` class:
- `mutate_pickle_bytes(pkl_bytes, payload_code, dangerous_callable, mutate_meta, mutation_prob)` — parses pickle, mutates metadata arguments (strings, ints, floats) with sampling, builds GLOBAL+REDUCE injection chunk with proper args tuple for the chosen callable, reconstructs stream with injection before STOP.
- `generate_candidate_pt(benign_pt_bytes, payload_code, dangerous_callable, mutate_meta, mutation_prob, op_swap_prob, callable_sub_prob, arg_fuzz_prob, stack_prob, attack_family, evasion_strategies, injection_transport)` — full candidate generation pipeline:
  1. Builds benign base dict and pickles at protocol 5
  2. Applies `PickleMutator.mutate()` with feedback-controlled probabilities
  3. Callable substitution re-roll if `callable_sub_prob` fires
  4. For `gadget` family: calls `mutate_pickle_bytes()`; for template families: calls `family_template(family).generate_pickle_payload()`
  5. Applies evasion pipeline via `apply_pipeline()` if strategies specified
  6. Self-checks structural sanity (max 3 retries), raises `ValueError` if still invalid
  7. Appends stacked pickle trailer if `stack_prob` fires
  8. Writes benign `.pt` to temp file, calls `inject_payload_into_torch()`, returns result bytes

**`_structurally_sane(pkl_bytes) -> bool`** — rejects stream-fusion artifacts: exactly one STOP, at most one leading PROTO, FRAME only at position 1.

#### `pipeline/mutators.py` (T3.4)
**Pickle mutation operators.**

`PickleMutator` class with five mutation methods:
- `mutate_opcode_swap(op, arg)` — swaps value opcodes (NONE/NewTRUE/NewFALSE) only; excludes container-type and build-op swaps that would corrupt stack semantics.
- `mutate_callable_substitution(op, arg)` — replaces GLOBAL/INST target with random registry entry.
- `mutate_argument_fuzz(op, arg)` — fuzzes length-prefixed strings/bytes, fixed-width ints/floats, delimited literals to sampled boundary values.
- `mutate_structural_stacking(pkl_bytes)` — appends independent trailing pickle (`pickle.dumps({"fuzzed_stack_payload": True})`).
- `mutate_opcode_encoding(op, arg)` — rewrites GLOBAL/INST to STACK_GLOBAL form (proto-4 SHORT_BINUNICODE + STACK_GLOBAL).

`mutate(pkl_bytes, op_swap_prob, callable_sub_prob, arg_fuzz_prob, stack_prob, encoding_prob)` — applies selected operators probabilistically, rebuilds stream, bumps PROTO to 4 if any encoding changed.

#### `pipeline/validity.py` (T3.5)
**Validity oracle — container-sandboxed load + trigger check.**

`ValidityOracle` class:
- `validate_pickle(pkl_bytes, trigger_file) -> bool` — writes candidate to temp file, runs `pickle.load()` inside `regenbench/base` container (mount with `:z` or `--security-opt label=disable` for SELinux), polls for sentinel file existence (5s timeout with 0.05s intervals to handle async child processes like subprocess.Popen).
- `validate_torch(pt_bytes, trigger_file) -> bool` — writes candidate to `/tmp`, runs `torch.load(..., weights_only=False, map_location='cpu')` inside container, checks trigger.
- `validate_gguf(gguf_bytes) -> bool` — runs ggufref container's reference parser, checks `load_ok` in JSON output.

**SELinux handling**: retries with `--security-opt label=disable` if initial mount fails with "relabeling" error. Trigger files live in system `/tmp` (mounted into container).

#### `pipeline/pre_filter.py` (T4.1)
**Static pre-filter admission gate.**

`is_admitted(file_path) -> bool`:
1. Checks magic bytes (ZIP for PyTorch, 0x80 for raw pickle)
2. For ZIP: extracts `data.pkl` from archive
3. Parses pickle with `parse_pickle()`
4. Recursively scans for dangerous imports via `_has_dangerous_import()`:
   - TOP-LEVEL: GLOBAL/INST operands, STACK_GLOBAL string pairs
   - NESTED: descends into BINBYTES/SHORT_BINBYTES payloads that look like pickle streams (up to depth 16)
5. **Fail-closed**: unparseable/corrupted files return `True` (must still reach dynamic oracle)
6. Returns `True` if any dangerous callable found, `False` otherwise

#### `pipeline/runner.py` (T0.10, T4.2, T4.3)
**Local task orchestration — generator → filter → scanner fan-out.**

`Config` dataclass: backend, tag, max_workers, timeout, extensions, min_size, skip, oracle, pre_filter, oracle_model_dir.

`Runner` class:
- `_filter(src)` — applies extension filter, min-size filter, skip patterns, hidden-file filter
- `_scanners_for(src)` — selects applicable scanners based on file extension (oracle only for torch/GGUF extensions)
- `_one(src, scanner)` — runs single scanner container via `run_scan()`, returns `ScanResult`
- `run(artifacts, db_path)` — main orchestration:
  1. Dedups artifact paths
  2. Initializes DB if path given
  3. For each artifact: generates candidate_id (MD5 of path), logs candidate, determines scanners
  4. If `dynahug` in scanners and `pre_filter=True`: runs `is_admitted()`; if not admitted, removes dynahug from scanners and logs synthetic benign oracle result
  5. Submits all (artifact, scanner) pairs to `ThreadPoolExecutor` (maxWorkers = min(32, cpu_count))
  6. Collects results, logs panel/oracle results to DB
  7. Sorts by (artifact, scanner), returns

`TrackingSink` — no-op default; MLflow implementation in T0.9.

`summarize(results)` / `print_report(results, summary)` — console output formatting.

#### `pipeline/scanners.py` (T0.3–T0.7)
**Scanner/oracle registry and container-launch primitive.**

`SCANNERS` dict: picklescan, modelscan, fickling, modeltracer (kind="panel"), dynahug, ggufref (kind="oracle").

`ScanResult` dataclass: scanner, artifact, verdict, exit_code, decision_score, findings, matched_rules, error, duration.

`run_scan(backend, image_full, src, timeout, oracle_model_dir)`:
- Builds container command with `:ro,z` shared SELinux mount, `--timeout` for conmon
- If `oracle_model_dir` provided: adds `-e DYNAHUG_MODEL_DIR=/opt/dynahug/recalibrated` and mounts recalibrated model dir
- Runs container, parses last line of stdout as JSON (unified verdict schema)
- Returns `(parsed_dict, error_string)`

`build_images(spec, tag, overrides)` — resolves image names with optional `name=image:tag` overrides.

`expected_scanners(spec, selected)` — filters scanner spec by selected list.

#### `pipeline/comparator.py` (T5.1)
**Dual-oracle bypass confirmation.**

`check_bypass(panel_verdicts: list[str], oracle_verdict: str) -> bool`:
- Returns `True` iff ALL panel verdicts are "benign" AND oracle verdict is "malicious"
- Returns `False` for empty panel, any "malicious"/"error" panel verdict, or non-malicious oracle

#### `pipeline/fitness.py` (T5.2)
**Distance-to-boundary fitness with multi-mode support.**

**Modes** (`FitnessMode` enum):
- `CURRENT`: panel evasion + boundary + novelty (original behavior)
- `ORACLE_AWARE`: adds oracle confirmation bonus
- `ORACLE_DOMINANT`: lexicographic ranking (dynamic confirmation > panel > coverage > novelty)

**Functions**:
- `compute_fitness(detected_count, total_scanners, decision_score) -> float`:
  `fitness = (total_scanners - detected_count) + 1.0 / (1.0 + abs(decision_score))`
- `compute_fitness_multi(scanner_verdicts, decision_score, novelty_score, weights) -> float`:
  `w_evasion * benign_count - w_error * error_count + w_boundary / (1 + |decision_score|) + w_novelty * novelty_score`
- `compute_fitness_oracle_aware(...)` — adds `w_oracle_bonus` when valid + oracle malicious
- `compute_fitness_lexicographic(...)` — tiered ranking with large gaps:
  - Tier 1: 10000 + boundary_proximity*100 + novelty*10 + coverage (confirmed malicious + valid)
  - Tier 2: 1000 + novelty*10 + coverage (all panel benign + valid)
  - Tier 3: 100 + novelty*10 + coverage (novel + valid)
  - Tier 4: 10 + coverage (coverage improvement + valid)
  - Tier 5: 1.0 (valid but nothing special)
  - 0.0 (invalid)

`FitnessWeights` dataclass: evasion=1.0, boundary=1.0, novelty=2.0, error_penalty=0.25, oracle_bonus=3.0.

#### `pipeline/feedback.py` (T5.3, T5.4)
**Coverage tracking and feedback-directed mutation control.**

`CoverageTracker`:
- Tracks `seen_opcodes: set[str]` and `seen_callables: set[tuple[str,str]]`
- `track_candidate(file_path)` — parses candidate (ZIP or raw pickle), extracts opcodes and dangerous callables (GLOBAL/INST/STACK_GLOBAL), recurses into nested payloads
- `log_round(round_num)` — computes opcode/callable coverage fractions, logs to DB

`NoveltyTracker`:
- Signature = `(tuple of opcode names, tuple of sorted extra labels)`
- First-sight signature scores 1.0; repeats decay as `1/(1+count)`

`FeedbackController`:
- Maintains per-callable weights and per-family weights (initialized to 1.0)
- `get_callable_weights()` / `get_family_weights()` — normalized distributions
- `_ingest_greybox(round_results)` — tallies per-scanner verdicts, penalizes callables whose names appear in scanner `matched_rules` (weight *= 0.85)
- `update(round_results)`:
  1. Reinforces callable weights: `weight += 0.2 * fitness`
  2. Rewards families: +2.0 for full evasion, +0.1 for validity
  3. Adjusts mutation probabilities based on evasion rate:
     - < 20%: increase probs by 0.05 (capped at MAX: op_swap=0.25, callable_sub=0.25, arg_fuzz=0.30)
     - > 60%: decrease probs by 0.03 (floored at MIN: 0.05)

### 3.2 Scanner/Container Infrastructure

#### Container directories (`containers/<name>/`)
Each scanner/oracle has:
- `Dockerfile` — base image + scanner-specific dependencies
- `build.sh` — builds `regenbench/<name>:<version>` and `:latest`
- `wrapper.py` or `validator.py` — container entrypoint that reads `/artifact`, runs scan, emits JSON verdict on stdout
- `README.md` — scanner-specific documentation

**Scanners**:
- `containers/base/` — base image (Python 3.13, pickletools, torch, etc.)
- `containers/picklescan/` — PickleScan static analyzer
- `containers/modelscan/` — ModelScan scanner
- `containers/fickling/` — Fickling pickle analyzer
- `containers/modeltracer/` — ModelTracer dynamic syscall tracer
- `containers/dynahug/` — DynaHug behavioral oracle (OCSVM on syscall profiles)
- `containers/gguf/` — GGUF reference parser (Task 3 oracle)

### 3.3 Experiment & Evaluation Scripts

#### `scripts/run_fuzzing_campaign.py` (T5.5)
**Guided/unguided fuzzing campaign driver.**

Key flow:
1. Resolves seed checkpoint (real corpus or `--base-checkpoint`)
2. Initializes DB, logs campaign run metadata
3. For each round:
   - Selects attack family (weighted in guided mode, uniform in unguided)
   - Selects dangerous callable (weighted in guided mode)
   - Picks evasion strategies (adaptive: feedback-informed subset; random: uniform; off: none)
   - Generates candidates via `CandidateGenerator.generate_candidate_pt()`
   - Runs panel + dynahug via `Runner`
   - Validates each candidate via `ValidityOracle.validate_torch()`
   - Computes fitness (mode-dependent)
   - Checks bypass via `check_bypass()`
   - Registers confirmed bypass in shelf-life tracker
   - Tracks coverage delta, novelty score
   - Logs everything to DB
   - Updates `FeedbackController` (guided mode only)
   - Logs round coverage
4. Generates `docs/fuzzing-report-<run_id>.md`
5. If time budget exceeded: corrects `total_candidates` in DB

**Arguments**: `--mode`, `--rounds`, `--candidates-per-round`, `--replicate`, `--base-checkpoint`, `--seed-corpus-dir`, `--seed-cluster`, `--attack-families`, `--evasion-mode`, `--evasion-strategies`, `--fitness-mode`, `--time-budget-hours`, `--oracle-model-dir`, `--panel-scanners`, `--pre-filter`, `--ensemble-oracle`, `--anomaly-*`.

#### `scripts/run_evaluation_suite.py` (T7.1–T7.11)
**Quantitative evaluation and ablation suite.**

**Statistical functions**:
- `bootstrap_ci(data, num_resamples=10000, seed) -> (low, high)` — 95% bootstrap CI
- `wilcoxon_test(guided, unguided, seed) -> dict` — paired Wilcoxon signed-rank (scipy if available, else Monte-Carlo permutation fallback)
- `two_proportion_test(evaded_a, admitted_a, evaded_b, admitted_b, seed) -> dict` — two-proportion z-test + Fisher's exact (scipy or stdlib erfc + Monte-Carlo)
- `_normal_tail_p(z) -> float` — `erfc(|z|/sqrt(2))` from stdlib math

**Evaluation tasks**:
1. **T7.5**: `run_benign_fp_check(scanners, corpus_dir, sample)` — scans real benign corpus, computes per-scanner FP rates, records per-artifact verdicts for detector agreement
2. **T7.6**: `run_ablation_unguided()` — generates 10 candidates with uniform selection, measures mean fitness + evasion yield
3. **T7.7**: `run_ablation_prefilter()` — 5 distinct benign file copies, measures duration with/without pre-filter
4. **T7.1/T7.2**: `query_campaign_stats(db)` — evasion counts, confirmed/uncorroborated bypasses from DB
5. **T7.10**: `query_run_evasion(db)` — per-run evasion summaries, two-proportion test guided vs unguided
6. **T7.3**: `query_coverage_history(db)` — per-round opcode/callable coverage
7. **T7.8**: H2 assessment — uncorroborated vs confirmed comparison
8. **T7.9**: `ShelfLifeTracker(db).compute_decay_curve()` — shelf-life retention (empirical or simulated)
9. **T7.11**: Writes `docs/evaluation-report.md`

**DB queries** (all strictly measured, no fabrication):
- `query_bypass_queries(db)` — queries-to-first-bypass per replicate (right-censored at total+1 when no bypass)
- `query_campaign_stats(db)` — confirmed bypass via strict SQL: oracle malicious + pre_filtered=0 + valid + panel has benign row + no malicious/error panel rows
- `query_run_evasion(db)` — per-run evasion with same strict criteria

#### `scripts/run_pilot_campaign.py` (T6.2)
**Config-driven pilot campaign.** Reads `config/campaign_config.yaml`, runs guided campaign with configured parameters.

#### `scripts/run_known_answers.py` (T6.1, supplementary)
**Validates scanner panel against known-answer corpus.** Checks `reference/known_answers/` artifacts (benign, malicious pickle/torch, GGUF malformed) against expected verdicts. Produces `reference/known-answers-report.json`.

#### `scripts/run_parallel_ablation.py`
**Parallel ablation experiment runner.** Runs multiple ablation configurations concurrently.

#### `scripts/calibrate_oracle.py`
**Fits environment-calibrated OCSVM on host syscall profiles.** The upstream DynaHug model (8ff8174) returns constant -rho for all inputs in this environment (sandbox traces 10-100x more syscalls). This script fits a new OCSVM on this environment's strace profiles, producing `real_benign_corpus/oracle-calibrated/<version>/` with `oneclass_svm_model.pkl`, `scaler.pkl`, `vectorizer.pkl`, `syscalls.txt`, `calibration-report.json`.

**Calibration versions**:
- `v2-disjoint/` — initial calibrated model
- `v3-all/` — all clusters
- `v4-textgen/` — text-generation cluster only
- `v5-recalibrated/` — latest, with anomaly subdetector (`isolation_forest.pkl` in `anomaly/`)

#### `scripts/organize_corpus.py`
**Splits benign corpus into oracle-positive/negative views by DynaHug decision score.** Creates `real_benign_corpus/oracle_positive/` and `oracle_negative/` hard links.

#### `scripts/validate_oracle.py`
**Runs DynaHug oracle over random sample of benign corpus, outputs validation JSON.**

#### `scripts/sanity_smoke.py`
**Quick sanity check:** validates containers are built and basic pipeline functions work.

#### `scripts/test_generator_suite.py` (T3.6)
**Unit/property tests for candidate generator.** Tests opcode parsing, mutation operators, payload injection, template generation.

#### `scripts/test_integration.py` (T4.5)
**End-to-end integration test suite.** Validates full pipeline: generate → filter → scan → compare.

#### `scripts/benchmark_perf.py` (T4.6)
**Throughput/latency benchmarking.** Measures pre-filter throughput speedup.

#### `scripts/triage_bypasses.py` (T6.4)
**Bypass triage reporter.** Profiles confirmed bypasses by dangerous callable, transport, strategies.

#### `scripts/save_results.py`
**Snapshots complete run into `results/<timestamp>/`.** Copies DB, reports, bypasses, corpus metadata, GGUF/MalHug inventories, generates `results.md` and `results.json`.

#### `scripts/run_task3_demo.py` (T3.11)
**GGUF attack surface demo.** Scans 7 malicious GGUF attack families + 24 real benign GGUFs across all scanners and ggufref oracle. Produces `docs/task3-demo.md`.

#### `scripts/crawl_benign.py` (T2.4, T2.5)
**Crawls benign HuggingFace checkpoints.** Downloads `pytorch_model.bin` from public non-gated repos, deduplicates by SHA-256, writes `data/crawled/seed_manifest.json`.

#### `scripts/crawl_gguf.py` (T3.9)
**Crawls real benign GGUF corpus.** TinyLlama series + llama.cpp tokenizer models → `data/gguf_benign_corpus/`.

#### `scripts/crawl_malhug.py` (T3.10)
**Crawls MalHug real malicious corpus.** ASE 2024 HuggingFace malicious models → `data/malhug/` with `manifest.json`.

#### `scripts/fit_oracle_sweep.py`
**Hyperparameter sweep for oracle calibration.** Tests different OCSVM parameters.

#### `scripts/fp_eval_oracle.py`
**Independent FP evaluation of calibrated oracle.**

#### `scripts/check_oracle_disjointness.py`
**Verifies oracle decisions are disjoint from scanner decisions.**

#### `scripts/diagnose_oracle_features.py`
**Diagnoses which syscall features drive oracle decisions.**

#### `scripts/run_oracle_dominant_validation.sh`
**5x oracle_dominant validation script.** Runs campaigns with ORACLE_DOMINANT fitness mode.

#### `scripts/run_fitness_ablation_experiment.sh`
**Fitness ablation experiment runner.**

#### `scripts/stress_concurrency.py`
**Stress tests concurrent scanner execution.**

#### `scripts/generate_seed_corpus.py`
**Generates synthetic seed corpus for testing.**

#### `scripts/shelf_life_rescan.py`
**Re-scans confirmed bypasses against updated scanner versions.**

#### `scripts/verify_host.sh`
**Host environment verification script.**

#### `scripts/verify_pins.py`
**Verifies dependency pins.**

#### `scripts/sanity_smoke.py`
**Sanity smoke test for the pipeline.**

### 3.4 Data & Corpus

#### `data/crawled/`
Real benign HuggingFace checkpoints crawled by `crawl_benign.py`. Organized by cluster/repo with `pytorch_model.bin` files. `seed_manifest.json` records SHA-256 provenance.

#### `data/malhug/`
MalHug real malicious corpus (ASE 2024). 73 malicious HuggingFace models with `manifest.json`.

#### `data/shelf_life.db`
SQLite database for bypass shelf-life tracking (versioned re-scan results).

#### `real_benign_corpus/`
Flat corpus directory for FP studies:
- `all/` — hard links to all crawled checkpoints (flat `<cluster>__<repo>.bin` naming)
- `oracle-calibrated/<version>/` — calibrated oracle models + traces
- `oracle-validation.json` — DynaHug scores on sample
- `oracle-split.json` — corpus split metadata

#### `data/candidates/<run_id>/`
Generated candidate checkpoints per campaign run (persisted for export).

#### `data/bypasses/<run_id>/`
Exported confirmed bypass artifacts (JSON + checkpoint file).

#### `ci/corpus/`
Smoke-test corpus:
- `pkl/benign/` — 10 benign pickle files
- `pkl/malicious/` — 10 malicious pickle files
- `torch/benign/benign.pt` — benign PyTorch checkpoint
- `torch/malicious/malicious.pt` — malicious PyTorch checkpoint
- `expected.json` — expected scanner verdicts for each artifact

#### `reference/`
Reference data and baseline snapshots:
- `known_answers/` — curated test artifacts: benign_dict.pkl, benign_strings.pkl, benign_torch.pt, bypass_nested_loads.pkl, bypass_nested_loads_in_torch.pt, evil_builtins_eval.pkl, evil_global_in_torch.pt, evil_global_os_system.pkl, evil_inst_form.pkl, evil_stack_global.pkl, malformed_bad_opcode.pkl, malformed_truncated.pkl, gguf_malformed/bad_magic.gguf, gguf_malformed/truncated_header.gguf
- `known_answers_manifest.json` — artifact manifest
- `known-answers-report.json` — validation results
- `oracle-sanity.json` / `oracle-sanity-batch.json` — oracle sanity check results
- `oracle-feature-diagnostics.json` — feature diagnostics
- `oracle-disjointness-report.json` — disjointness analysis
- `sanity-verdict-log.json` — verdict log
- `published-scanner-metrics.json` — published scanner metrics
- `published-dynahug-metrics.json` — published DynaHug metrics
- `blindspot-probe.json` — blindspot probe data
- `baseline_contracts.md` — formal module contracts
- `baseline_snapshot_checksums.sha256` — snapshot checksums
- `baseline_snapshot/` — full results snapshot (20260818-141227):
  - `results.json` / `results.md` — machine-readable and human-readable summaries
  - `comparison-methodology.md` — comparison methodology
  - `evaluation-report.md` — evaluation report
  - `fuzzing-report-*.md` — per-campaign fuzzing reports
  - `perf-report.md` — performance report
  - `triage-report.md` — bypass triage
  - `seed_manifest.json` / `malhug_manifest.json` — corpus manifests
  - `regenbench_campaign.db` — campaign database
  - `oracle-validation.json` — oracle validation

### 3.5 Rust Performance Components

#### `crates/regenbench-core/`
Rust implementation of performance-critical pipeline components.

**`Cargo.toml`**: Dependencies — `thiserror`, `lazy_static`, `rand`.

**`src/lib.rs`**: Public module exports:
- `opcodes` — pickle opcode parsing and classification
- `mutators` — `PickleMutator` struct
- `evasion` — `EvasionStrategy` trait, `apply_pipeline`, strategy registry
- `types` — `OpcodeCategory`, `OpcodeClassification`, `ParsedOpcode`, `MutatorConfig`, `EvasionConfig`

**`src/opcodes.rs`**: Full opcode table (256 entries) built at startup via `build_opcode_table()`. Covers all CPython pickle protocols 0-5. Includes `parse_pickle()`, `reconstruct()`, `get_opcode_classification()`, `get_opcode_by_byte()`. Error types via `ParseError` enum (UnknownOpcode, TruncatedFixedArg, TruncatedLengthPrefix, TruncatedPayload, MissingDelimiter, MissingGlobalSecondField).

**`src/types.rs`**: Core types:
- `OpcodeCategory` enum: NoArg, FixedArg, LengthPrefixed, Delimited
- `OpcodeClassification` struct: code (u8), name, category, arg_width, proto
- `ParsedOpcode` struct: classification + arg (Vec<u8>)
- `MutatorConfig` struct: op_swap_prob, callable_sub_prob, arg_fuzz_prob, stack_prob, encoding_prob
- `EvasionConfig` struct: strategies (Vec<String>)

**`src/mutators.rs`**: `PickleMutator` struct with Rust implementations of all mutation operators. Uses `rand` for probabilistic selection. Methods: `mutate()`, `mutate_opcode_swap()`, `mutate_callable_substitution()`, `mutate_opcode_encoding()`, `mutate_argument_fuzz()`, `mutate_structural_stacking()`. Reuses `DANGEROUS_CALLABLES` from registry for substitution.

**`src/evasion.rs`**: `EvasionStrategy` trait with macro-generated strategy implementations:
- `StackGlobalEncoding` — rewrites GLOBAL/INST to STACK_GLOBAL
- `NestedLoadsWrap` — wraps in `_pickle.loads(BINBYTES(...))`
- `PayloadObfuscation` — hides trigger strings in nested loads
- `IndirectChain` — builtins.__import__ + builtins.getattr chain
- Helper functions: `encode_short_binunicode()`, `binbytes_tuple()`, `args_tuple_bytes()`, `ensure_proto()`, `canonical_module()`, `find_tuple_start()`

**`crates/regenbench-py/`**: PyO3 bindings for Python integration.
- `Cargo.toml` + `pyproject.toml` for Python package build
- `src/lib.rs` — PyO3 module exposing Rust implementations to Python

### 3.6 Configuration & Reference Data

#### `config/campaign_config.yaml`
Experiment configuration:
- `experiment.name`: "regenbench-main"
- `experiment.tier`: "pilot" | "main"
- `tiers.pilot`: 100 real checkpoints, 100 guided/unguided candidates, 2 replicates, 60 oracle sample
- `tiers.main`: 600 real checkpoints, 500 guided/unguided candidates, 5 replicates, 100 oracle sample
- `corpus.root`: "real_benign_corpus/all"
- `corpus.clusters`: text-generation, text-classification, feature-extraction
- `campaign.base_checkpoint`: real text-generation checkpoint
- `campaign.rounds`: 5, `candidates_per_round`: 20
- `campaign.panel_scanners`: picklescan, fickling, modelscan, modeltracer
- `campaign.oracle_scanners`: dynahug
- `database.path`: "data/regenbench_campaign.db"
- `evaluation.script`: "scripts/run_evaluation_suite.py"

#### `pipeline/dangerous_callables.yaml`
Registry of dangerous callables with module, name, category, description, genuine_code_exec flag, optional platform restriction.

### 3.7 Container Definitions

#### Build order
```
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do
  containers/$d/build.sh
done
```

Each container produces `regenbench/<name>:<version>` and `:latest`.

#### Container entrypoints
All scanners/oracles follow the same invocation pattern:
- Host artifact mounted read-only at `/artifact` with `:ro,z` (shared SELinux relabel)
- Container receives `/artifact` as argv
- Entrypoint reads artifact, runs analysis, emits JSON verdict on last line of stdout
- Unified verdict schema: `{"verdict": "benign"|"malicious"|"error", "exit_code": 0|1|2, "decision_score": float, "findings": [...], "matched_rules": [...]}`

### 3.8 Documentation & Reports

#### `README.md`
Full project documentation: components table, prerequisites, build instructions, running the framework (crawl → validate → fuzz → evaluate → Task 3), saving results, latest results with evasion-mode campaign tables, evaluation correctness fixes (SELinux mount race + calibrated DynaHug wiring).

#### `DISCLAIMER.md`
Security warning, purpose limitation, no warranty, external data provenance.

#### `docs/fuzzing-report-guided-r*.md`
Per-replicate fuzzing reports (r2-r5) showing round-by-round: valid/generated counts, confirmed bypasses, mean fitness, opcode/callable coverage, attack-family distribution, per-scanner evasions (adaptive evasion mode).

#### `reference/baseline_snapshot/results-20260818-141227/`
Full baseline snapshot with all reports, database, and corpus metadata.

---

## 4. Evaluation Mechanism

### 4.1 Campaign Execution Flow

```
Seed checkpoint (real HF model or synthetic)
    │
    ▼
CandidateGenerator.generate_candidate_pt()
    │
    ├── PickleMutator.mutate() [feedback-controlled probs]
    ├── Attack family selection (gadget / overwritten / pypi_injected / external / indirect_chain)
    ├── Dangerous callable selection (weighted in guided mode)
    ├── Evasion strategy selection (adaptive / random / off)
    ├── Template.generate_pickle_payload() or mutate_pickle_bytes()
    ├── apply_pipeline() [evasion strategies]
    ├── Structural sanity check (max 3 retries)
    ├── inject_payload_into_torch() [splice or loads transport]
    └── Write to data/candidates/<run_id>/round_N/candidate_M.pt
    │
    ▼
Runner.run() — panel scanners + dynahug fan-out
    │
    ├── Pre-filter: is_admitted() gates dynahug
    ├── ThreadPoolExecutor: parallel container scans
    ├── Each scanner: container runs, JSON verdict parsed
    └── Results logged to SQLite DB
    │
    ▼
ValidityOracle.validate_torch() — container-sandboxed torch.load + trigger check
    │
    ▼
Fitness computation (mode-dependent)
    │
    ├── CURRENT: compute_fitness() or compute_fitness_multi()
    ├── ORACLE_AWARE: compute_fitness_oracle_aware()
    └── ORACLE_DOMINANT: compute_fitness_lexicographic()
    │
    ▼
Bypass confirmation: check_bypass(panel_verdicts, oracle_verdict)
    │
    ├── True → register_confirmed_bypass() [shelf-life tracker]
    └── False → no bypass
    │
    ▼
FeedbackController.update() [guided mode only]
    │
    ├── Reinforce callable weights (+0.2 * fitness)
    ├── Reward families (+2.0 evasion, +0.1 validity)
    ├── Penalize flagged callables (* 0.85)
    └── Adjust mutation probs based on evasion rate
    │
    ▼
CoverageTracker.log_round() — opcode/callable coverage to DB
    │
    ▼
Generate fuzzing-report-<run_id>.md
```

### 4.2 Dual-Oracle Bypass Confirmation

A candidate is a **confirmed bypass** when ALL of:
1. **Valid**: `ValidityOracle.validate_torch()` returns True (loads + trigger fires)
2. **Panel evasion**: ALL static panel scanners return "benign" (no "malicious", no "error")
3. **Oracle corroboration**: DynaHug behavioral oracle returns "malicious"

The strict SQL query in `query_campaign_stats()`:
```sql
SELECT COUNT(*) FROM oracle_results o
JOIN candidates c ON c.candidate_id = o.candidate_id
JOIN campaign_fitness f ON f.candidate_id = o.candidate_id
WHERE o.verdict = 'malicious'
  AND o.pre_filtered = 0
  AND f.is_valid = 1
  AND EXISTS (
      SELECT 1 FROM panel_results p
      WHERE p.candidate_id = o.candidate_id AND p.verdict = 'benign'
  )
  AND NOT EXISTS (
      SELECT 1 FROM panel_results p
      WHERE p.candidate_id = o.candidate_id
        AND p.verdict IN ('malicious', 'error')
  )
```

### 4.3 Evaluation Suite Tasks

| Task | Function | Output |
|------|----------|--------|
| T7.1 | Evasion rates per scanner with bootstrap CIs | RQ1 table in evaluation-report.md |
| T7.2 | Bootstrap CI computation | 95% CI columns in RQ1 table |
| T7.3 | Per-round coverage growth | Coverage breadth table |
| T7.4 | (reserved) | — |
| T7.5 | Benign FP rates over real corpus | RQ3 FP table |
| T7.6 | Guided vs unguided ablation | RQ4 ablation 1 table |
| T7.7 | Pre-filter throughput ablation | RQ4 ablation 2 table |
| T7.8 | DynaHug cross-check efficacy (H2) | RQ4 ablation 3 table |
| T7.9 | Shelf-life decay (H3) | Decay curve (simulated if no rescans) |
| T7.10 | Guided vs unguided statistical test | Two-proportion z-test + Fisher's exact |
| T7.11 | Report generation | docs/evaluation-report.md |

### 4.4 Statistical Methods

**Bootstrap CI**: 10,000 resamples with replacement, seeded for reproducibility. 2.5th and 97.5th percentiles.

**Wilcoxon signed-rank test** (RQ2, guided vs unguided Q_first):
- Paired test on queries-to-first-bypass per replicate
- Uses `scipy.stats.wilcoxon` when available
- Fallback: Monte-Carlo permutation over sign flips of nonzero paired differences (10,000 permutations)
- Drops zero differences, uses average ranks for ties

**Two-proportion z-test** (T7.10, guided vs unguided confirmed bypass rates):
- Pooled proportion SE: `sqrt(p_pooled * (1 - p_pooled) * (1/n_a + 1/n_b))`
- z = `(p_a - p_b) / SE`
- p-value from `scipy.stats.norm.sf` (two-sided) or stdlib `erfc(|z|/sqrt(2))`
- Fisher's exact as complementary test (scipy or Monte-Carlo permutation)

**Fail-safe behavior**: When pooled proportion is 0 or 1, SE is undefined — report "not computed" explicitly rather than fabricating a value.

### 4.5 False-Positive Study (RQ3)

- Scans real benign HuggingFace checkpoints (96 in baseline, provenance-based ground truth)
- Per-scanner FP rate = malicious_detections / total_scanned
- Detector agreement analysis: pairwise agreement over artifacts where BOTH detectors produced a verdict
- **Critical caveat**: DynaHug calibrated oracle has 63.5% FP rate on benign corpus — reported honestly, not filtered out

---

## 5. Evaluation Results

### 5.1 Baseline Snapshot (20260818-141227)

**Campaigns** (7 runs, 693 valid candidates):

| Run | Type | Replicate | Candidates | Valid | Confirmed Bypasses |
|-----|------|-----------|------------|-------|-------------------|
| pilot-20260816T030153Z | guided | 1 | 100 | 93 | 0 |
| guided-r1 | guided | 1 | 100 | 100 | 0 |
| guided-r2 | guided | 2 | 100 | 100 | 0 |
| unguided-r1 | unguided | 1 | 100 | 100 | 0 |
| unguided-r2 | unguided | 2 | 100 | 100 | 0 |
| pilot-20260817T101219Z | guided | 1 | 100 | 100 | 0 |
| guided-r3 | guided | 3 | 100 | 100 | 0 |

**Panel verdicts (all runs)**:
| Scanner | Malicious | Benign | Error |
|---------|-----------|--------|-------|
| fickling | 94 | 0 | 606 |
| modelscan | 539 | 0 | 161 |
| modeltracer | 15 | 1 | 684 |
| picklescan | 607 | 0 | 93 |

**Oracle verdicts (all runs)**:
| Verdict | Count |
|---------|-------|
| malicious | 324 |
| error | 376 |

### 5.2 RQ1: Scanner Evasion Rates

| Scanner | Admitted | Evasion Count | Evasion Rate | 95% Bootstrap CI |
|---------|----------|---------------|-------------|------------------|
| PickleScan | 693 | 0 | 0.0% | [0.0%, 0.0%] |
| Fickling | 693 | 0 | 0.0% | [0.0%, 0.0%] |
| ModelScan | (not in valid panel for all runs) | — | — | — |

**H1 verdict**: Not supported — measured evasion rates are below the 70% threshold.

### 5.3 RQ2: Search Efficiency

- Guided Q_first per replicate: [101, 101, 101, 101, 101] (all censored — right-censored at total+1)
- Unguided Q_first per replicate: [101, 101] (all censored)
- Wilcoxon test not run: pairs unequal or too few for paired test

### 5.4 RQ3: Oracle Reliability & False-Positive Costs

**Benign FP rates (96 real HuggingFace checkpoints)**:

| Scanner | Benign Models Scanned | FP Detections | FP Rate |
|---------|----------------------|--------------|---------|
| PickleScan | 96 | 0 | 0.0% |
| Fickling | 96 | 6 | 6.2% |
| ModelScan | 96 | 0 | 0.0% |
| ModelTracer | 96 | 0 | 0.0% |
| DynaHug (Calibrated Oracle) | 96 | 61 | 63.5% |

**DynaHug oracle characterization**:
- Upstream pretrained OCSVM (8ff8174, gamma=0.1, kernel=rbf, nu=0.01) returns constant decision score ≈ -rho (-1.3489) for every loadable checkpoint in this environment
- Sandbox traces 10-100x the syscall counts of the upstream training environment
- Environment-calibrated oracle (scripts/calibrate_oracle.py) restores discriminative decision scores
- Calibrated oracle still has 63.5% measured FP rate — its traces are dominated by Python/torch startup baseline

### 5.5 RQ4: Ablation Studies

**Ablation 1: Coverage-Guided Feedback (T7.6)**:

| Campaign | Replicate | Valid | Panel Evasions | Confirmed | Evasion Yield |
|----------|-----------|-------|----------------|-----------|---------------|
| guided | 1 | 93 | 0 | 0 | 0.0% |
| guided | 1 | 100 | 0 | 0 | 0.0% |
| guided | 1 | 100 | 0 | 0 | 0.0% |
| guided | 2 | 100 | 0 | 0 | 0.0% |
| guided | 3 | 100 | 0 | 0 | 0.0% |
| unguided | 1 | 100 | 0 | 0 | 0.0% |
| unguided | 2 | 100 | 0 | 0 | 0.0% |

- Unguided ablation harness: mean fitness 1.555, evasion yield 0.0% (10 candidates)
- Guided vs unguided confirmed-bypass rates: 0/493 vs 0/200 — test not computable (pooled proportion is 0)

**Coverage Growth (T7.3)**:
- Opcode coverage: 0.441 → 0.441 (round 1 → round 5, no growth — opcode space exhausted quickly)
- Callable coverage: 0.556 → 0.778 (round 1 → round 5, meaningful growth)

**Ablation 2: Pre-filter Throughput (T7.7)**:

| Metric | With Pre-Filter | Without Pre-Filter | Speedup |
|--------|-----------------|-------------------|---------|
| Execution Duration (5 files) | 1.03s | 17.47s | **16.92x** |

**Ablation 3: DynaHug Cross-Check (T7.8 / H2)**:

| Metric | Evasion Count | Rate |
|--------|--------------|------|
| Uncorroborated Evasions (Panel-Only) | 0 | 0.0% |
| Confirmed Evasions (Dual-Oracle) | 0 | 0.0% |

**H2 verdict**: Not assessable — both counts are 0.

### 5.6 H3: Shelf-Life Decay

Not assessed — no empirical version-delta rescans recorded. Simulated decay curve placeholder only (0% retention at all simulated versions, since baseline evasion was 0%).

### 5.7 Evasion-Mode Campaigns (2026-08-23, dev branch)

With Phase-1/2 evasion pipeline active:

| Run | Mode | Evasion | Candidates | Valid | Confirmed Bypasses |
|-----|------|---------|------------|-------|-------------------|
| guided-r21 | guided | adaptive | 36 | 23 | 1 |
| guided-r31 | guided | adaptive | 100 | 77 | 1 |
| guided-r32 | guided | adaptive | 100 | 72 | 0 |
| unguided-r22 | unguided | random | 36 | 21 | 4 |
| unguided-r33 | unguided | random | 100 | 77 | 7 |
| unguided-r34 | unguided | random | 100 | 68 | 10 |

**All-time (11 runs, 1244 candidates)**:
- Confirmed bypasses: 23 (all `pypi_injected` sink + splice transport)
- Per-scanner evasion on evasion-mode runs (338 valid):
  - PickleScan: 23/338 = 6.8%
  - ModelScan: 66/338 = 19.5%
  - Fickling: 294/294 = 100% (no rules for IPython/third-party sinks)
- Confirmed bypasses by mode: guided 2/172, unguided 21/166
- **T7.10 guided vs unguided (all-time)**: 2/694 vs 21/393, z=-5.56, p≈2.6e-8 — uniform search significantly outperforms guided feedback because the winning vector lives in a family outside the callable-weighting scope
- **H1**: Not supported (evasion < 70% threshold)
- **H2**: Not supported (uncorroborated == confirmed = 23; dynamic validation does not inflate counts)
- **H3**: Unassessed until empirical version-delta rescans are run

### 5.8 Task 3: GGUF Attack Surface

- `ggufref` oracle: detects 7/7 GGUF attacks (6 malformed-header families + Jinja2 SSTI CVE-2024-34359) with 0 FP on 24 real benign GGUFs
- modelscan 0.8.8: misses all 7 attacks (0/7 detection)
- fickling: flags every benign GGUF as malicious (24/24 FP)

---

## 6. Architecture & Data Flow

### 6.1 Component Layers

```
Layer 3: Evaluation & Reporting
    ├── scripts/run_evaluation_suite.py  (T7.1-T7.11)
    ├── scripts/run_fuzzing_campaign.py  (T5.5)
    ├── scripts/run_pilot_campaign.py    (T6.2)
    ├── scripts/save_results.py
    └── docs/evaluation-report.md, fuzzing-report-*.md

Layer 2: Campaign Orchestration
    ├── pipeline/runner.py               (T0.10, T4.2, T4.3)
    ├── pipeline/comparator.py           (T5.1)
    ├── pipeline/fitness.py              (T5.2)
    ├── pipeline/feedback.py             (T5.3, T5.4)
    └── pipeline/shelf_life.py           (T7.9)

Layer 1: Candidate Generation & Validation
    ├── pipeline/generator.py           (T3.3)
    ├── pipeline/mutators.py             (T3.4)
    ├── pipeline/templates.py            (T2.1-T2.3)
    ├── pipeline/evasion.py              (Phase 1)
    ├── pipeline/opcodes.py              (T3.1)
    ├── pipeline/registry.py             (T3.2)
    ├── pipeline/validity.py             (T3.5)
    ├── pipeline/pre_filter.py           (T4.1)
    └── pipeline/db.py                   (T4.4)

Layer 0: Scanner/Container Infrastructure
    ├── pipeline/scanners.py             (T0.3-T0.7)
    ├── containers/base/
    ├── containers/picklescan/
    ├── containers/modelscan/
    ├── containers/fickling/
    ├── containers/modeltracer/
    ├── containers/dynahug/
    └── containers/gguf/

Data Layer
    ├── data/crawled/                    (real benign HF corpus)
    ├── data/malhug/                    (real malicious corpus)
    ├── real_benign_corpus/             (flat corpus + oracle views)
    ├── data/regenbench_campaign.db     (SQLite campaign DB)
    ├── data/candidates/<run_id>/       (generated candidates)
    ├── data/bypasses/<run_id>/         (exported confirmed bypasses)
    └── reference/                      (known answers, published metrics)
```

### 6.2 Key Design Decisions

1. **Fail-closed pre-filter**: unparseable/corrupted candidates are admitted to the dynamic oracle rather than silently dropped — rejecting them would let crafted payloads bypass behavioral analysis.

2. **Fail-closed scanner verdicts**: an errored scanner (parse failure, timeout) is never treated as "benign" — it's recorded as "error" so it cannot count as evasion.

3. **Shared SELinux relabel (`:ro,z`)**: fixes the mount race where concurrent scanners mounting the same artifact with private relabels (`:ro,Z`) caused intermittent PermissionError crashes.

4. **Environment-calibrated oracle**: the upstream DynaHug model is non-discriminative in this sandbox environment; calibration on host syscall profiles is required for meaningful results.

5. **Splice transport over loads-wrap**: when evasion is active, the splice transport (raw opcode splice before STOP) avoids re-introducing the flagged `_pickle.loads` GLOBAL signature that the legacy loads-wrap carries.

6. **Callable-weighting scope limitation**: the guided feedback only weights armable callables; the `pypi_injected` family (IPython.utils.process.system) wins uniformly because it's a template family outside the callable-weighting scope — hence unguided search outperforms guided.

7. **Right-censored RQ2 observations**: when no bypass is found in a replicate, the Q_first observation is censored at total_candidates + 1, not discarded — preserving the information that the search exhausted without finding a bypass.

8. **Non-armable sink exclusion**: callables that cannot carry inline payloads (runpy.run_module, pandas.eval, sympy.sympify, yaml.unsafe_load) and smuggling primitives (builtins.__import__, builtins.getattr, _pickle.loads) are registered as dangerous but excluded from candidate generator selection to prevent guaranteed validity failures.

---

*End of comprehensive implementation documentation.*
