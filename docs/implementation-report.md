# RegenBench — Comprehensive Implementation Documentation

> **Note (2026-08-31)**: This is the implementation reference (modules,
> invariants, attack families, DB schema). Quantitative results are **not**
> maintained here — the authoritative, live numbers are in
> [`docs/evaluation-report.md`](evaluation-report.md) (regenerated from the
> campaign DB), [`README.md#latest-results`](../README.md#latest-results), and
> the per-run `docs/fuzzing-report-*.md`. Historical quantitative tables in §5
> are archival. The clean-slate pass (2026-08-31) reset all experiment
> artifacts and rebuilt the corpus as **100 real HuggingFace checkpoints**
> (5 clusters × 20; no synthetics) — see `docs/experiment-plan.md` and
> `docs/QUICKSTART.md`.

**Branch**: dev  
**Generated**: 2026-08-28 (archival; regenerated live report is `docs/evaluation-report.md` at 2026-08-30)  
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
| **H1** | *Directed fuzzing achieves higher evasion rates against static scanners compared to published baselines.* | **Supported** (post-fix scaled run 2026-08-30, reframed to proposal wording: relative improvement over ShadowPickle baseline, not an absolute 70% threshold). Live: fuzzing 51.9% (514/990) vs baseline 25.0% (10/40); per-scanner PickleScan 51.9% vs 25%, ModelScan 62.9% vs 50%, Fickling 94.2% vs 100%. Archival snapshot here: 47.2% (446/945) — see `docs/evaluation-report.md`. |
| **H2** | *Without dynamic validation, scanner bypass counts are significantly inflated.* | **Valid negative result** (post-fix): uncorroborated == confirmed (514 live; 446 in this archival snapshot). The static panel already detects all non-executing candidates, so the dual-oracle adds no precision; dynamic validation's value is confirming payload execution (trigger polling / StraceOracle 0% FP), not filtering false evasions. |
| **H3** | *Confirmed bypasses retain evasion efficacy across minor version scanner updates.* | **Supported** (empirical): 100% retention of 514 live (446 in this snapshot) confirmed bypasses across 6 historical scanner versions (picklescan 1.0.4/1.0.3, modelscan 0.8.7/0.8.6, fickling 0.1.11/0.1.10) — `data/shelf_life.db`. |

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
| IndirectChain | `indirect_chain` | picklescan, modelscan, fickling | Resolve sink via `getattr(__import__(module, None, None, [name]), name)` — fromlist makes dotted modules resolve to the leaf |
| OpcodeReordering | `opcode_reordering` | picklescan | Shuffle independent BUILD/APPEND/SETITEM blocks |
| DeadCodeInjection | `dead_code_injection` | picklescan | Inject MARK/POP no-op sequences |
| StringEncodingVariants | `string_encoding_variants` | picklescan | Alternate string encoding opcodes (SHORT_BINUNICODE/BINUNICODE/UNICODE) |
| ProtocolDowngrade | `protocol_downgrade` | picklescan | Downgrade proto 4/5 to proto 2 |
| AttributeMasking | `attribute_masking` | modelscan | (placeholder) attribute-name masking |
| ModuleAliasing | `module_aliasing` | modelscan | Use module alias paths for dangerous imports |
| NestedLoadObfuscation | `nested_load_obfuscation` | modelscan | Double-wrap nested loads |

**Application order** (`PIPELINE_ORDER`): payload_obfuscation → string_encoding_variants → indirect_chain → stack_global_encoding → module_aliasing → opcode_reordering → dead_code_injection → protocol_downgrade → attribute_masking → nested_load_obfuscation → nested_loads_wrap

**Selection constraints (2026-08-29)**: `select_strategies` caps subset size at `{0,1}` and per-family defaults exclude `nested_loads_wrap`/`payload_obfuscation`/`indirect_chain` stacks that reintroduce denylisted globals (`_pickle.loads`, `builtins.__import__`/`getattr`) — stacking multiple strategies empirically killed evasion.

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
  - `platform.popen` — removed in Python 3.3; GLOBAL'd on py3 raises AttributeError at load
  - `builtins.__import__`, `builtins.getattr`, `_pickle.loads` — smuggling primitives (used by evasion chains, never selected as direct sinks)

**Registry categories**: `command_execution` (os.system, subprocess.Popen/run/call/check_call/check_output, posix.system, nt.system), `code_evaluation` (builtins.eval, pandas.eval), `code_execution` (builtins.exec, runpy.run_module, runpy.run_path, numpy.testing._private.utils.runstring), `import_smuggling` (builtins.__import__, builtins.getattr, _pickle.loads).

#### `pipeline/templates.py` (T2.1–T2.3, T3.9)
**ShadowPickle attack templates and torch injection.**

**Attack templates** (all subclass `AttackTemplate`):
- `OverwrittenModuleTemplate` (T2.1): Generates a two-stage pickle. Stage 1: `exec(shadow_module_code, {})` installs a malicious shadow of `collections.OrderedDict` (or other) into `sys.modules`. Stage 2: `GLOBAL collections OrderedDict` with payload as constructor arg — the shadow's `__new__` execs the payload. Self-contained, no external files needed.
- `PyPIInjectedTemplate` (T2.2): `sink_kind = "system"`. Calls `IPython.utils.process.system` with `python3 -c <payload>`.
- `ExternalModuleTemplate` (T2.3): `sink_kind = "runstring"`. Calls `numpy.testing._private.utils.runstring` with `(payload_code, {})`.
- `IndirectChainTemplate`: Stealth family. Resolves sink via `getattr(__import__(module, None, None, [name]), name)` — the `fromlist=[name]` argument makes dotted modules (e.g. `IPython.utils.process.system`) resolve to the leaf module, so no GLOBAL operand names the dangerous pair.

**Family registry**:
- `FAMILY_TEMPLATES: dict[str, AttackTemplate]` — maps family id to template instance
- `FAMILIES: tuple[str, ...]` — `("gadget", "overwritten", "external", "indirect_chain", "pypi_injected")`
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

**Plausibility gate (`_plausible_candidate`)** — pre-scan rejection using `_import_pairs(parsed)`, which extracts `(module, name)` from GLOBAL/INST operands AND STACK_GLOBAL string pairs (the latter is what `stack_global_encoding` emits), so evasion-rewritten gadget candidates are still admitted.

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
- The container backend defaults to `default_backend()` (podman if present, else docker).

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

`Config` dataclass: backend (defaults to `default_backend()`, i.e. podman if present else docker), tag, max_workers, timeout, extensions, min_size, skip, oracle, pre_filter, oracle_model_dir.

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
- Builds container command with `:ro,z` shared SELinux mount; the conmon `--timeout` flag is passed only for podman (docker `run` rejects it — the host-side subprocess timeout bounds the docker path)
- If `oracle_model_dir` provided: adds `-e DYNAHUG_MODEL_DIR=/opt/dynahug/recalibrated` and mounts recalibrated model dir
- Runs container, parses last line of stdout as JSON (unified verdict schema)
- Returns `(parsed_dict, error_string)`

`default_backend(prefer="podman")` — picks a usable container runtime: prefers podman, falls back to docker when podman is not on PATH (docker-only hosts). Used as the `Config.backend` field default and the `ValidityOracle` backend default.

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
- `CONTINUOUS`: smooth multi-objective (evasion × oracle multiplier + boundary + novelty + coverage)
- `COVERAGE_GUIDED`: coverage delta as the primary objective when evasion plateaus

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
- Maintains per-callable weights, per-family weights (initialized to 1.0), and combo weights `(family, transport, frozenset(strategies))`
- `get_callable_weights()` / `get_family_weights()` — normalized distributions
- `sample_with_novelty()` — combo exploitation with exploration probability that scales with the uncovered-family share, so a family absent from `combo_weights` (e.g. `pypi_injected` early in a campaign) is never permanently starved
- `_ingest_greybox(round_results)` — tallies per-scanner verdicts, penalizes callables whose names appear in scanner `matched_rules` (weight *= 0.85)
- `update(round_results)`:
  1. Reinforces callable weights: `weight += 0.2 * fitness`
  2. Rewards families via tier-based combo reinforcement (Tier1/2/3 deltas)
  3. Adjusts mutation probabilities based on evasion rate:
- < 20%: increase probs by 0.05 (capped at MAX: op_swap=0.25, callable_sub=0.25, arg_fuzz=0.30)
      - > 60%: decrease probs by 0.03 (floored at MIN: 0.05)

#### `pipeline/monitor.py` (T3.15)
**Load-time monitoring + deterministic strace oracle.**
- `StraceOracle` — containerized `strace -f` syscall analysis; 0% FP on the
  benign corpus, replaces DynaHug as the deterministic execution signal
  (bypass confirmation is trigger-polling / StraceOracle, not DynaHug).
- `LoadTimeMonitor` — records torch-load wall time; malicious payloads load
  measurably slower than benign (secondary signal).

#### `pipeline/sanitizer.py`, `pipeline/repair.py`, `pipeline/defense.py` (T3.12)
**Defense prototype: static sanitization + repair/quarantine policy.**
- `PickleSanitizer` rewrites 5 direct sinks (`os.system`, `subprocess.Popen`,
  `builtins.exec/eval`, `IPython.utils.process.system` → `builtins.len`);
  `indirect_chain`/`runstring`/`posix.execv` escapes are **quarantined**, not
  reserialized (guaranteed benign preservation; remaining escapes quarantined).
- `repair.py` implements the repair decision + quarantine policy;
  `defense.py` orchestrates the end-to-end defense pipeline. Source artifacts
  are never mutated; only content that survives
  `torch.load(weights_only=True)` in the sandbox is reserialized.

#### `pipeline/plausibility.py`
**Deterministic bypass confirmation wrapper** around the ExecutionOracle
(trigger-polling); the verdict that gates H1/H2/H3 confirmation.

#### `pipeline/shelf_life.py` (H3)
**Bypass shelf-life DB + rescan + decay.**
- `register_bypasses_from_campaign_db` bulk-registers confirmed bypasses into
  `data/shelf_life.db` (`bypass_records`, `rescans`).
- `ShelfLifeTracker.rescan_bypass` re-runs a bypass against an explicit
  historical image and logs `evasion_retained`.

#### `pipeline/differential.py`
**RQ1 cross-parser disagreement generation** — `differential_mutate` /
`disagreement` for pickle-parser differential fuzzing (`--differential-prob`).

#### `pipeline/oracle_ensemble.py`
**Deprecated** AND-gate ensemble (`dynahug and anomaly and executed`). It
suppresses true positives, so bypass confirmation is trigger-execution only;
DynaHug is a supplementary `decision_score`. Imports sklearn at top — do not
import where sklearn is absent.

#### `pipeline/gguf_tools.py` (T3.7)
**GGUF parser/writer + attack generators** (malformed-header families + Jinja2
SSTI chat-template), used by the format-complexity GGUF demo.

### 3.2 Scanner/Container Infrastructure

#### Container directories (`containers/<name>/`)
Each scanner/oracle has:
- `Dockerfile` — base image + scanner-specific dependencies; takes a `SCANNER_COMMIT` build ARG (defaulting to the pinned release) so historical versions are buildable
- `build.sh` — builds `regenbench/<name>:<version>`; optional args `[VERSION] [SCANNER_COMMIT]` build a historical release tagged `regenbench/<name>:<VERSION>` (default no-arg build also refreshes `:latest`)
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
   - Selects attack family (weighted in guided mode via `sample_with_novelty`, uniform in unguided)
   - Selects dangerous callable (weighted in guided mode)
   - Picks evasion strategies (adaptive: single-strategy subsets; random: uniform; off: none)
   - Generates candidates via `CandidateGenerator.generate_candidate_pt()` — parallel workers reseed from `sha256(base_seed:round:index)` so generation is deterministic across runs
   - Runs panel + dynahug via `Runner`
   - Validates each candidate via `ValidityOracle.validate_torch()`
   - Computes fitness (mode-dependent)
   - Checks bypass via `check_bypass()` (execution-oracle primary)
   - Registers confirmed bypass in shelf-life tracker
   - Tracks coverage delta, novelty score
   - Logs everything to DB
   - Updates `FeedbackController` (guided mode only)
   - Logs round coverage
4. Generates `docs/fuzzing-report-<run_id>.md`
5. If time budget exceeded: corrects `total_candidates` in DB

**Arguments**: `--mode`, `--rounds`, `--candidates-per-round`, `--replicate`, `--base-checkpoint`, `--seed-corpus-dir`, `--seed-cluster`, `--attack-families`, `--evasion-mode`, `--evasion-strategies`, `--fitness-mode`, `--time-budget-hours`, `--oracle-model-dir`, `--panel-scanners`, `--pre-filter`, `--ensemble-oracle`, `--anomaly-*`, `--differential-prob`, `--family-synthesis-prob`, `--gen-workers`.

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
**GGUF attack surface demo.** Scans 7 malicious GGUF attack families + 24 real benign GGUFs across all scanners and ggufref oracle. Output is consolidated into `docs/demo-report.md#5`; the unified `scripts/demo_task3.py` also covers GGUF (synthetic benign default when the real corpus is absent).

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
- `--register` bulk-registers confirmed bypasses from the campaign DB into the shelf DB (`register_bypasses_from_campaign_db`) before re-scanning (idempotent)
- `--image scanner=image:tag` overrides target a specific scanner version snapshot (e.g. `--image picklescan=regenbench/picklescan:1.0.4`)
- `--decay-only` computes the decay curve from existing rescans without re-scanning

#### `scripts/verify_host.sh`
**Host environment verification script.**

#### `scripts/verify_pins.py`
**Verifies dependency pins.**

#### `scripts/sanity_smoke.py`
**Sanity smoke test for the pipeline.**

### 3.4 Data & Corpus

#### `data/crawled/`
Real benign HuggingFace checkpoints crawled by `crawl_benign.py`. Organized by cluster/repo with `pytorch_model.bin` files. `seed_manifest.json` records SHA-256 provenance. **Target corpus: 100 real models, 5 task clusters × 20** (text-generation, text-classification, feature-extraction, token-classification, question-answering); no synthetic models. The crawl is resumable and backfills pre-existing downloads into the manifest.

#### `data/malhug/`
MalHug real malicious corpus (ASE 2024). 73 malicious HuggingFace models with `manifest.json`.

#### `data/shelf_life.db`
SQLite database for bypass shelf-life tracking (versioned re-scan results).

#### `real_benign_corpus/`
Flat corpus directory for FP studies:
- `all/` — hard links to all crawled checkpoints (flat `<cluster>__<repo>.bin` naming)
- `oracle_positive/`, `oracle_negative/` — seed-selection views (hard links) split by DynaHug score
- `oracle-calibrated/<version>/` — calibrated oracle models + traces; default is `oracle-calibrated/current`
- `oracle-validation.json` — DynaHug scores on sample
- `oracle-split.json` — deterministic cluster-stratified train/eval split (disjointness guard)

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
- `IndirectChain` — `getattr(__import__(module, None, None, [name]), name)` chain (via `fromlist_import_args`), resolving dotted modules to the leaf and skipping smuggling primitives
- Helper functions: `encode_short_binunicode()`, `encode_binunicode()`, `fromlist_import_args()`, `binbytes_tuple()`, `ensure_proto()`, `canonical_module()`, `find_tuple_start()`

**Note (2026-08-29)**: the Rust opcode constants and IndirectChain were corrected to match Python (TUPLE=0x74 not 0x8e, BINBYTES=0x42 not 0x85, REDUCE=0x52 not 0xb0; dotted modules resolve via fromlist). The crate is the Phase-0 migration target and is not currently wired into the Python pipeline — Python is the source of truth.

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
- `campaign.panel_scanners`: picklescan, fickling, modelscan (modeltracer excluded — strace-based, cannot analyze torch artifacts)
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

Each container produces `regenbench/<name>:<version>` and (default build) `:latest`. Historical scanner releases are built by passing the release tag and upstream commit, e.g. for H3 shelf-life rescans:
```
containers/picklescan/build.sh 1.0.4 bf26452ae2e3204429762c2bb1aa9eacd40436bb
containers/modelscan/build.sh  0.8.7 abc4b1510315ba1ba162e3ae002e5d394db32200
containers/fickling/build.sh   0.1.11 62028fbb8e60742469a77ef07c9aabd33e3cb568
```

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

### 4.2 Bypass Confirmation (ExecutionOracle-Primary)

A candidate is a **confirmed bypass** when ALL of:
1. **Valid**: `ValidityOracle.validate_torch()` returns True (loads + trigger fires) — this is the primary ExecutionOracle
2. **Panel evasion**: ALL static panel scanners return "benign" (no "malicious", no "error")
3. **Oracle corroboration**: DynaHug is **supplementary** only — it provides a `decision_score` signal but does NOT gate confirmation. `check_bypass(panel_verdicts, "malicious" if is_valid else "benign")` is the rule.

The SQL query in `query_campaign_stats()` reads confirmed bypasses from `campaign_fitness.is_valid = 1` joined against `panel_results` (at least one benign row, no malicious/error row) — DynaHug's verdict is not part of the confirmation predicate.

The confirmed-bypass rule in `pipeline/comparator.py`:
```python
def check_bypass(panel_verdicts: list[str], execution_oracle_verdict: str) -> bool:
    # True iff ALL panel verdicts are "benign" AND the execution oracle
    # confirms payload execution ("malicious" = trigger fired).
    if not panel_verdicts:
        return False
    return all(v == "benign" for v in panel_verdicts) and execution_oracle_verdict == "malicious"
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
| T7.9 | Shelf-life decay (H3) | Decay curve (empirical rescans since 2026-08-29; 100% retention across 6 version snapshots) |
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

## 5. Evaluation Results — Live (see `docs/evaluation-report.md` for provenance)

> Live DB: `data/regenbench_campaign.db` (2 runs, 1025 generated / 990 valid / 514 bypasses, `data/regenbench_shadowpickle.db` 10/40 bypasses, `data/shelf_life.db` 514×6 100% retention). Archival snapshots (`reference/baseline_snapshot/`, 2026-08-18 693 valid 0 bypasses, 2026-08-23 evasion-mode 338 valid 23 bypasses) are preserved in `reference/baseline_snapshot/` and noted as archival below. This section is synchronized to the live DB; `docs/evaluation-report.md` is authoritative. Orphan 30 candidates (null run_id, no fitness) were removed and `campaign_runs.total_candidates` corrected to actual per-run counts (560/465).

### 5.1 Baseline Snapshot (20260818-141227) — ARCHIVAL

**Campaigns** (7 runs, 693 valid candidates, 0 bypasses — pre-fix, no evasion):

| Run | Type | Replicate | Candidates | Valid | Confirmed Bypasses |
|-----|------|-----------|------------|-------|-------------------|
| pilot-20260816T030153Z | guided | 1 | 100 | 93 | 0 |
| guided-r1 | guided | 1 | 100 | 100 | 0 |
| guided-r2 | guided | 2 | 100 | 100 | 0 |
| unguided-r1 | unguided | 1 | 100 | 100 | 0 |
| unguided-r2 | unguided | 2 | 100 | 100 | 0 |
| pilot-20260817T101219Z | guided | 1 | 100 | 100 | 0 |
| guided-r3 | guided | 3 | 100 | 100 | 0 |

**Panel verdicts (all runs, archival)**: fickling 94 malicious / 606 error, modelscan 539/161, picklescan 607/93. **Oracle** malicious 324 / error 376. Superseded by §5.9 live.

### 5.2 RQ1: Scanner Evasion Rates — LIVE

| Scanner | Valid Admitted | Evaded | Evasion Rate | 95% Bootstrap CI |
|---------|---------------:|-------:|-------------|------------------|
| PickleScan | 990 | 514 | 51.9% | [48.9%, 55.1%] |
| Fickling | 990 | 933 | 94.2% | [92.7%, 95.7%] |
| ModelScan | 990 | 623 | 62.9% | [59.9%, 65.9%] |

**H1 verdict**: **Supported** — fuzzing 51.9% (514/990) vs ShadowPickle baseline 25.0% (10/40) — relative improvement 108%, non-overlapping CIs. Per-scanner: PickleScan 51.9% vs 25%, ModelScan 62.9% vs 50%, Fickling 94.2% vs 100%. Archival 47.2% (446/945) in snapshot.

### 5.3 RQ2: Search Efficiency — LIVE

- Guided Q_first per replicate: [1] (guided-r1, 500 total), Unguided Q_first: [12] (unguided-r1, 462 total) — right-censored at total+1 if no bypass.
- Wilcoxon: pairs unequal or too few for paired test; use independent Mann-Whitney. Early Q_first reflects high sink susceptibility (`pypi_injected`+`splice`), not convergence.
- **Candidate Bypass Yield** (primary): guided 428/554 (77.3%) vs unguided 86/436 (19.7%), Fisher p=0.0, z=17.99 p=2.5e-72.

### 5.4 RQ3: Oracle Reliability & False-Positive Costs — LIVE

**Benign FP rates (17 real HF checkpoints, provenance-based ground truth, StraceOracle 0% FP, DynaHug supplementary)**:

| Scanner | Benign Models Scanned | FP Detections | FP Rate |
|---------|----------------------|--------------|---------|
| PickleScan | 17 | 0 | 0.0% |
| Fickling | 17 | 0 | 0.0% |
| ModelScan | 17 | 0 | 0.0% |
| ModelTracer | 17 | 0 | 0.0% |
| DynaHug (Calibrated Oracle, supplementary) | 17 | 11 | 64.7% |

**Archival 96-checkpoint** (pre-fix): PickleScan 0/96, Fickling 6/96 (6.2%), ModelScan 0, ModelTracer 0, DynaHug 61/96 (63.5%). Upstream OCSVM (8ff8174) collapses to `-rho` constant in this container; calibrated oracle restores discrimination at ~63.5% FP (startup baseline). ExecutionOracle (trigger poll / StraceOracle) gates confirmation, not DynaHug.

### 5.5 RQ4: Ablation Studies — LIVE

**Ablation 1: Coverage-Guided Feedback (T7.6)**:

| Campaign | Replicate | Valid | Panel Evasions | Confirmed | Evasion Yield |
|----------|-----------|-------|----------------|-----------|---------------|
| guided-r1 | 1 | 554 | 514* | 428 | 77.3% |
| unguided-r1 | 1 | 436 | 514* (overall) | 86 | 19.7% |

*Panel evasions counted per-scanner across valid; 514 is all-panel bypasses. Guided vs unguided confirmed: 428/554 vs 86/436 — Fisher p=0.0, z=17.99.*

**Coverage Growth (T7.3, reachable-space denominator)**:
- Opcode: 58 reachable, guided-r1 45.6%→45.6% (flat), unguided-r1 45.6%→48.5%, overall max 48.5%
- Callable: 17 armable, guided 28%→60%, unguided 24%→80%, overall max 80%
- Family entropy (uniform 5 =1.61 nats): guided ~1.2, unguided ~1.5 (see fuzzing reports)

**Ablation 2: Pre-filter Throughput (T7.7, docs/perf-report.md)**:

| Metric | With Pre-Filter | Without Pre-Filter | Speedup |
|--------|-----------------|-------------------|---------|
| Execution Duration (5 files) | 1.03s | 17.47s | **16.92×** |
| Full benchmark (10 files, baseline snapshot) | 10.19s | 19.45s | **1.91×** |

**Ablation 3: DynaHug Cross-Check (T7.8 / H2)**:

| Metric | Evasion Count | Rate |
|--------|--------------|------|
| Uncorroborated Evasions (Panel-Only) | 514 | 51.9% |
| Confirmed Evasions (ExecutionOracle) | 514 | 51.9% |

**H2 verdict**: **Valid negative** — uncorroborated == confirmed (514/514). Static panel already detects all non-executing candidates; dynamic validation confirms execution, not filters false evasions.

### 5.6 H3: Shelf-Life Decay (Empirical) — LIVE

514 confirmed bypasses bulk-registered via `register_bypasses_from_campaign_db` and rescanned against 6 historical scanner versions:

| Scanner Version | Retained | Total | Retention Rate |
|-----------------|----------|-------|----------------|
| picklescan 1.0.4 | 514 | 514 | 100.0% |
| picklescan 1.0.3 | 520 | 520 | 100.0% (520 due to 6 extra rescans) |
| modelscan 0.8.7 | 514 | 514 | 100.0% |
| modelscan 0.8.6 | 514 | 514 | 100.0% |
| fickling 0.1.11 | 514 | 514 | 100.0% |
| fickling 0.1.10 | 514 | 514 | 100.0% |
| plus :latest | 484 | 484 | 100.0% |

**Verdict on H3**: **Supported** — 100% retention. Caveat: retention reflects scanner stagnation (no rule for `IPython.utils.process.system` / splice transport in minor bumps), not patch evasion.

### 5.7 Evasion-Mode Campaigns (2026-08-23, dev branch) — ARCHIVAL

With Phase-1/2 evasion pipeline active (archival, superseded by §5.9 live):

| Run | Mode | Evasion | Candidates | Valid | Confirmed Bypasses |
|-----|------|---------|------------|-------|-------------------|
| guided-r21 | guided | adaptive | 36 | 23 | 1 |
| guided-r31 | guided | adaptive | 100 | 77 | 1 |
| guided-r32 | guided | adaptive | 100 | 72 | 0 |
| unguided-r22 | unguided | random | 36 | 21 | 4 |
| unguided-r33 | unguided | random | 100 | 77 | 7 |
| unguided-r34 | unguided | random | 100 | 68 | 10 |

**All-time (11 runs, 1244 candidates, archival)**: 23 bypasses, PickleScan 6.8%, ModelScan 19.5%, Fickling 100%. Guided 2/172 vs unguided 21/166, p≈2.6e-8 — pre-fix guided underperformed; fixed in live §5.9.

### 5.9 Post-Fix Scaled Results (2026-08-30) — LIVE (authoritative)

Scaled proof campaign on this host over all 5 families with adaptive evasion (`--evasion-mode adaptive`, `splice` transport, family quotas ≤40%/≥1, entropy target 1.5):

| Run | Mode | Generated (actual) | Valid | Confirmed Bypasses | Bypass Yield |
|-----|------|-------------------|-------|-------------------|--------------|
| guided-r1 | guided | 560 | 554 | 428 | 77.3% |
| unguided-r1 | unguided | 465 | 436 | 86 | 19.7% |

*Generated = actual per-run counts from `campaign_runs` (560/465, not planned 500/462 — extra due to structural retry and filesystem archival duplicates cleaned; see `_structurally_sane` retry). Total generated 1025 / valid 990 / bypass 514. `campaign_runs.total_candidates` is now authoritative after orphan cleanup (30 null-run_id rows removed).*

**RQ1 per-scanner evasion (990 valid, live)**: PickleScan 51.9% (514/990), ModelScan 62.9% (623/990), Fickling 94.2% (933/990).

**RQ2 search efficiency**: Q_first guided [1], unguided [12] (Fisher p=0.0, z=17.99 for yield).

**H1**: baseline 10/40 (25.0%) vs fuzzing 514/990 (51.9%) — **Supported** (relative improvement, non-overlapping CIs).

**H2 (inflation)**: uncorroborated == confirmed (514) — **valid negative**.

**H3 (shelf-life)**: 514 ×6 versions → **100% retention → Supported** (`data/shelf_life.db`).

### 5.8 Task 3: GGUF Attack Surface (format-complexity demo) — LIVE

- `ggufref` oracle (reference parser): detects 7/7 GGUF attacks (6 malformed-header families + Jinja2 SSTI CVE-2024-34359) with 0 FP on 13 synthetic benign GGUFs (`data/gguf_benign_corpus/`, `benign_gguf()` minimal) — dedicated oracle contribution. Real corpus `data/gguf_benign_corpus/` via `scripts/crawl_gguf.py` optional (~24 TinyLlama/vocab GGUFs, same 0 FP expected).
- Pickle-oriented panel is not applicable to GGUF: modelscan 0.8.8 misses all 7 (0/7, no GGUF rules); fickling flags benign GGUF as malicious when forced (catastrophic FP). GGUF results demonstrate format complexity, not scanner robustness. See `docs/demo-report.md#5`.

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
